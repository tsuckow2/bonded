use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{server::TlsStream as ServerTlsStream, TlsAcceptor};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{
    accept_async, connect_async, connect_async_tls_with_config, Connector, MaybeTlsStream,
    WebSocketStream,
};

/// A stream wrapper that replays `prefix` bytes before delegating all reads to
/// the inner stream.  Writes always go directly to the inner stream.
///
/// Used by the server bootstrap router: after reading and parsing the HTTP
/// request headers to decide whether a connection is a WebSocket upgrade or a
/// plain REST request, the router creates a `PrependedStream` that replays those
/// headers so that `tokio_tungstenite::accept_async` can complete the WebSocket
/// handshake as if it had read them itself.
pub struct PrependedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

// Safety: all fields are Unpin when S: Unpin (Vec<u8>, usize, and S).
impl<S: Unpin> Unpin for PrependedStream<S> {}

impl<S> PrependedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrependedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let remaining = &this.prefix[this.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.pos += to_copy;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrependedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

use crate::session::SessionFrame;

const MIN_SESSION_FRAME_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    NaiveTcp,
    WebSocketTls,
    Quic,
    WireGuard,
}

#[async_trait]
pub trait Transport: Send {
    async fn send(&mut self, frame: SessionFrame) -> anyhow::Result<()>;
    async fn recv(&mut self) -> anyhow::Result<SessionFrame>;
    fn kind(&self) -> TransportKind;
}

pub struct NaiveTcpTransport {
    stream: TcpStream,
    /// Accumulates bytes across `select!` cancellations so that `recv()` is cancel-safe.
    read_buf: BytesMut,
}

enum WebSocketStreamInner {
    Client(WebSocketStream<MaybeTlsStream<TcpStream>>),
    Server(WebSocketStream<TcpStream>),
    ServerTls(WebSocketStream<ServerTlsStream<TcpStream>>),
    /// Server-side, plain TCP, HTTP headers already consumed for routing and replayed.
    ServerRoutedPlain(WebSocketStream<PrependedStream<TcpStream>>),
    /// Server-side, TLS-terminated, HTTP headers already consumed for routing and replayed.
    ServerRoutedTls(WebSocketStream<PrependedStream<ServerTlsStream<TcpStream>>>),
}

pub struct WebSocketTlsTransport {
    stream: WebSocketStreamInner,
}

impl NaiveTcpTransport {
    pub async fn connect(address: &str) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(address).await?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            read_buf: BytesMut::new(),
        })
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        Self {
            stream,
            read_buf: BytesMut::new(),
        }
    }

    pub async fn close(&mut self) -> anyhow::Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }
}

impl WebSocketTlsTransport {
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let (stream, _response) = connect_async(url).await?;
        Ok(Self {
            stream: WebSocketStreamInner::Client(stream),
        })
    }

    pub async fn connect_with_connector(url: &str, connector: Connector) -> anyhow::Result<Self> {
        let (stream, _response) =
            connect_async_tls_with_config(url, None, false, Some(connector)).await?;
        Ok(Self {
            stream: WebSocketStreamInner::Client(stream),
        })
    }

    pub fn from_client_stream(stream: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        Self {
            stream: WebSocketStreamInner::Client(stream),
        }
    }

    pub async fn accept(stream: TcpStream) -> anyhow::Result<Self> {
        let stream = accept_async(stream).await?;
        Ok(Self {
            stream: WebSocketStreamInner::Server(stream),
        })
    }

    pub async fn accept_tls(stream: TcpStream, acceptor: TlsAcceptor) -> anyhow::Result<Self> {
        let tls_stream = acceptor.accept(stream).await?;
        let ws_stream = accept_async(tls_stream).await?;
        Ok(Self {
            stream: WebSocketStreamInner::ServerTls(ws_stream),
        })
    }

    /// Build a server-side transport from a plain TCP stream whose leading HTTP
    /// request bytes have already been consumed for routing and must be replayed.
    pub async fn from_routed_plain(stream: PrependedStream<TcpStream>) -> anyhow::Result<Self> {
        let ws_stream = accept_async(stream).await?;
        Ok(Self {
            stream: WebSocketStreamInner::ServerRoutedPlain(ws_stream),
        })
    }

    /// Build a server-side transport from a TLS-terminated stream whose leading
    /// HTTP request bytes have already been consumed for routing and must be replayed.
    pub async fn from_routed_tls(
        stream: PrependedStream<ServerTlsStream<TcpStream>>,
    ) -> anyhow::Result<Self> {
        let ws_stream = accept_async(stream).await?;
        Ok(Self {
            stream: WebSocketStreamInner::ServerRoutedTls(ws_stream),
        })
    }

    pub async fn send_text(&mut self, text: &str) -> anyhow::Result<()> {
        match &mut self.stream {
            WebSocketStreamInner::Client(stream) => {
                stream.send(Message::Text(text.to_owned())).await?;
            }
            WebSocketStreamInner::Server(stream) => {
                stream.send(Message::Text(text.to_owned())).await?;
            }
            WebSocketStreamInner::ServerTls(stream) => {
                stream.send(Message::Text(text.to_owned())).await?;
            }
            WebSocketStreamInner::ServerRoutedPlain(stream) => {
                stream.send(Message::Text(text.to_owned())).await?;
            }
            WebSocketStreamInner::ServerRoutedTls(stream) => {
                stream.send(Message::Text(text.to_owned())).await?;
            }
        }
        Ok(())
    }

    pub async fn recv_text(&mut self) -> anyhow::Result<String> {
        loop {
            let next = match &mut self.stream {
                WebSocketStreamInner::Client(stream) => stream.next().await,
                WebSocketStreamInner::Server(stream) => stream.next().await,
                WebSocketStreamInner::ServerTls(stream) => stream.next().await,
                WebSocketStreamInner::ServerRoutedPlain(stream) => stream.next().await,
                WebSocketStreamInner::ServerRoutedTls(stream) => stream.next().await,
            };

            match next {
                Some(Ok(Message::Text(text))) => return Ok(text),
                Some(Ok(Message::Binary(_))) => {
                    anyhow::bail!("unexpected websocket binary message while awaiting text")
                }
                Some(Ok(Message::Close(_))) => {
                    anyhow::bail!("websocket closed while awaiting text")
                }
                Some(Ok(_)) => continue,
                Some(Err(err)) => return Err(err.into()),
                None => anyhow::bail!("websocket closed while awaiting text"),
            }
        }
    }

    pub async fn close(&mut self) -> anyhow::Result<()> {
        match &mut self.stream {
            WebSocketStreamInner::Client(stream) => stream.close(None).await?,
            WebSocketStreamInner::Server(stream) => stream.close(None).await?,
            WebSocketStreamInner::ServerTls(stream) => stream.close(None).await?,
            WebSocketStreamInner::ServerRoutedPlain(stream) => stream.close(None).await?,
            WebSocketStreamInner::ServerRoutedTls(stream) => stream.close(None).await?,
        }
        Ok(())
    }
}

#[async_trait]
impl Transport for NaiveTcpTransport {
    async fn send(&mut self, frame: SessionFrame) -> anyhow::Result<()> {
        let encoded = frame.encode();
        let len = u32::try_from(encoded.len())?;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(&encoded).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> anyhow::Result<SessionFrame> {
        // Fill the internal buffer until we have the 4-byte length prefix.
        // Bytes already in `self.read_buf` survive a `tokio::select!` cancellation,
        // making this method cancel-safe.
        while self.read_buf.len() < 4 {
            let mut tmp = [0u8; 4096];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                anyhow::bail!("connection closed while reading frame length prefix");
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }

        let len = u32::from_be_bytes([
            self.read_buf[0],
            self.read_buf[1],
            self.read_buf[2],
            self.read_buf[3],
        ]) as usize;

        if len < MIN_SESSION_FRAME_LEN {
            anyhow::bail!(
                "invalid session frame length prefix: {len} bytes (minimum {MIN_SESSION_FRAME_LEN})"
            );
        }

        // Fill the buffer until we have the full frame (length prefix + payload).
        while self.read_buf.len() < 4 + len {
            let mut tmp = [0u8; 4096];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                anyhow::bail!("connection closed while reading frame payload");
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }

        // Consume exactly one frame from the front of the buffer.
        let _ = self.read_buf.split_to(4); // discard 4-byte length prefix
        let frame_bytes = self.read_buf.split_to(len);
        Ok(SessionFrame::decode(&frame_bytes)?)
    }

    fn kind(&self) -> TransportKind {
        TransportKind::NaiveTcp
    }
}

#[async_trait]
impl Transport for WebSocketTlsTransport {
    async fn send(&mut self, frame: SessionFrame) -> anyhow::Result<()> {
        let payload = frame.encode().to_vec();
        match &mut self.stream {
            WebSocketStreamInner::Client(stream) => {
                stream.send(Message::Binary(payload)).await?;
            }
            WebSocketStreamInner::Server(stream) => {
                stream.send(Message::Binary(payload)).await?;
            }
            WebSocketStreamInner::ServerTls(stream) => {
                stream.send(Message::Binary(payload)).await?;
            }
            WebSocketStreamInner::ServerRoutedPlain(stream) => {
                stream.send(Message::Binary(payload)).await?;
            }
            WebSocketStreamInner::ServerRoutedTls(stream) => {
                stream.send(Message::Binary(payload)).await?;
            }
        }
        Ok(())
    }

    async fn recv(&mut self) -> anyhow::Result<SessionFrame> {
        loop {
            let next = match &mut self.stream {
                WebSocketStreamInner::Client(stream) => stream.next().await,
                WebSocketStreamInner::Server(stream) => stream.next().await,
                WebSocketStreamInner::ServerTls(stream) => stream.next().await,
                WebSocketStreamInner::ServerRoutedPlain(stream) => stream.next().await,
                WebSocketStreamInner::ServerRoutedTls(stream) => stream.next().await,
            };

            match next {
                Some(Ok(Message::Binary(raw))) => return Ok(SessionFrame::decode(&raw)?),
                Some(Ok(Message::Close(_))) => anyhow::bail!("websocket closed"),
                Some(Ok(_)) => continue,
                Some(Err(err)) => return Err(err.into()),
                None => anyhow::bail!("websocket closed"),
            }
        }
    }

    fn kind(&self) -> TransportKind {
        TransportKind::WebSocketTls
    }
}

// ── QUIC transport ────────────────────────────────────────────────────────────

/// Transport backed by a single persistent QUIC bidirectional stream.
///
/// Both the client and server open exactly one bidirectional stream per session
/// (via [`QuicTransport::from_client_connection`] /
/// [`QuicTransport::from_server_connection`]).  Frames are length-prefixed with
/// a 4-byte big-endian `u32` — the same encoding used by `NaiveTcpTransport`.
///
/// The underlying `quinn::Connection` is kept alive as long as the transport
/// exists.  Dropping the transport closes the QUIC stream but does not
/// immediately close the connection (the caller should call `connection.close()`
/// separately if needed).
pub struct QuicTransport {
    /// The QUIC send half of the bidirectional stream.
    send: quinn::SendStream,
    /// The QUIC receive half of the bidirectional stream.
    recv: quinn::RecvStream,
    /// Buffered bytes that survive `select!`/`await` cancellations between
    /// individual `recv()` calls, making `recv()` cancel-safe.
    read_buf: BytesMut,
    /// Hold the connection alive while the transport is open.
    _connection: quinn::Connection,
}

impl QuicTransport {
    /// Open a new bidirectional QUIC stream on an outbound (client) connection.
    pub async fn from_client_connection(connection: quinn::Connection) -> anyhow::Result<Self> {
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| anyhow::anyhow!("failed to open QUIC bidirectional stream: {e}"))?;
        Ok(Self {
            send,
            recv,
            read_buf: BytesMut::new(),
            _connection: connection,
        })
    }

    /// Accept the first inbound bidirectional QUIC stream on a server connection.
    pub async fn from_server_connection(connection: quinn::Connection) -> anyhow::Result<Self> {
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|e| anyhow::anyhow!("failed to accept QUIC bidirectional stream: {e}"))?;
        Ok(Self {
            send,
            recv,
            read_buf: BytesMut::new(),
            _connection: connection,
        })
    }

    /// Whether the underlying QUIC connection has closed (locally, by
    /// the peer, or by error). Lets owners of a transport that is not
    /// actively being read notice a dead connection without a recv.
    pub fn connection_closed(&self) -> bool {
        self._connection.close_reason().is_some()
    }

    /// Send a UTF-8 text line terminated with `\n` over the QUIC stream.
    /// Used during the auth handshake before the session frame protocol starts.
    pub async fn send_text(&mut self, text: &str) -> anyhow::Result<()> {
        self.send.write_all(text.as_bytes()).await?;
        self.send.write_all(b"\n").await?;
        Ok(())
    }

    /// Receive a UTF-8 line (terminated with `\n`) from the QUIC stream.
    /// Used during the auth handshake before the session frame protocol starts.
    pub async fn recv_text(&mut self) -> anyhow::Result<String> {
        use tokio::io::AsyncBufReadExt;
        let mut buf_reader = tokio::io::BufReader::new(&mut self.recv);
        let mut line = String::new();
        let n = buf_reader.read_line(&mut line).await?;
        if n == 0 {
            anyhow::bail!("QUIC: connection closed while reading text line");
        }
        Ok(line)
    }

    /// Gracefully finish the send stream.  The connection itself is closed
    /// when the transport is dropped (the `quinn::Connection` held in
    /// `_connection` calls `close(0, b"")` on the last handle's drop).
    pub async fn close(&mut self) -> anyhow::Result<()> {
        self.send.finish()?;
        Ok(())
    }
}

#[async_trait]
impl Transport for QuicTransport {
    async fn send(&mut self, frame: SessionFrame) -> anyhow::Result<()> {
        let encoded = frame.encode();
        let len = u32::try_from(encoded.len())
            .map_err(|_| anyhow::anyhow!("QUIC: frame too large ({} bytes)", encoded.len()))?;
        self.send.write_all(&len.to_be_bytes()).await?;
        self.send.write_all(&encoded).await?;
        Ok(())
    }

    async fn recv(&mut self) -> anyhow::Result<SessionFrame> {
        // Accumulate until we have the 4-byte length prefix.
        while self.read_buf.len() < 4 {
            let mut tmp = [0u8; 4096];
            match self.recv.read(&mut tmp).await? {
                None | Some(0) => {
                    anyhow::bail!("QUIC: connection closed while reading frame length prefix")
                }
                Some(n) => self.read_buf.extend_from_slice(&tmp[..n]),
            }
        }

        let len = u32::from_be_bytes([
            self.read_buf[0],
            self.read_buf[1],
            self.read_buf[2],
            self.read_buf[3],
        ]) as usize;

        if len < MIN_SESSION_FRAME_LEN {
            anyhow::bail!(
                "QUIC: invalid frame length prefix: {len} bytes (minimum {MIN_SESSION_FRAME_LEN})"
            );
        }

        // Accumulate until we have the full frame.
        while self.read_buf.len() < 4 + len {
            let mut tmp = [0u8; 4096];
            match self.recv.read(&mut tmp).await? {
                None | Some(0) => {
                    anyhow::bail!("QUIC: connection closed while reading frame payload")
                }
                Some(n) => self.read_buf.extend_from_slice(&tmp[..n]),
            }
        }

        let _ = self.read_buf.split_to(4); // discard length prefix
        let frame_bytes = self.read_buf.split_to(len);
        Ok(SessionFrame::decode(&frame_bytes)?)
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Quic
    }
}

#[cfg(test)]
mod tests {
    use super::{NaiveTcpTransport, Transport, TransportKind, WebSocketTlsTransport};
    use crate::session::{SessionFrame, SessionHeader};
    use bytes::Bytes;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn naive_tcp_transport_exchanges_frames() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("local addr should resolve");

        let server_task = tokio::spawn(async move {
            let (server_stream, _) = listener.accept().await.expect("accept should succeed");
            let mut server_transport = NaiveTcpTransport::from_stream(server_stream);
            let frame = server_transport
                .recv()
                .await
                .expect("server should recv frame");
            assert_eq!(frame.header.connection_id, 88);
            assert_eq!(&frame.payload[..], b"ping");

            let response = SessionFrame {
                header: SessionHeader {
                    connection_id: 88,
                    sequence: 1,
                    flags: 0,
                },
                payload: Bytes::from_static(b"pong"),
            };
            server_transport
                .send(response)
                .await
                .expect("server should send response");
        });

        let mut client_transport = NaiveTcpTransport::connect(&address.to_string())
            .await
            .expect("client should connect");
        assert_eq!(client_transport.kind(), TransportKind::NaiveTcp);

        let request = SessionFrame {
            header: SessionHeader {
                connection_id: 88,
                sequence: 0,
                flags: 0,
            },
            payload: Bytes::from_static(b"ping"),
        };
        client_transport
            .send(request)
            .await
            .expect("client should send request");

        let response = client_transport
            .recv()
            .await
            .expect("client should receive response");
        assert_eq!(response.header.sequence, 1);
        assert_eq!(&response.payload[..], b"pong");

        server_task.await.expect("server task should join");
    }

    #[tokio::test]
    async fn websocket_transport_exchanges_frames() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("local addr should resolve");

        let server_task = tokio::spawn(async move {
            let (server_stream, _) = listener.accept().await.expect("accept should succeed");
            let mut server_transport = WebSocketTlsTransport::accept(server_stream)
                .await
                .expect("server websocket should accept");
            let frame = server_transport
                .recv()
                .await
                .expect("server should recv websocket frame");
            assert_eq!(frame.header.connection_id, 66);
            assert_eq!(&frame.payload[..], b"hello-ws");

            let response = SessionFrame {
                header: SessionHeader {
                    connection_id: 66,
                    sequence: 1,
                    flags: 0,
                },
                payload: Bytes::from_static(b"world-ws"),
            };
            server_transport
                .send(response)
                .await
                .expect("server should send websocket response");
        });

        let mut client_transport = WebSocketTlsTransport::connect(&format!("ws://{address}"))
            .await
            .expect("client websocket should connect");
        assert_eq!(client_transport.kind(), TransportKind::WebSocketTls);

        let request = SessionFrame {
            header: SessionHeader {
                connection_id: 66,
                sequence: 0,
                flags: 0,
            },
            payload: Bytes::from_static(b"hello-ws"),
        };
        client_transport
            .send(request)
            .await
            .expect("client should send websocket request");

        let response = client_transport
            .recv()
            .await
            .expect("client should recv websocket response");
        assert_eq!(response.header.sequence, 1);
        assert_eq!(&response.payload[..], b"world-ws");

        server_task.await.expect("server task should join");
    }
}

// ─── WireGuard transport ─────────────────────────────────────────────────────

/// Maximum WireGuard UDP datagram size.
const WG_MAX_DATAGRAM: usize = 1500;
/// Minimum output buffer size required by boringtun for handshake packets.
const WG_HS_BUF: usize = 148;
/// WireGuard encryption adds up to 60 bytes of overhead per packet.
const WG_ENCAP_OVERHEAD: usize = 60;
/// Fake IPv4 source used to satisfy boringtun's IP-version check.
const WG_FAKE_SRC_IP: [u8; 4] = [100, 64, 0, 1];
/// Fake IPv4 destination used to satisfy boringtun's IP-version check.
const WG_FAKE_DST_IP: [u8; 4] = [100, 64, 0, 2];
/// IPv4 header length in bytes (no options).
const IPV4_HDR_LEN: usize = 20;

/// Wrap raw bytes in a minimal IPv4 header so boringtun's decapsulate can
/// classify the payload.  boringtun checks the IP version nibble when routing
/// decapsulated bytes; without a valid IP header the frame is silently dropped.
fn wrap_in_ipv4(payload: &[u8]) -> Vec<u8> {
    let total_len = IPV4_HDR_LEN + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[1] = 0x00; // DSCP / ECN
    let tl = (total_len as u16).to_be_bytes();
    pkt[2] = tl[0];
    pkt[3] = tl[1];
    // id, flags, frag offset all zero
    pkt[8] = 64; // TTL
    pkt[9] = 253; // protocol: experimental (RFC 3692)
                  // checksum (bytes 10-11) — compute over header
    pkt[12..16].copy_from_slice(&WG_FAKE_SRC_IP);
    pkt[16..20].copy_from_slice(&WG_FAKE_DST_IP);
    // Compute header checksum.
    let mut csum: u32 = 0;
    for i in (0..IPV4_HDR_LEN).step_by(2) {
        let word = u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        csum += word;
    }
    while csum >> 16 != 0 {
        csum = (csum & 0xffff) + (csum >> 16);
    }
    let csum = !(csum as u16);
    pkt[10] = (csum >> 8) as u8;
    pkt[11] = (csum & 0xff) as u8;
    pkt[IPV4_HDR_LEN..].copy_from_slice(payload);
    pkt
}

/// Strip the IPv4 header added by `wrap_in_ipv4` and return the payload bytes.
fn unwrap_from_ipv4(ip_pkt: &[u8]) -> anyhow::Result<&[u8]> {
    if ip_pkt.len() < IPV4_HDR_LEN {
        anyhow::bail!(
            "WireGuard: received IP packet too short ({} bytes)",
            ip_pkt.len()
        );
    }
    let ihl = ((ip_pkt[0] & 0x0f) as usize) * 4;
    if ip_pkt.len() < ihl {
        anyhow::bail!(
            "WireGuard: malformed IP packet (IHL={ihl} > pkt_len={})",
            ip_pkt.len()
        );
    }
    Ok(&ip_pkt[ihl..])
}

/// WireGuard-encapsulated UDP transport.
///
/// Uses [`boringtun::noise::Tunn`] as a pure crypto engine — no second TUN
/// device is created.  Session frames are the payload that WireGuard encrypts;
/// they travel as WireGuard UDP packets between client and server.
///
/// ## Key exchange
///
/// X25519 key material is generated randomly (`WireGuardKeypair::generate`) or
/// restored from persisted 32-byte seeds.  The peer's public key must be
/// provided before the transport can send or receive authenticated data.
///
/// ## Handshake
///
/// The WireGuard handshake is initiated lazily on the first `send()` or driven
/// transparently during `recv()`.  Frames arriving during a handshake window
/// are buffered in `pending_recv` and returned from the next `recv()` call.
pub struct WireGuardTransport {
    tunn: boringtun::noise::Tunn,
    socket: tokio::net::UdpSocket,
    peer_addr: std::net::SocketAddr,
    /// Decoded frames that arrived while a handshake was completing.
    pending_recv: std::collections::VecDeque<SessionFrame>,
    /// Scratch buffer for incoming UDP datagrams.
    udp_buf: Vec<u8>,
    /// Scratch buffer for boringtun encapsulate / decapsulate output.
    wg_buf: Vec<u8>,
}

/// A Curve25519 keypair used with the WireGuard transport.
pub struct WireGuardKeypair {
    pub secret: boringtun::x25519::StaticSecret,
    pub public: boringtun::x25519::PublicKey,
}

impl WireGuardKeypair {
    /// Generate a fresh random keypair.
    pub fn generate() -> Self {
        let secret = boringtun::x25519::StaticSecret::random_from_rng(rand::thread_rng());
        let public = boringtun::x25519::PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Restore a keypair from a 32-byte seed (the raw secret scalar bytes).
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = boringtun::x25519::StaticSecret::from(bytes);
        let public = boringtun::x25519::PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Base64-encode the public key for use in API requests / peer registration.
    pub fn public_key_b64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.public.as_bytes())
    }
}

impl WireGuardTransport {
    /// Bind a UDP socket to `bind_addr` and create a WireGuard transport to
    /// `peer_addr` using `local_keypair` and the peer's `peer_public_key`.
    ///
    /// The WireGuard handshake is not performed here — it is driven lazily on
    /// the first `send()`.
    pub async fn new(
        local_keypair: WireGuardKeypair,
        peer_public_key: boringtun::x25519::PublicKey,
        bind_addr: &str,
        peer_addr: std::net::SocketAddr,
        session_index: u32,
        #[cfg(unix)] socket_protect: Option<&crate::config::SocketProtectFn>,
    ) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        let socket = tokio::net::UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("WireGuard: failed to bind UDP socket on {bind_addr}"))?;
        #[cfg(unix)]
        if let Some(protect) = socket_protect {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            if !protect.0(fd) {
                anyhow::bail!("WireGuard: failed to protect UDP socket from VPN capture (fd={fd})");
            }
        }
        socket.connect(peer_addr).await?;

        let tunn = boringtun::noise::Tunn::new(
            local_keypair.secret,
            peer_public_key,
            None,     // no preshared key
            Some(25), // 25-second persistent keepalive interval
            session_index,
            None, // no rate limiter
        );

        Ok(Self {
            tunn,
            socket,
            peer_addr,
            pending_recv: std::collections::VecDeque::new(),
            udp_buf: vec![0u8; WG_MAX_DATAGRAM],
            wg_buf: vec![0u8; WG_MAX_DATAGRAM + WG_ENCAP_OVERHEAD],
        })
    }

    /// Initiate the WireGuard handshake and drive it to completion.
    ///
    /// Sends the initiation packet and processes inbound datagrams until the
    /// session key is established (`time_since_last_handshake()` becomes
    /// `Some`).  Data packets received during the handshake are buffered.
    pub async fn establish_session(&mut self) -> anyhow::Result<()> {
        use boringtun::noise::TunnResult;

        if self.tunn.time_since_last_handshake().is_some() {
            return Ok(());
        }

        // Send handshake initiation.
        let init_pkt: Option<Vec<u8>> = {
            let result = self
                .tunn
                .format_handshake_initiation(&mut self.wg_buf, false);
            match result {
                TunnResult::WriteToNetwork(pkt) => Some(pkt.to_vec()),
                TunnResult::Done => None,
                other => anyhow::bail!(
                    "WireGuard: format_handshake_initiation returned unexpected result: {other:?}"
                ),
            }
        };
        if let Some(init_pkt) = init_pkt {
            self.socket.send(&init_pkt).await?;
        }

        // Wait up to 5 s for handshake to complete.
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        loop {
            if self.tunn.time_since_last_handshake().is_some() {
                return Ok(());
            }
            let n = tokio::time::timeout_at(deadline, self.socket.recv(&mut self.udp_buf))
                .await
                .map_err(|_| anyhow::anyhow!("WireGuard: handshake timed out after 5 s"))?
                .map_err(|e| {
                    anyhow::anyhow!("WireGuard: socket read error during handshake: {e}")
                })?;
            let datagram = self.udp_buf[..n].to_vec();
            self.process_datagram(&datagram).await?;
        }
    }

    /// Process one UDP datagram through boringtun's `decapsulate`.
    ///
    /// Handshake packets produce response datagrams that are sent immediately.
    /// Data packets are unwrapped from their fake IPv4 header, decoded into
    /// [`SessionFrame`]s, and pushed onto `pending_recv`.
    async fn process_datagram(&mut self, datagram: &[u8]) -> anyhow::Result<()> {
        use boringtun::noise::TunnResult;

        let peer_ip = self.peer_addr.ip();
        let mut outbound: Vec<Vec<u8>> = Vec::new();
        let mut decoded_frames: Vec<SessionFrame> = Vec::new();

        // First call with real datagram.
        {
            let result = self
                .tunn
                .decapsulate(Some(peer_ip), datagram, &mut self.wg_buf);
            match result {
                TunnResult::Done => {}
                TunnResult::WriteToNetwork(pkt) => outbound.push(pkt.to_vec()),
                TunnResult::WriteToTunnelV4(ip_pkt, ..)
                | TunnResult::WriteToTunnelV6(ip_pkt, ..) => {
                    match unwrap_from_ipv4(ip_pkt)
                        .and_then(|b| SessionFrame::decode(b).map_err(Into::into))
                    {
                        Ok(frame) => decoded_frames.push(frame),
                        Err(e) => tracing::warn!("WireGuard: failed to decode frame: {e}"),
                    }
                }
                TunnResult::Err(e) => tracing::warn!("WireGuard: decapsulate error: {e:?}"),
            }
        }

        // Drain any follow-up results (handshake may produce multiple outbound packets).
        loop {
            let result = self.tunn.decapsulate(None, &[], &mut self.wg_buf);
            let done = matches!(result, TunnResult::Done);
            match result {
                TunnResult::Done => {}
                TunnResult::WriteToNetwork(pkt) => outbound.push(pkt.to_vec()),
                TunnResult::WriteToTunnelV4(ip_pkt, ..)
                | TunnResult::WriteToTunnelV6(ip_pkt, ..) => {
                    match unwrap_from_ipv4(ip_pkt)
                        .and_then(|b| SessionFrame::decode(b).map_err(Into::into))
                    {
                        Ok(frame) => decoded_frames.push(frame),
                        Err(e) => tracing::warn!("WireGuard: failed to decode frame (drain): {e}"),
                    }
                }
                TunnResult::Err(e) => tracing::warn!("WireGuard: decapsulate error (drain): {e:?}"),
            }
            if done {
                break;
            }
        }

        for pkt in outbound {
            self.socket.send(&pkt).await?;
        }
        for frame in decoded_frames {
            self.pending_recv.push_back(frame);
        }
        Ok(())
    }
}

#[async_trait]
impl Transport for WireGuardTransport {
    async fn send(&mut self, frame: SessionFrame) -> anyhow::Result<()> {
        use boringtun::noise::TunnResult;

        // Service keepalive timers before sending data.
        {
            let result = self.tunn.update_timers(&mut self.wg_buf);
            if let TunnResult::WriteToNetwork(pkt) = result {
                let pkt = pkt.to_vec();
                self.socket.send(&pkt).await?;
            }
        }

        let encoded = frame.encode();
        let ip_pkt = wrap_in_ipv4(&encoded);

        let dst_len = (ip_pkt.len() + WG_ENCAP_OVERHEAD).max(WG_HS_BUF);
        if self.wg_buf.len() < dst_len {
            self.wg_buf.resize(dst_len, 0);
        }

        let result = self.tunn.encapsulate(&ip_pkt, &mut self.wg_buf);
        match result {
            TunnResult::WriteToNetwork(pkt) => {
                let pkt = pkt.to_vec();
                self.socket.send(&pkt).await?;
            }
            TunnResult::Err(_) | TunnResult::Done => {
                // boringtun may report either `Err(_)` or `Done` before the first
                // data-capable session key is established. Drive the handshake, then
                // retry the encapsulation once.
                self.establish_session().await?;
                let result = self.tunn.encapsulate(&ip_pkt, &mut self.wg_buf);
                match result {
                    TunnResult::WriteToNetwork(pkt) => {
                        let pkt = pkt.to_vec();
                        self.socket.send(&pkt).await?;
                    }
                    other => {
                        anyhow::bail!("WireGuard: encapsulate failed after handshake: {other:?}");
                    }
                }
            }
            other => {
                anyhow::bail!("WireGuard: unexpected encapsulate result: {other:?}");
            }
        }
        Ok(())
    }

    async fn recv(&mut self) -> anyhow::Result<SessionFrame> {
        // Return any frame buffered during a previous handshake exchange.
        if let Some(frame) = self.pending_recv.pop_front() {
            return Ok(frame);
        }

        loop {
            // Service keepalive timers.
            {
                let result = self.tunn.update_timers(&mut self.wg_buf);
                if let boringtun::noise::TunnResult::WriteToNetwork(pkt) = result {
                    let pkt = pkt.to_vec();
                    self.socket.send(&pkt).await?;
                }
            }

            let n = self.socket.recv(&mut self.udp_buf).await?;
            let datagram = self.udp_buf[..n].to_vec();
            self.process_datagram(&datagram).await?;

            if let Some(frame) = self.pending_recv.pop_front() {
                return Ok(frame);
            }
        }
    }

    fn kind(&self) -> TransportKind {
        TransportKind::WireGuard
    }
}

impl WireGuardTransport {
    /// Gracefully shut down: the QUIC-style close is not needed for UDP, but
    /// callers may want a no-op method to match `NaiveTcpTransport::close`.
    pub async fn close(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
