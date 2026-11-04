//! DNS proxy for the tunnel: queries addressed to the tunnel gateway
//! (10.8.0.1:53) are resolved by the server itself, using the server
//! host's own resolvers from /etc/resolv.conf, instead of being
//! forwarded to the internet like any other UDP packet.
//!
//! The Android client sets the VPN DNS server to the tunnel gateway, so
//! when the tunnel is up, all device DNS goes through the tunnel to this
//! proxy. Nothing reaches here by accident: 10.8.0.1 is not a real
//! client address, and the server answers nothing else on it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bonded_core::session::{SessionFrame, SessionHeader};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::smoltcp_forwarder::{build_ipv4_udp_packet, Ipv4UdpPacket};

/// The tunnel gateway address the client uses as its VPN DNS server.
pub const TUN_DNS_ADDR: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);
/// DNS port.
pub const TUN_DNS_PORT: u16 = 53;
/// DNS-over-TLS port. No DoT listener exists on the gateway: TCP SYNs
/// to it are answered with an immediate RST by the smoltcp forwarder
/// (see its explicit gateway-DoT rejection) instead of being dialed,
/// which would hang on the blackholed gateway route until DIAL_TIMEOUT.
pub const TUN_DOT_PORT: u16 = 853;

/// How long to wait for one upstream resolver before trying the next.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

/// Per-client-tuple reply state, mirroring the UDP flow pump: responses
/// carry the flow's next sequence so they stay ordered in the session's
/// delivery stream.
#[derive(Clone, Copy)]
struct DnsFlowState {
    connection_id: u32,
    next_sequence: u64,
}

/// Server-side DNS proxy for one session.
#[derive(Clone)]
pub struct DnsProxy {
    session_id: u64,
    outbound_tx: mpsc::UnboundedSender<SessionFrame>,
    flows: Arc<Mutex<HashMap<(Ipv4Addr, u16), DnsFlowState>>>,
}

impl DnsProxy {
    pub fn new(session_id: u64, outbound_tx: mpsc::UnboundedSender<SessionFrame>) -> Self {
        Self {
            session_id,
            outbound_tx,
            flows: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Answer one DNS query addressed to the tunnel gateway, using the
    /// server host's own resolvers.
    pub async fn handle_query(&self, header: SessionHeader, pkt: Ipv4UdpPacket) {
        let resolvers = system_resolvers();
        self.answer(header, pkt, &resolvers).await;
    }

    /// Answer one DNS query using an explicit resolver list (the
    /// production path passes the system resolvers; tests pass a stub).
    async fn answer(&self, header: SessionHeader, pkt: Ipv4UdpPacket, resolvers: &[SocketAddr]) {
        let query = pkt.payload;
        if query.len() < 12 {
            debug!(session_id = self.session_id, "dropping short DNS query to tunnel gateway");
            return;
        }
        let response = match forward_query(&query, resolvers).await {
            Some(response) => response,
            None => {
                warn!(
                    session_id = self.session_id,
                    resolvers = resolvers.len(),
                    "no upstream DNS resolver answered; returning SERVFAIL"
                );
                build_servfail(&query)
            }
        };
        let (response_header, identification) = {
            let mut flows = self.flows.lock().await;
            let state = flows.entry((pkt.src_ip, pkt.src_port)).or_insert(DnsFlowState {
                connection_id: header.connection_id,
                next_sequence: header.sequence,
            });
            state.connection_id = header.connection_id;
            let seq = state.next_sequence;
            state.next_sequence = state.next_sequence.wrapping_add(1);
            (
                SessionHeader {
                    connection_id: state.connection_id,
                    sequence: seq,
                    flags: 0,
                },
                pkt.identification,
            )
        };
        let Ok(response_pkt) = build_ipv4_udp_packet(
            TUN_DNS_ADDR,
            pkt.src_ip,
            TUN_DNS_PORT,
            pkt.src_port,
            identification,
            &response,
        ) else {
            return;
        };
        if self
            .outbound_tx
            .send(SessionFrame {
                header: response_header,
                payload: response_pkt.into(),
            })
            .is_err()
        {
            debug!(session_id = self.session_id, "DNS response dropped: session gone");
        }
    }
}

/// Forward a raw DNS query to the given resolvers in order, returning
/// the first response. Each resolver gets a fresh ephemeral socket, so
/// concurrent queries never mix up replies.
async fn forward_query(query: &[u8], resolvers: &[SocketAddr]) -> Option<Vec<u8>> {
    for resolver in resolvers {
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(_) => continue,
        };
        if socket.send_to(query, resolver).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; 65535];
        match timeout(UPSTREAM_TIMEOUT, socket.recv(&mut buf)).await {
            Ok(Ok(n)) => return Some(buf[..n].to_vec()),
            _ => continue,
        }
    }
    None
}

/// The server host's resolvers from /etc/resolv.conf, in order.
fn system_resolvers() -> Vec<SocketAddr> {
    let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    parse_resolv_conf(&contents)
}

/// Parse `nameserver` lines out of resolv.conf content. IPv6
/// nameservers are skipped: the proxy queries over IPv4.
fn parse_resolv_conf(contents: &str) -> Vec<SocketAddr> {
    let mut resolvers = Vec::new();
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        let Some(addr) = parts.next() else { continue };
        let Ok(IpAddr::V4(ip)) = addr.parse::<IpAddr>() else {
            continue;
        };
        resolvers.push(SocketAddr::new(IpAddr::V4(ip), 53));
    }
    resolvers
}

/// A SERVFAIL response echoing the query's ID and question count, so
/// the client fails fast instead of waiting out its own timeout.
fn build_servfail(query: &[u8]) -> Vec<u8> {
    let mut response = vec![0u8; 12];
    response[0] = query[0];
    response[1] = query[1];
    // QR=1, RD=1, RA=1, RCODE=2 (SERVFAIL).
    response[2] = 0x81;
    response[3] = 0x82;
    response[4] = query[4];
    response[5] = query[5];
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_query() -> Vec<u8> {
        // Minimal DNS query: ID 0x1234, RD set, one question.
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    #[test]
    fn resolv_conf_parsing_skips_comments_and_ipv6() {
        let contents = "# a comment\nnameserver 192.168.1.1\nnameserver 2001:db8::1 # trailing\nsearch example.com\noptions ndots:5\nnameserver 8.8.8.8\n";
        let resolvers = parse_resolv_conf(contents);
        assert_eq!(resolvers.len(), 2);
        assert_eq!(resolvers[0].ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(resolvers[0].port(), 53);
        assert_eq!(resolvers[1].ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn servfail_echoes_id_and_qdcount_with_rcode_2() {
        let response = build_servfail(&example_query());
        assert_eq!(response.len(), 12);
        assert_eq!(&response[0..2], &[0x12, 0x34]);
        assert_eq!(response[2], 0x81);
        assert_eq!(response[3], 0x82);
        assert_eq!(&response[4..6], &[0x00, 0x01]);
        assert_eq!(&response[6..12], &[0, 0, 0, 0, 0, 0]);
    }

    /// Whether this environment can send UDP on loopback. This sandbox
    /// blocks UDP sending (EPERM), so a stub-resolver test that needs a
    /// real send must skip here; it runs on hosts where UDP works.
    async fn udp_loopback_available() -> bool {
        let Ok(tx) = UdpSocket::bind("127.0.0.1:0").await else {
            return false;
        };
        let Ok(rx) = UdpSocket::bind("127.0.0.1:0").await else {
            return false;
        };
        let rx_addr = match rx.local_addr() {
            Ok(addr) => addr,
            Err(_) => return false,
        };
        if tx.send_to(b"probe", rx_addr).await.is_err() {
            return false;
        }
        let mut buf = [0u8; 8];
        matches!(
            timeout(Duration::from_millis(500), rx.recv(&mut buf)).await,
            Ok(Ok(5))
        )
    }

    #[tokio::test]
    async fn forward_query_returns_stub_response() {
        if !udp_loopback_available().await {
            eprintln!("skipping stub-resolver test: UDP sending unavailable here");
            return;
        }
        // A stub resolver that answers one canned response.
        let stub = UdpSocket::bind("127.0.0.1:0").await.expect("stub bind");
        let stub_addr = stub.local_addr().expect("stub addr");
        let canned: Vec<u8> = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01];
        let canned_clone = canned.clone();
        let serve = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let (n, peer) = stub.recv_from(&mut buf).await.expect("stub recv");
            assert_eq!(&buf[..n], &example_query()[..]);
            stub.send_to(&canned_clone, peer).await.expect("stub send");
        });
        let response = forward_query(&example_query(), &[stub_addr])
            .await
            .expect("stub should answer");
        assert_eq!(response, canned);
        serve.await.expect("stub task");
    }

    #[tokio::test]
    async fn answer_returns_servfail_when_no_resolver_answers() {
        // A closed port: sends succeed, nothing ever replies.
        let (tx, mut rx) = mpsc::unbounded_channel::<SessionFrame>();
        let proxy = DnsProxy::new(7, tx);
        let pkt = Ipv4UdpPacket {
            src_ip: Ipv4Addr::new(10, 8, 0, 2),
            dst_ip: TUN_DNS_ADDR,
            src_port: 54321,
            dst_port: TUN_DNS_PORT,
            payload: example_query(),
            identification: 0x4321,
        };
        let header = SessionHeader {
            connection_id: 9,
            sequence: 100,
            flags: 0,
        };
        proxy
            .answer(header, pkt, &[SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1)])
            .await;
        let frame = rx.recv().await.expect("a response frame");
        assert_eq!(frame.header.connection_id, 9);
        assert_eq!(frame.header.sequence, 100);
        // The response packet is addressed back to the client tuple.
        let payload = frame.payload.as_ref();
        assert_eq!(&payload[12..16], &[10, 8, 0, 1]);
        assert_eq!(&payload[16..20], &[10, 8, 0, 2]);
        assert_eq!(&payload[20..22], &[0x00, 0x35]);
        assert_eq!(&payload[22..24], &[0xd4, 0x31]);
        // SERVFAIL body: ID echo + RCODE 2.
        assert_eq!(&payload[28..30], &[0x12, 0x34]);
        assert_eq!(payload[31], 0x82);
    }
}
