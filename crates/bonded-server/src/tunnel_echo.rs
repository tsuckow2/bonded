//! TCP echo endpoint for the tunnel gateway (10.8.0.1:18099).
//!
//! The transport-overhead diagnostic needs a TCP connection with a fixed
//! payload through the tunnel whose far end is known to echo it back
//! verbatim. The tunnel gateway is the only destination that is
//! guaranteed reachable from every client without depending on the
//! internet, so the server terminates echo connections locally instead
//! of forwarding them.
//!
//! How it works: each [`SmoltcpForwarder`] binds one loopback listener
//! (127.0.0.1, ephemeral port) at construction and spawns an accept
//! loop on the Tokio runtime. When `dispatch_tcp` sees a SYN for the
//! echo port it dials that loopback listener through the normal
//! dial-first path, so the whole smoltcp bridge machinery (SYN-ACK
//! only after the dial succeeds, half-close, RST on dial failure) is
//! reused unchanged — the echo is just another upstream `TcpStream` as
//! far as the bridge is concerned.
//!
//! Reachability: the listener binds loopback only, so the echo is
//! reachable ONLY via the tunnel (destination 10.8.0.1:18099). Nothing
//! new listens on a public interface, and forwarding for every other
//! destination is unchanged. This mirrors the UDP DNS special-case
//! (`dns_proxy`), which also intercepts gateway-addressed traffic
//! before the internet relay — but unlike DNS, echo only works in the
//! smoltcp forwarding mode; the kernel-TUN mode bypasses
//! `SmoltcpForwarder` entirely, exactly like the DNS proxy.
//!
//! Limits (fail-closed, so a misbehaving client cannot exhaust the
//! server): at most [`MAX_ECHO_CONNECTIONS`] concurrent echo
//! connections per listener, at most
//! [`MAX_ECHO_BYTES_PER_CONNECTION`] echoed bytes per connection, and
//! an idle timeout of [`ECHO_IDLE_TIMEOUT`] per connection. Echo
//! sessions log at debug level only, never per packet.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// The tunnel gateway address (same address the DNS proxy answers on).
pub const TUN_ECHO_ADDR: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);

/// TCP echo port on the tunnel gateway.
///
/// Chosen to collide with nothing the server already special-cases or
/// serves: 53 is the DNS proxy, 853 is the (dial-first) DoT port,
/// 8080-8082 are the server's health/status listeners, 48117 is the
/// TV QR-pairing listener (client side), and 443 is the public
/// endpoint. 18099 is unprivileged and otherwise unused in the
/// codebase.
pub const TUN_ECHO_PORT: u16 = 18099;

/// Max concurrent echo connections per listener (shared across all
/// sessions using that listener).
pub const MAX_ECHO_CONNECTIONS: usize = 16;

/// Max bytes echoed per connection. The diagnostic's largest payload
/// is 10 MiB on one connection; 64 MiB leaves room for a few runs per
/// connection while still bounding a runaway client.
pub const MAX_ECHO_BYTES_PER_CONNECTION: u64 = 64 * 1024 * 1024;

/// Idle timeout per connection: no bytes in either direction for this
/// long closes the connection.
pub const ECHO_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Tunable limits for the echo listener (tests use small values).
#[derive(Debug, Clone, Copy)]
pub struct EchoConfig {
    pub max_connections: usize,
    pub max_bytes_per_connection: u64,
    pub idle_timeout: Duration,
}

impl Default for EchoConfig {
    fn default() -> Self {
        Self {
            max_connections: MAX_ECHO_CONNECTIONS,
            max_bytes_per_connection: MAX_ECHO_BYTES_PER_CONNECTION,
            idle_timeout: ECHO_IDLE_TIMEOUT,
        }
    }
}

/// A loopback TCP echo listener. Bound at construction; the accept
/// loop is aborted on drop.
pub struct TunnelEchoListener {
    addr: SocketAddrV4,
    accept_task: JoinHandle<()>,
}

impl TunnelEchoListener {
    /// Bind 127.0.0.1:0 and spawn the accept loop on `handle`.
    pub fn start(
        handle: &tokio::runtime::Handle,
        config: EchoConfig,
    ) -> std::io::Result<Self> {
        let std_listener =
            std::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        std_listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(std_listener)?;
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr()?.port());
        let semaphore = Arc::new(Semaphore::new(config.max_connections));
        let accept_task = handle.spawn(async move {
            accept_loop(listener, semaphore, config).await;
        });
        debug!(%addr, "tunnel echo listener started");
        Ok(Self { addr, accept_task })
    }

    /// The loopback address dial-first connects to for echo SYNs.
    pub fn addr(&self) -> SocketAddrV4 {
        self.addr
    }
}

impl Drop for TunnelEchoListener {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

async fn accept_loop(
    listener: TcpListener,
    semaphore: Arc<Semaphore>,
    config: EchoConfig,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    // At the cap: drop the connection (the client sees a
                    // RST, exactly like a refused dial) instead of
                    // queueing it.
                    debug!(
                        max_connections = config.max_connections,
                        "tunnel echo: at max connections, dropping new connection"
                    );
                    drop(stream);
                    continue;
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    echo_connection(stream, &config).await;
                });
            }
            Err(err) => {
                // The listener is gone (server shutting down); exit.
                warn!(error = %err, "tunnel echo: accept loop ended");
                break;
            }
        }
    }
}

/// Echo one connection verbatim until the client closes, the byte cap
/// is hit, or the connection idles out.
async fn echo_connection(mut stream: TcpStream, config: &EchoConfig) {
    let _ = stream.set_nodelay(true);
    let mut buf = vec![0u8; 65535];
    let mut total: u64 = 0;
    loop {
        match tokio::time::timeout(config.idle_timeout, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                // Echo up to the cap, then close: the crossing chunk is
                // echoed partially rather than dropped, so a client that
                // overruns the cap still gets a clean prefix back.
                let remaining = config
                    .max_bytes_per_connection
                    .saturating_sub(total);
                let echo_n = (n as u64).min(remaining) as usize;
                if echo_n > 0 {
                    if stream.write_all(&buf[..echo_n]).await.is_err() {
                        break;
                    }
                    total = total.saturating_add(echo_n as u64);
                }
                if total >= config.max_bytes_per_connection {
                    debug!(
                        total,
                        max_bytes = config.max_bytes_per_connection,
                        "tunnel echo: connection reached byte cap, closing"
                    );
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => {
                debug!(
                    total,
                    "tunnel echo: idle timeout, closing connection"
                );
                break;
            }
        }
    }
    debug!(total, "tunnel echo: connection closed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_config() -> EchoConfig {
        EchoConfig {
            max_connections: 4,
            max_bytes_per_connection: 1024 * 1024,
            idle_timeout: Duration::from_secs(10),
        }
    }

    /// Deterministic patterned payload: byte i is (i % 251) so any
    /// truncation, reorder, or corruption is visible in a comparison.
    fn patterned_payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[tokio::test]
    async fn echo_returns_payload_verbatim_across_segments() {
        let handle = tokio::runtime::Handle::current();
        let listener = TunnelEchoListener::start(&handle, test_config())
            .expect("echo listener should bind on loopback");
        let addr = listener.addr();

        let mut stream = TcpStream::connect(addr)
            .await
            .expect("echo connect should succeed");
        // 100 KiB is far larger than one TCP segment, so the echo has
        // to survive chunked reads/writes on both sides.
        let payload = patterned_payload(100 * 1024);
        stream
            .write_all(&payload)
            .await
            .expect("echo write should succeed");
        let mut received = vec![0u8; payload.len()];
        stream
            .read_exact(&mut received)
            .await
            .expect("echo read should return the full payload");
        assert_eq!(received, payload, "echoed payload must match sent bytes");
    }

    #[tokio::test]
    async fn echo_survives_empty_close_and_still_serves() {
        let handle = tokio::runtime::Handle::current();
        let listener = TunnelEchoListener::start(&handle, test_config())
            .expect("echo listener should bind on loopback");
        let addr = listener.addr();

        // Connect and close immediately without sending anything.
        drop(
            TcpStream::connect(addr)
                .await
                .expect("empty-close connect should succeed"),
        );

        // A second connection must still echo: the empty close did not
        // take the listener down.
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("second echo connect should succeed");
        let payload = patterned_payload(1024);
        stream
            .write_all(&payload)
            .await
            .expect("echo write should succeed");
        let mut received = vec![0u8; payload.len()];
        stream
            .read_exact(&mut received)
            .await
            .expect("echo read should return the full payload");
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn echo_byte_cap_closes_connection() {
        let handle = tokio::runtime::Handle::current();
        let config = EchoConfig {
            max_connections: 4,
            max_bytes_per_connection: 1024,
            idle_timeout: Duration::from_secs(10),
        };
        let listener = TunnelEchoListener::start(&handle, config)
            .expect("echo listener should bind on loopback");
        let addr = listener.addr();

        let mut stream = TcpStream::connect(addr)
            .await
            .expect("echo connect should succeed");
        // Send twice the cap; the listener echoes the first 1024 bytes
        // and then closes, so the read side must hit EOF.
        let payload = patterned_payload(2048);
        stream
            .write_all(&payload)
            .await
            .expect("echo write should succeed");
        let mut received = vec![0u8; 1024];
        stream
            .read_exact(&mut received)
            .await
            .expect("first 1024 bytes should be echoed");
        assert_eq!(received, payload[..1024]);
        let mut one = [0u8; 1];
        let n = stream
            .read(&mut one)
            .await
            .expect("read after cap should not error");
        assert_eq!(n, 0, "connection must be closed after the byte cap");
    }

    #[tokio::test]
    async fn echo_max_connections_drops_excess() {
        let handle = tokio::runtime::Handle::current();
        let config = EchoConfig {
            max_connections: 1,
            max_bytes_per_connection: 1024 * 1024,
            idle_timeout: Duration::from_secs(10),
        };
        let listener = TunnelEchoListener::start(&handle, config)
            .expect("echo listener should bind on loopback");
        let addr = listener.addr();

        // Hold the single slot open without sending anything.
        let _held = TcpStream::connect(addr)
            .await
            .expect("first echo connect should succeed");
        // Give the accept loop a chance to take the first connection.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // A second connection is dropped at accept time: the read side
        // hits EOF promptly instead of hanging.
        let mut excess = TcpStream::connect(addr)
            .await
            .expect("second echo connect should succeed at TCP level");
        let mut one = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), excess.read(&mut one))
            .await
            .expect("excess read should not time out")
            .expect("excess read should not error");
        assert_eq!(n, 0, "excess connection must be closed, not queued");
    }
}
