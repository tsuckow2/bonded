use bonded_core::auth::verify_signature;
use bonded_core::config::SocketProtectFn;
use bonded_core::peer_share::{PeerRelayRegistration, SignedPeerShareIntroduction};
use bonded_core::transport::{QuicTransport, Transport};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::select;

use crate::cert_proof;
use crate::{connect_quic_client_with_bind, extract_quic_peer_certificate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerListenerIdentity {
    pub provider_device_public_key: String,
    pub instance_nonce: String,
    pub listener_transport: String,
    pub listener_cert_fingerprint: String,
}

#[derive(Debug, Deserialize)]
struct PeerRelayAcceptResponse {
    status: String,
}

pub struct AcceptedPeerRelay {
    pub transport: QuicTransport,
    pub introduction: SignedPeerShareIntroduction,
}

/// The provider's verdict on a dialed leg, parsed from its
/// accept-response text. Pure, so the dial loop's stop signal is
/// unit-testable without a QUIC connection.
#[derive(Debug, PartialEq, Eq)]
enum RelayAcceptVerdict {
    Ok,
    NoPath,
    Rejected,
}

fn parse_relay_accept_response(text: &str) -> anyhow::Result<RelayAcceptVerdict> {
    let response: PeerRelayAcceptResponse = serde_json::from_str(text)?;
    Ok(match response.status.as_str() {
        "ok" => RelayAcceptVerdict::Ok,
        "no_path" => RelayAcceptVerdict::NoPath,
        _ => RelayAcceptVerdict::Rejected,
    })
}

pub fn verify_consumer_introduction(
    server_public_key: &str,
    expected_provider_device_public_key: &str,
    introduction: &SignedPeerShareIntroduction,
) -> anyhow::Result<()> {
    verify_server_signature(server_public_key, introduction)?;

    let claims = &introduction.introduction;
    if claims.provider_device_public_key != expected_provider_device_public_key {
        anyhow::bail!("peer introduction provider key mismatch");
    }
    ensure_not_expired(claims.expires_at)?;
    Ok(())
}

pub fn verify_provider_introduction(
    server_public_key: &str,
    listener: &PeerListenerIdentity,
    introduction: &SignedPeerShareIntroduction,
) -> anyhow::Result<()> {
    verify_server_signature(server_public_key, introduction)?;

    let claims = &introduction.introduction;
    if claims.provider_device_public_key != listener.provider_device_public_key {
        anyhow::bail!("peer introduction was not issued for this provider device");
    }
    if claims.provider_instance_nonce != listener.instance_nonce {
        anyhow::bail!("peer introduction instance nonce mismatch");
    }
    if claims.listener_transport != listener.listener_transport {
        anyhow::bail!("peer introduction listener transport mismatch");
    }
    if claims.listener_cert_fingerprint != listener.listener_cert_fingerprint {
        anyhow::bail!("peer introduction listener cert fingerprint mismatch");
    }
    ensure_not_expired(claims.expires_at)?;
    Ok(())
}

pub async fn connect_peer_relay(
    server_public_key: &str,
    expected_provider_device_public_key: &str,
    introduction: &SignedPeerShareIntroduction,
    socket_protect: Option<&SocketProtectFn>,
    bind_ip: Option<IpAddr>,
) -> anyhow::Result<PeerRelayDial> {
    verify_consumer_introduction(
        server_public_key,
        expected_provider_device_public_key,
        introduction,
    )?;

    let claims = &introduction.introduction;
    if !claims.listener_transport.eq_ignore_ascii_case("quic") {
        anyhow::bail!(
            "unsupported peer listener transport: {}",
            claims.listener_transport
        );
    }

    let endpoint = parse_peer_endpoint(&claims.provider_endpoint)?;
    let rustls_config =
        (*cert_proof::make_pinned_tls_config(&claims.listener_cert_fingerprint)).clone();
    let (_endpoint, connection) = connect_quic_client_with_bind(
        &endpoint.ip().to_string(),
        endpoint.port(),
        rustls_config,
        b"bonded-peer",
        socket_protect,
        None,
        bind_ip,
        None,
    )
    .await?;

    let presented_cert = extract_quic_peer_certificate(&connection)?;
    let presented_fingerprint = cert_proof::compute_fingerprint(&presented_cert);
    if presented_fingerprint != claims.listener_cert_fingerprint {
        anyhow::bail!(
            "peer listener cert fingerprint mismatch: expected {}, got {}",
            claims.listener_cert_fingerprint,
            presented_fingerprint
        );
    }

    let mut transport = QuicTransport::from_client_connection(connection).await?;
    transport
        .send_text(&serde_json::to_string(introduction)?)
        .await?;
    match parse_relay_accept_response(&transport.recv_text().await?)? {
        RelayAcceptVerdict::Ok => Ok(PeerRelayDial::Accepted(transport)),
        RelayAcceptVerdict::NoPath => Ok(PeerRelayDial::NoPath),
        RelayAcceptVerdict::Rejected => {
            anyhow::bail!("peer relay listener rejected introduction")
        }
    }
}

/// Outcome of dialing a peer relay: either the provider accepted the
/// leg, or it has no free provider path left for this consumer (the
/// dial-until-reject stop signal: the consumer already holds a leg for
/// every provider path).
pub enum PeerRelayDial {
    Accepted(QuicTransport),
    NoPath,
}

/// Verify a dialed leg's introduction against the listener identity.
/// Unlike the old accept path, this does NOT send the accept response:
/// the accept task sends it only after the consumer-cap and path-claim
/// checks, so a rejected leg never looks accepted to the consumer.
pub async fn accept_peer_relay(
    server_public_key: &str,
    listener: &PeerListenerIdentity,
    connection: quinn::Connection,
) -> anyhow::Result<AcceptedPeerRelay> {
    let mut transport = QuicTransport::from_server_connection(connection).await?;
    let introduction: SignedPeerShareIntroduction =
        serde_json::from_str(&transport.recv_text().await?)?;
    verify_provider_introduction(server_public_key, listener, &introduction)?;
    Ok(AcceptedPeerRelay {
        transport,
        introduction,
    })
}

pub async fn relay_peer_frames<A, B>(peer: &mut A, upstream: &mut B) -> anyhow::Result<()>
where
    A: Transport,
    B: Transport,
{
    use tracing::{debug, warn};
    loop {
        select! {
            peer_frame = peer.recv() => {
                let frame = match peer_frame {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(error = %e, "relay: peer recv failed, terminating relay");
                        return Err(e.into());
                    }
                };
                debug!(flags = frame.header.flags, payload_len = frame.payload.len(), seq = frame.header.sequence, "relay: peer->upstream forwarding frame");
                if let Err(e) = upstream.send(frame).await {
                    warn!(error = %e, "relay: upstream send failed");
                    return Err(e.into());
                }
            }
            upstream_frame = upstream.recv() => {
                let frame = match upstream_frame {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(error = %e, "relay: upstream recv failed, terminating relay");
                        return Err(e.into());
                    }
                };
                debug!(flags = frame.header.flags, payload_len = frame.payload.len(), seq = frame.header.sequence, "relay: upstream->peer forwarding frame");
                if let Err(e) = peer.send(frame).await {
                    warn!(error = %e, "relay: peer send failed");
                    return Err(e.into());
                }
            }
        }
    }
}

/// Simple pacing rate limiter for peer relay bandwidth caps.
/// `kbps == 0` means unlimited. Sends are paced so the long-term average
/// does not exceed the cap; the first send is never delayed.
pub struct PeerRelayRateLimiter {
    kbps: u64,
    next_allowed: std::time::Instant,
}

impl PeerRelayRateLimiter {
    pub fn new(kbps: u64) -> Self {
        Self {
            kbps,
            next_allowed: std::time::Instant::now(),
        }
    }

    pub fn unlimited() -> Self {
        Self::new(0)
    }

    /// Pace `bytes` under the configured cap. Returns immediately when
    /// unlimited or when still within the allowed budget.
    pub async fn throttle(&mut self, bytes: usize) {
        if self.kbps == 0 {
            return;
        }
        let bytes_per_sec = self.kbps as f64 * 125.0;
        let now = std::time::Instant::now();
        let start = self.next_allowed.max(now);
        let send_duration = std::time::Duration::from_secs_f64(bytes as f64 / bytes_per_sec);
        self.next_allowed = start + send_duration;
        if start > now {
            tokio::time::sleep(start - now).await;
        }
    }
}

/// Relay frames between peer and upstream with an optional bandwidth cap
/// applied in both directions.
pub async fn relay_peer_frames_rate_limited<A, B>(
    peer: &mut A,
    upstream: &mut B,
    limiter: &mut PeerRelayRateLimiter,
) -> anyhow::Result<()>
where
    A: Transport,
    B: Transport,
{
    use tokio::select;
    use tracing::warn;
    loop {
        select! {
            peer_frame = peer.recv() => {
                let frame = match peer_frame {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(error = %e, "relay: peer recv failed, terminating relay");
                        return Err(e.into());
                    }
                };
                limiter.throttle(frame.payload.len()).await;
                if let Err(e) = upstream.send(frame).await {
                    warn!(error = %e, "relay: upstream send failed");
                    return Err(e.into());
                }
            }
            upstream_frame = upstream.recv() => {
                let frame = match upstream_frame {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(error = %e, "relay: upstream recv failed, terminating relay");
                        return Err(e.into());
                    }
                };
                limiter.throttle(frame.payload.len()).await;
                if let Err(e) = peer.send(frame).await {
                    warn!(error = %e, "relay: peer send failed");
                    return Err(e.into());
                }
            }
        }
    }
}

pub async fn register_peer_relay_upstream<T>(
    upstream: &mut T,
    introduction: SignedPeerShareIntroduction,
) -> anyhow::Result<()>
where
    T: Transport,
{
    upstream
        .send(PeerRelayRegistration { introduction }.into_control_frame()?)
        .await
}

fn verify_server_signature(
    server_public_key: &str,
    introduction: &SignedPeerShareIntroduction,
) -> anyhow::Result<()> {
    verify_signature(
        server_public_key,
        &introduction.introduction.signing_payload()?,
        &introduction.server_signature,
    )?;
    Ok(())
}

fn ensure_not_expired(expires_at: u64) -> anyhow::Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if expires_at <= now {
        anyhow::bail!("peer introduction has expired");
    }
    Ok(())
}

fn parse_peer_endpoint(endpoint: &str) -> anyhow::Result<SocketAddr> {
    endpoint
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid peer endpoint {endpoint}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{
        accept_peer_relay, connect_peer_relay, parse_relay_accept_response,
        register_peer_relay_upstream, relay_peer_frames, verify_consumer_introduction,
        verify_provider_introduction, AcceptedPeerRelay, PeerListenerIdentity, PeerRelayDial,
        PeerRelayRateLimiter, RelayAcceptVerdict,
    };
    use bonded_core::auth::{sign_bytes, DeviceKeypair};
    use bonded_core::peer_share::{
        PeerRelayRegistration, PeerShareIntroductionClaims, SignedPeerShareIntroduction,
    };
    use bonded_core::session::{SessionFrame, SessionHeader};
    use bonded_core::transport::{Transport, TransportKind};
    use bytes::Bytes;
    use quinn::ServerConfig as QuicServerConfig;
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::{sync::Arc, time::Duration};
    use tokio::sync::mpsc;
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    use crate::cert_proof;

    #[test]
    fn provider_verification_accepts_matching_signed_introduction() {
        let server = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let claims = PeerShareIntroductionClaims {
            consumer_device_public_key: "consumer".to_owned(),
            provider_device_public_key: provider.public_key_b64.clone(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:listener-fingerprint".to_owned(),
            expires_at: now_plus(300),
        };
        let introduction = sign_introduction(&server, claims.clone());
        let listener = PeerListenerIdentity {
            provider_device_public_key: provider.public_key_b64,
            instance_nonce: claims.provider_instance_nonce,
            listener_transport: claims.listener_transport,
            listener_cert_fingerprint: claims.listener_cert_fingerprint,
        };

        verify_provider_introduction(&server.public_key_b64, &listener, &introduction)
            .expect("matching introduction should verify");
    }

    #[tokio::test]
    async fn rate_limiter_unlimited_returns_immediately() {
        let mut limiter = PeerRelayRateLimiter::unlimited();
        let start = std::time::Instant::now();
        limiter.throttle(10 * 1024 * 1024).await;
        assert!(start.elapsed() < std::time::Duration::from_millis(100));
    }

    #[tokio::test]
    async fn rate_limiter_throttles_to_configured_bandwidth() {
        // 800 kbps = 100 KB/s; pacing two 100 KB sends must take ~1s.
        let mut limiter = PeerRelayRateLimiter::new(800);
        let start = std::time::Instant::now();
        limiter.throttle(100 * 1024).await;
        limiter.throttle(100 * 1024).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed >= std::time::Duration::from_millis(900),
            "expected ~1s pacing, got {elapsed:?}"
        );
        // Upper bound is generous: on a heavily loaded CI box tokio timer
        // wakeups can be delayed well past the ~1s pacing target.
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "pacing took too long: {elapsed:?}"
        );
    }

    #[test]
    fn provider_verification_rejects_expired_introduction() {
        let server = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let claims = PeerShareIntroductionClaims {
            consumer_device_public_key: "consumer".to_owned(),
            provider_device_public_key: provider.public_key_b64.clone(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:listener-fingerprint".to_owned(),
            expires_at: now_plus(0).saturating_sub(1),
        };
        let introduction = sign_introduction(&server, claims.clone());
        let listener = PeerListenerIdentity {
            provider_device_public_key: provider.public_key_b64,
            instance_nonce: claims.provider_instance_nonce,
            listener_transport: claims.listener_transport,
            listener_cert_fingerprint: claims.listener_cert_fingerprint,
        };

        let error = verify_provider_introduction(&server.public_key_b64, &listener, &introduction)
            .expect_err("expired introduction should fail");
        assert!(error.to_string().contains("expired"));
    }

    #[test]
    fn consumer_verification_rejects_wrong_provider() {
        let server = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let claims = PeerShareIntroductionClaims {
            consumer_device_public_key: "consumer".to_owned(),
            provider_device_public_key: provider.public_key_b64,
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:listener-fingerprint".to_owned(),
            expires_at: now_plus(300),
        };
        let introduction = sign_introduction(&server, claims);

        let error = verify_consumer_introduction(
            &server.public_key_b64,
            "some-other-provider",
            &introduction,
        )
        .expect_err("wrong provider should fail");
        assert!(error.to_string().contains("provider key mismatch"));
    }

    #[tokio::test]
    async fn signed_introduction_establishes_peer_relay_quic_transport() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server_identity = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let cert = generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
            .expect("self-signed cert should build");
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let fingerprint = cert_proof::compute_fingerprint(&cert_der);

        let server_config = build_peer_server_config(cert_der.clone(), key_der);
        let endpoint = quinn::Endpoint::server(
            server_config,
            "127.0.0.1:0".parse().expect("bind address should parse"),
        )
        .expect("peer server endpoint should bind");
        let listen_addr = endpoint.local_addr().expect("local addr should resolve");
        let listener_identity = PeerListenerIdentity {
            provider_device_public_key: provider.public_key_b64.clone(),
            instance_nonce: "nonce-1".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: fingerprint.clone(),
        };

        let claims = PeerShareIntroductionClaims {
            consumer_device_public_key: "consumer".to_owned(),
            provider_device_public_key: provider.public_key_b64.clone(),
            provider_instance_nonce: listener_identity.instance_nonce.clone(),
            provider_endpoint: listen_addr.to_string(),
            listener_transport: listener_identity.listener_transport.clone(),
            listener_cert_fingerprint: listener_identity.listener_cert_fingerprint.clone(),
            expires_at: now_plus(300),
        };
        let introduction = sign_introduction(&server_identity, claims);

        let provider_key = provider.public_key_b64.clone();
        let server_public_key = server_identity.public_key_b64.clone();
        let provider_endpoint = endpoint.clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let provider_task = tokio::spawn(async move {
            let incoming = provider_endpoint
                .accept()
                .await
                .expect("incoming peer relay connection");
            let connection = incoming
                .await
                .expect("peer relay connection should complete");
            let AcceptedPeerRelay { mut transport, .. } =
                accept_peer_relay(&server_public_key, &listener_identity, connection)
                    .await
                    .expect("provider should accept peer relay introduction");
            transport
                .send_text(r#"{"status":"ok"}"#)
                .await
                .expect("provider should send accept response");
            let frame = transport
                .recv()
                .await
                .expect("provider should receive frame");
            assert_eq!(frame.payload, Bytes::from_static(b"hello-peer"));

            transport
                .send(SessionFrame {
                    header: SessionHeader {
                        connection_id: frame.header.connection_id,
                        sequence: 0,
                        flags: 0,
                    },
                    payload: Bytes::from_static(b"hello-consumer"),
                })
                .await
                .expect("provider should send reply frame");
            transport
                .close()
                .await
                .expect("provider should gracefully finish relay stream");
            let _ = shutdown_rx.await;
        });

        let PeerRelayDial::Accepted(mut consumer) = connect_peer_relay(
            &server_identity.public_key_b64,
            &provider_key,
            &introduction,
            None,
            None,
        )
        .await
        .expect("consumer should connect peer relay") else {
            panic!("provider should accept the relay leg");
        };
        consumer
            .send(SessionFrame {
                header: SessionHeader {
                    connection_id: 7,
                    sequence: 0,
                    flags: 0,
                },
                payload: Bytes::from_static(b"hello-peer"),
            })
            .await
            .expect("consumer should send frame");
        let response = timeout(Duration::from_secs(5), consumer.recv())
            .await
            .expect("consumer recv should not time out")
            .expect("consumer should receive reply frame");
        assert_eq!(response.payload, Bytes::from_static(b"hello-consumer"));

        let _ = shutdown_tx.send(());
        provider_task.await.expect("provider task should join");
    }

    #[tokio::test]
    async fn relay_peer_frames_forwards_between_peer_and_upstream() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server_identity = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let cert = generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
            .expect("self-signed cert should build");
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let fingerprint = cert_proof::compute_fingerprint(&cert_der);

        let server_config = build_peer_server_config(cert_der, key_der);
        let endpoint = quinn::Endpoint::server(
            server_config,
            "127.0.0.1:0".parse().expect("bind address should parse"),
        )
        .expect("peer server endpoint should bind");
        let listen_addr = endpoint.local_addr().expect("local addr should resolve");
        let listener_identity = PeerListenerIdentity {
            provider_device_public_key: provider.public_key_b64.clone(),
            instance_nonce: "nonce-2".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: fingerprint.clone(),
        };

        let introduction = sign_introduction(
            &server_identity,
            PeerShareIntroductionClaims {
                consumer_device_public_key: "consumer".to_owned(),
                provider_device_public_key: provider.public_key_b64.clone(),
                provider_instance_nonce: listener_identity.instance_nonce.clone(),
                provider_endpoint: listen_addr.to_string(),
                listener_transport: listener_identity.listener_transport.clone(),
                listener_cert_fingerprint: listener_identity.listener_cert_fingerprint.clone(),
                expires_at: now_plus(300),
            },
        );

        let (provider_upstream, mut upstream_control) = MockTransport::new(TransportKind::NaiveTcp);
        let provider_key = provider.public_key_b64.clone();
        let server_public_key = server_identity.public_key_b64.clone();
        let provider_endpoint = endpoint.clone();
        let provider_task = tokio::spawn(async move {
            let incoming = provider_endpoint
                .accept()
                .await
                .expect("incoming peer relay connection");
            let connection = incoming
                .await
                .expect("peer relay connection should complete");
            let AcceptedPeerRelay {
                transport: mut peer,
                ..
            } = accept_peer_relay(&server_public_key, &listener_identity, connection)
                .await
                .expect("provider should accept peer relay introduction");
            peer.send_text(r#"{"status":"ok"}"#)
                .await
                .expect("provider should send accept response");
            let mut upstream = provider_upstream;
            let relay_result = timeout(
                Duration::from_secs(5),
                relay_peer_frames(&mut peer, &mut upstream),
            )
            .await
            .expect("relay loop should stay active during exchange");
            relay_result.expect_err("relay loop should stop once test channels close");
        });

        let PeerRelayDial::Accepted(mut consumer) = connect_peer_relay(
            &server_identity.public_key_b64,
            &provider_key,
            &introduction,
            None,
            None,
        )
        .await
        .expect("consumer should connect peer relay") else {
            panic!("provider should accept the relay leg");
        };
        consumer
            .send(SessionFrame {
                header: SessionHeader {
                    connection_id: 9,
                    sequence: 0,
                    flags: 0,
                },
                payload: Bytes::from_static(b"forward-to-upstream"),
            })
            .await
            .expect("consumer should send frame");

        let forwarded = timeout(Duration::from_secs(5), upstream_control.recv_sent())
            .await
            .expect("upstream recv should not time out")
            .expect("upstream should receive forwarded frame");
        assert_eq!(
            forwarded.payload,
            Bytes::from_static(b"forward-to-upstream")
        );

        upstream_control
            .send_inbound(SessionFrame {
                header: SessionHeader {
                    connection_id: 9,
                    sequence: 0,
                    flags: 0,
                },
                payload: Bytes::from_static(b"return-to-consumer"),
            })
            .expect("upstream should accept injected reply frame");

        let response = timeout(Duration::from_secs(5), consumer.recv())
            .await
            .expect("consumer recv should not time out")
            .expect("consumer should receive relayed reply frame");
        assert_eq!(response.payload, Bytes::from_static(b"return-to-consumer"));

        drop(consumer);
        drop(upstream_control);
        provider_task
            .await
            .expect("provider relay task should join");
    }

    #[tokio::test]
    async fn peer_relay_registration_is_sent_as_control_frame() {
        let introduction = SignedPeerShareIntroduction {
            introduction: PeerShareIntroductionClaims {
                consumer_device_public_key: "consumer".to_owned(),
                provider_device_public_key: "provider".to_owned(),
                provider_instance_nonce: "nonce-1".to_owned(),
                provider_endpoint: "192.168.1.20:54443".to_owned(),
                listener_transport: "quic".to_owned(),
                listener_cert_fingerprint: "sha256:listener-fingerprint".to_owned(),
                expires_at: now_plus(300),
            },
            server_signature: "sig".to_owned(),
        };
        let (mut upstream, mut control) = MockTransport::new(TransportKind::Quic);

        register_peer_relay_upstream(&mut upstream, introduction.clone())
            .await
            .expect("relay registration should send");

        let frame = control
            .recv_sent()
            .await
            .expect("mock upstream should receive the control frame");
        let registration = PeerRelayRegistration::from_control_frame(&frame)
            .expect("control frame should parse as relay registration");
        assert_eq!(registration.introduction, introduction);
    }

    fn sign_introduction(
        server: &DeviceKeypair,
        claims: PeerShareIntroductionClaims,
    ) -> SignedPeerShareIntroduction {
        let server_signature = sign_bytes(
            server,
            &claims.signing_payload().expect("claims should serialize"),
        )
        .expect("server should sign claims");
        SignedPeerShareIntroduction {
            introduction: claims,
            server_signature,
        }
    }

    fn now_plus(offset_secs: u64) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time should be after unix epoch")
            .as_secs()
            .saturating_add(offset_secs)
    }

    fn build_peer_server_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> QuicServerConfig {
        let cert = CertificateDer::from(cert_der);
        let key = PrivateKeyDer::try_from(key_der).expect("valid private key DER");
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server TLS config should build");
        tls_config.alpn_protocols = vec![b"bonded-peer".to_vec()];

        let mut server_config = QuicServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
                .expect("QUIC crypto config should build"),
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(4u32.into());
        server_config.transport_config(Arc::new(transport));
        server_config
    }

    struct MockTransport {
        kind: TransportKind,
        inbound_rx: mpsc::UnboundedReceiver<SessionFrame>,
        outbound_tx: mpsc::UnboundedSender<SessionFrame>,
    }

    struct MockTransportControl {
        inbound_tx: mpsc::UnboundedSender<SessionFrame>,
        outbound_rx: mpsc::UnboundedReceiver<SessionFrame>,
    }

    impl MockTransport {
        fn new(kind: TransportKind) -> (Self, MockTransportControl) {
            let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
            let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
            (
                Self {
                    kind,
                    inbound_rx,
                    outbound_tx,
                },
                MockTransportControl {
                    inbound_tx,
                    outbound_rx,
                },
            )
        }
    }

    impl MockTransportControl {
        async fn recv_sent(&mut self) -> anyhow::Result<SessionFrame> {
            self.outbound_rx
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("mock transport outbound channel closed"))
        }

        fn send_inbound(&self, frame: SessionFrame) -> anyhow::Result<()> {
            self.inbound_tx
                .send(frame)
                .map_err(|_| anyhow::anyhow!("mock transport inbound channel closed"))
        }
    }

    #[async_trait::async_trait]
    impl Transport for MockTransport {
        async fn send(&mut self, frame: SessionFrame) -> anyhow::Result<()> {
            self.outbound_tx
                .send(frame)
                .map_err(|_| anyhow::anyhow!("mock transport outbound channel closed"))
        }

        async fn recv(&mut self) -> anyhow::Result<SessionFrame> {
            self.inbound_rx
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("mock transport inbound channel closed"))
        }

        fn kind(&self) -> TransportKind {
            self.kind
        }
    }

    #[test]
    fn accept_response_parsing_maps_statuses() {
        assert_eq!(
            parse_relay_accept_response(r#"{"status":"ok"}"#).unwrap(),
            RelayAcceptVerdict::Ok
        );
        assert_eq!(
            parse_relay_accept_response(r#"{"status":"no_path"}"#).unwrap(),
            RelayAcceptVerdict::NoPath
        );
        assert_eq!(
            parse_relay_accept_response(r#"{"status":"rejected"}"#).unwrap(),
            RelayAcceptVerdict::Rejected
        );
        assert_eq!(
            parse_relay_accept_response(r#"{"status":"weird"}"#).unwrap(),
            RelayAcceptVerdict::Rejected
        );
        assert!(parse_relay_accept_response("not json").is_err());
    }
}
