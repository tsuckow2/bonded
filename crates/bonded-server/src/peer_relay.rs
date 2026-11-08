use anyhow::Context;
use bonded_core::auth::{verify_signature, DeviceKeypair};
use bonded_core::peer_share::{PeerRelayRegistration, SignedPeerShareIntroduction};
use bonded_core::session::{SessionFrame, FLAG_PEER_RELAY_REGISTRATION};
use bonded_core::transport::Transport;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SessionBinding {
    pub client_public_key: String,
    pub initial_frame: Option<SessionFrame>,
    pub relayed_via_provider: bool,
}

pub async fn resolve_session_binding<T>(
    transport: &mut T,
    authenticated_public_key: String,
    server_identity: &DeviceKeypair,
) -> anyhow::Result<SessionBinding>
where
    T: Transport,
{
    let first_frame = transport
        .recv()
        .await
        .context("failed to receive initial session frame")?;

    if first_frame.header.flags & FLAG_PEER_RELAY_REGISTRATION == 0 {
        return Ok(SessionBinding {
            client_public_key: authenticated_public_key,
            initial_frame: Some(first_frame),
            relayed_via_provider: false,
        });
    }

    let registration = PeerRelayRegistration::from_control_frame(&first_frame)
        .context("invalid peer relay registration control frame")?;
    verify_relay_registration(
        &registration.introduction,
        &authenticated_public_key,
        server_identity,
    )?;

    Ok(SessionBinding {
        client_public_key: registration
            .introduction
            .introduction
            .consumer_device_public_key,
        initial_frame: None,
        relayed_via_provider: true,
    })
}

fn verify_relay_registration(
    introduction: &SignedPeerShareIntroduction,
    authenticated_provider_key: &str,
    server_identity: &DeviceKeypair,
) -> anyhow::Result<()> {
    let claims = &introduction.introduction;
    verify_signature(
        &server_identity.public_key_b64,
        &claims.signing_payload()?,
        &introduction.server_signature,
    )
    .context("peer relay introduction signature verification failed")?;

    // The direction names the peer leg (forward: consumer dialed the
    // provider; reverse: provider dialed the consumer, 4.56). It
    // does NOT change the server-side binding: either way the
    // provider authenticated to the server and the session belongs to
    // the consumer, so `relayed_via_provider` accounting is identical
    // for reverse legs. Only a direction the server never mints is
    // rejected (claims minted before 4.56 parse as "forward").
    if claims.direction != "forward" && claims.direction != "reverse" {
        anyhow::bail!(
            "peer relay introduction has unknown direction: {}",
            claims.direction
        );
    }

    if claims.provider_device_public_key != authenticated_provider_key {
        anyhow::bail!(
            "peer relay introduction provider key mismatch: expected {}, got {}",
            authenticated_provider_key,
            claims.provider_device_public_key
        );
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if claims.expires_at <= now {
        anyhow::bail!("peer relay introduction expired");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::resolve_session_binding;
    use async_trait::async_trait;
    use bonded_core::auth::{sign_bytes, DeviceKeypair};
    use bonded_core::peer_share::{
        PeerRelayRegistration, PeerShareIntroductionClaims, SignedPeerShareIntroduction,
    };
    use bonded_core::session::{SessionFrame, SessionHeader};
    use bonded_core::transport::{Transport, TransportKind};
    use bytes::Bytes;
    use std::collections::VecDeque;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn relay_registration_rebinds_authenticated_provider_to_consumer_session() {
        let server_identity = DeviceKeypair::generate();
        let claims = PeerShareIntroductionClaims {
            consumer_device_public_key: "consumer".to_owned(),
            provider_device_public_key: "provider".to_owned(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            expires_at: now_plus(300),
            direction: "forward".to_owned(),
            consumer_endpoints: Vec::new(),
        };
        let registration = PeerRelayRegistration {
            introduction: SignedPeerShareIntroduction {
                introduction: claims.clone(),
                server_signature: sign_bytes(
                    &server_identity,
                    &claims.signing_payload().expect("claims should serialize"),
                )
                .expect("server should sign claims"),
            },
        };
        let mut transport = MockTransport::with_frames(vec![registration
            .into_control_frame()
            .expect("control frame should serialize")]);

        let binding =
            resolve_session_binding(&mut transport, "provider".to_owned(), &server_identity)
                .await
                .expect("relay registration should bind to the consumer session");

        assert_eq!(binding.client_public_key, "consumer");
        assert!(binding.initial_frame.is_none());
        assert!(binding.relayed_via_provider);
    }

    #[tokio::test]
    async fn reversed_relay_registration_binds_with_same_relayed_accounting() {
        // Reverse leg (4.56): the provider dialed the consumer and
        // presents the reversed introduction as its registration.
        // The direction governs the peer leg, not the server binding:
        // the session is authenticated via the provider either way,
        // so relayed_via_provider accounting is identical to the
        // forward case — the consumer's traffic is still marked as
        // relayed via the provider.
        let server_identity = DeviceKeypair::generate();
        let claims = PeerShareIntroductionClaims {
            consumer_device_public_key: "consumer".to_owned(),
            provider_device_public_key: "provider".to_owned(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:consumer-listener".to_owned(),
            expires_at: now_plus(300),
            direction: "reverse".to_owned(),
            consumer_endpoints: vec!["192.168.43.10:54443".to_owned()],
        };
        let registration = PeerRelayRegistration {
            introduction: SignedPeerShareIntroduction {
                introduction: claims.clone(),
                server_signature: sign_bytes(
                    &server_identity,
                    &claims.signing_payload().expect("claims should serialize"),
                )
                .expect("server should sign claims"),
            },
        };
        let mut transport = MockTransport::with_frames(vec![registration
            .into_control_frame()
            .expect("control frame should serialize")]);

        let binding =
            resolve_session_binding(&mut transport, "provider".to_owned(), &server_identity)
                .await
                .expect("reversed relay registration should bind to the consumer session");

        assert_eq!(binding.client_public_key, "consumer");
        assert!(binding.initial_frame.is_none());
        assert!(binding.relayed_via_provider);
    }

    #[tokio::test]
    async fn relay_registration_rejects_unknown_direction() {
        let server_identity = DeviceKeypair::generate();
        let claims = PeerShareIntroductionClaims {
            consumer_device_public_key: "consumer".to_owned(),
            provider_device_public_key: "provider".to_owned(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            expires_at: now_plus(300),
            direction: "sideways".to_owned(),
            consumer_endpoints: Vec::new(),
        };
        let registration = PeerRelayRegistration {
            introduction: SignedPeerShareIntroduction {
                introduction: claims.clone(),
                server_signature: sign_bytes(
                    &server_identity,
                    &claims.signing_payload().expect("claims should serialize"),
                )
                .expect("server should sign claims"),
            },
        };
        let mut transport = MockTransport::with_frames(vec![registration
            .into_control_frame()
            .expect("control frame should serialize")]);

        let error = match resolve_session_binding(
            &mut transport,
            "provider".to_owned(),
            &server_identity,
        )
        .await
        {
            Ok(_) => panic!("unknown direction should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unknown direction"));
    }

    #[tokio::test]
    async fn non_relay_first_frame_keeps_authenticated_session_binding() {
        let server_identity = DeviceKeypair::generate();
        let first_frame = SessionFrame {
            header: SessionHeader {
                connection_id: 7,
                sequence: 0,
                flags: 0,
            },
            payload: Bytes::from_static(b"payload"),
        };
        let mut transport = MockTransport::with_frames(vec![first_frame.clone()]);

        let binding =
            resolve_session_binding(&mut transport, "provider".to_owned(), &server_identity)
                .await
                .expect("non-relay frame should keep authenticated binding");

        assert_eq!(binding.client_public_key, "provider");
        assert_eq!(binding.initial_frame, Some(first_frame));
        assert!(!binding.relayed_via_provider);
    }

    fn now_plus(offset_secs: u64) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time should be after unix epoch")
            .as_secs()
            .saturating_add(offset_secs)
    }

    struct MockTransport {
        frames: VecDeque<SessionFrame>,
    }

    impl MockTransport {
        fn with_frames(frames: Vec<SessionFrame>) -> Self {
            Self {
                frames: VecDeque::from(frames),
            }
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn send(&mut self, _frame: SessionFrame) -> anyhow::Result<()> {
            Ok(())
        }

        async fn recv(&mut self) -> anyhow::Result<SessionFrame> {
            self.frames
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("mock transport frame queue exhausted"))
        }

        fn kind(&self) -> TransportKind {
            TransportKind::Quic
        }
    }
}
