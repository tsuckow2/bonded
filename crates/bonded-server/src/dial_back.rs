//! Server-mediated dial-back push (4.56).
//!
//! When the server mints a reversed introduction for a consumer that
//! asked to be dialed back, it also pushes a
//! [`PeerShareDialBackNotification`] to the provider on the provider's
//! existing session, naming the consumer and the consumer's endpoints
//! plus the reversed introduction itself. The provider needs this push
//! even when it has no active relay with that consumer: the push is
//! the only way the provider learns a leg is wanted.
//!
//! Delivery reuses the session's existing outbound router
//! ([`SessionOutboundRouter::requeue`]): the notification frame is
//! handed to the router, which delivers it to one live transport of
//! the session (last-active first, as for any non-flow frame). No new
//! channel, no queueing: if the provider has no live session — no
//! registry entry, or no forwarding context for its session id —
//! the push is dropped and `push` returns `false`. The consumer
//! retries via the normal introduction flow (its next request
//! re-mints and re-pushes); nothing is stored server-side.
//!
//! The frame is addressed with the session's own connection id and
//! sequence `u64::MAX` (see `FLAG_PEER_DIAL_BACK`): an old client
//! that feeds it to the reorder buffer buffers it past the gap
//! instead of delivering it to TUN or consuming a data sequence.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use bonded_core::peer_share::PeerShareDialBackNotification;
use bonded_core::session::{SessionFrame, SessionHeader, FLAG_PEER_DIAL_BACK};

use crate::session_registry::SessionRegistry;
use crate::smoltcp_forwarder::SessionContext;

/// Registry of live forwarding contexts, keyed by session id — the
/// same registry the session handlers insert into. (Deliberately
/// the concrete type, not an alias: `bootstrap.rs` and `main.rs`
/// each declare their own `ForwarderRegistry` alias for it.)
pub type DialBackForwarders = Arc<RwLock<HashMap<u64, Arc<SessionContext>>>>;

/// Pushes dial-back notifications onto providers' live sessions.
#[derive(Clone)]
pub struct DialBackPush {
    sessions: SessionRegistry,
    forwarders: DialBackForwarders,
}

impl DialBackPush {
    pub fn new(sessions: SessionRegistry, forwarders: DialBackForwarders) -> Self {
        Self {
            sessions,
            forwarders,
        }
    }

    /// Push a dial-back notification to the provider's live session.
    /// Returns `true` when the provider had a live session and the
    /// frame was handed to its router; `false` when there was no
    /// live session (no registry entry, or no forwarding context for
    /// the session) and the notification was dropped. A `true` does
    /// NOT confirm delivery to the device: if every transport of the
    /// session is dead, the router drops the frame with its usual
    /// warning.
    pub fn push(
        &self,
        provider_device_public_key: &str,
        notification: &PeerShareDialBackNotification,
    ) -> bool {
        let Some(session_id) = self.sessions.session_id_for(provider_device_public_key) else {
            return false;
        };
        let Some(session_ctx) = self
            .forwarders
            .read()
            .expect("forwarder registry lock should not be poisoned")
            .get(&session_id)
            .cloned()
        else {
            return false;
        };
        session_ctx
            .router
            .requeue(dial_back_frame(session_id, notification));
        true
    }
}

/// Build the session frame carrying a dial-back notification:
/// the session's own connection id, sequence `u64::MAX`, and the
/// dial-back flag. Cloned from the notification so the caller keeps
/// the original.
pub fn dial_back_frame(
    session_id: u64,
    notification: &PeerShareDialBackNotification,
) -> SessionFrame {
    let payload = notification
        .clone()
        .into_control_frame()
        .expect("dial-back notification should serialize");
    SessionFrame {
        header: SessionHeader {
            connection_id: session_id as u32,
            sequence: u64::MAX,
            flags: FLAG_PEER_DIAL_BACK,
        },
        payload: payload.payload,
    }
}

#[cfg(test)]
mod tests {
    use super::{dial_back_frame, DialBackPush};
    use bonded_core::peer_share::{
        PeerShareDialBackNotification, PeerShareIntroductionClaims, SignedPeerShareIntroduction,
    };
    use bonded_core::session::FLAG_PEER_DIAL_BACK;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, RwLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::session_registry::SessionRegistry;
    use crate::smoltcp_forwarder::{SessionContext, SessionOutboundRouter, SmoltcpForwarder};

    fn notification() -> PeerShareDialBackNotification {
        PeerShareDialBackNotification {
            consumer_device_public_key: "consumer".to_owned(),
            consumer_endpoints: vec!["192.168.43.10:54443".to_owned()],
            introduction: SignedPeerShareIntroduction {
                introduction: PeerShareIntroductionClaims {
                    consumer_device_public_key: "consumer".to_owned(),
                    provider_device_public_key: "provider".to_owned(),
                    provider_instance_nonce: "nonce-1".to_owned(),
                    provider_endpoint: "192.168.1.20:54443".to_owned(),
                    listener_transport: "quic".to_owned(),
                    listener_cert_fingerprint: "sha256:consumer-listener".to_owned(),
                    expires_at: now_plus(300),
                    direction: "reverse".to_owned(),
                    consumer_endpoints: vec!["192.168.43.10:54443".to_owned()],
                },
                server_signature: "sig".to_owned(),
            },
        }
    }

    fn now_plus(offset_secs: u64) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time should be after unix epoch")
            .as_secs()
            .saturating_add(offset_secs)
    }

    /// A live forwarding context whose router has one transport
    /// wired to `transport_rx`, so a pushed frame can be observed.
    fn live_session_context() -> (
        Arc<SessionContext>,
        tokio::sync::mpsc::UnboundedReceiver<bonded_core::session::SessionFrame>,
    ) {
        let (router, fwd_tx) = SessionOutboundRouter::new();
        let (transport_tx, transport_rx) =
            tokio::sync::mpsc::unbounded_channel::<bonded_core::session::SessionFrame>();
        router.add_transport(1, transport_tx);
        let forwarder = Arc::new(SmoltcpForwarder::new(
            0,
            fwd_tx,
            Arc::new(AtomicU64::new(0)),
            std::net::SocketAddr::from(([192, 0, 2, 53], 53)),
        ));
        (Arc::new(SessionContext { forwarder, router }), transport_rx)
    }

    #[tokio::test]
    async fn push_delivers_notification_to_providers_live_transport() {
        let sessions = SessionRegistry::default();
        let handle = sessions.register_client("provider".to_owned());
        let (session_ctx, mut transport_rx) = live_session_context();
        let forwarders: Arc<RwLock<HashMap<u64, Arc<SessionContext>>>> =
            Arc::new(RwLock::new(HashMap::from([(
                handle.session_id,
                session_ctx,
            )])));
        let push = DialBackPush::new(sessions, forwarders);

        assert!(push.push("provider", &notification()));

        let frame = tokio::time::timeout(std::time::Duration::from_secs(2), transport_rx.recv())
            .await
            .expect("push should deliver promptly")
            .expect("transport should receive the frame");
        assert_eq!(frame.header.connection_id, handle.session_id as u32);
        assert_eq!(frame.header.sequence, u64::MAX);
        assert_ne!(frame.header.flags & FLAG_PEER_DIAL_BACK, 0);
        let parsed = PeerShareDialBackNotification::from_control_frame(&frame)
            .expect("pushed frame should parse as a dial-back notification");
        assert_eq!(parsed, notification());
        assert!(parsed.introduction.introduction.is_reverse());
    }

    #[tokio::test]
    async fn push_drops_notification_without_live_session() {
        let sessions = SessionRegistry::default();
        let forwarders: Arc<RwLock<HashMap<u64, Arc<SessionContext>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let push = DialBackPush::new(sessions, forwarders);

        // The provider never registered a session: no queueing, no
        // panic — the consumer retries via the introduction flow.
        assert!(!push.push("provider", &notification()));
    }

    #[tokio::test]
    async fn push_drops_notification_without_forwarding_context() {
        let sessions = SessionRegistry::default();
        let _ = sessions.register_client("provider".to_owned());
        // Registered, but the session has no forwarding context yet
        // (e.g. it died between registration and context creation).
        let forwarders: Arc<RwLock<HashMap<u64, Arc<SessionContext>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let push = DialBackPush::new(sessions, forwarders);

        assert!(!push.push("provider", &notification()));
    }

    #[test]
    fn dial_back_frame_header_is_session_id_and_max_sequence() {
        let frame = dial_back_frame(7, &notification());
        assert_eq!(frame.header.connection_id, 7);
        assert_eq!(frame.header.sequence, u64::MAX);
        assert_eq!(frame.header.flags, FLAG_PEER_DIAL_BACK);
    }
}
