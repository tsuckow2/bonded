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
//! the push is dropped and `push` returns
//! [`DialBackPushOutcome::NoLiveSession`]. The consumer
//! retries via the normal introduction flow (its next request
//! re-mints and re-pushes); nothing is stored server-side.
//!
//! Rate limit (churn-loop backoff): a flapping consumer that
//! re-requests introductions several times a second — observed
//! 2026-11-11 morning, when the OnePlus One re-authenticated via
//! the bootstrap listener several times a second and every request
//! pushed a dial-back notification to the 6a, driving its battery
//! cliff — must not hammer the provider. Pushes are paced per
//! (consumer, provider) pair: at most one push per
//! [`DIAL_BACK_PUSH_MIN_INTERVAL`]. Extra requests still mint the
//! forward introduction (the consumer can always dial forward
//! legs itself); only the provider-side push is dropped, and the
//! consumer's next request after the window re-pushes. The window
//! is far inside the 300 s introduction life, and legitimate flows
//! push far less often than once per window (renewal every ~240 s;
//! a redial burst is at most 3 attempts 10 s apart).
//!
//! The frame is addressed with the session's own connection id and
//! sequence `u64::MAX` (see `FLAG_PEER_DIAL_BACK`): an old client
//! that feeds it to the reorder buffer buffers it past the gap
//! instead of delivering it to TUN or consuming a data sequence.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bonded_core::peer_share::PeerShareDialBackNotification;
use bonded_core::session::{SessionFrame, SessionHeader, FLAG_PEER_DIAL_BACK};

use crate::session_registry::SessionRegistry;
use crate::smoltcp_forwarder::SessionContext;

/// Registry of live forwarding contexts, keyed by session id — the
/// same registry the session handlers insert into. (Deliberately
/// the concrete type, not an alias: `bootstrap.rs` and `main.rs`
/// each declare their own `ForwarderRegistry` alias for it.)
pub type DialBackForwarders = Arc<RwLock<HashMap<u64, Arc<SessionContext>>>>;

/// Minimum spacing between dial-back pushes to the same provider
/// for the same consumer. A flapping consumer re-requesting
/// introductions several times a second collapses to at most one
/// provider wakeup per window; a genuine re-auth after a real
/// disconnect still pushes within one window, far inside the 300 s
/// introduction life. 30 s also covers the densest legitimate
/// burst — the consumer redial queue's 3 attempts 10 s apart —
/// with a single push, which is all the provider needs: it is
/// already dialing from the first one, and the consumer's forward
/// dials proceed on every request regardless.
pub const DIAL_BACK_PUSH_MIN_INTERVAL: Duration = Duration::from_secs(30);

/// Outcome of a dial-back push attempt. `Pushed` does NOT confirm
/// delivery to the device: if every transport of the session is
/// dead, the router drops the frame with its usual warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialBackPushOutcome {
    /// The provider had a live session and the frame was handed to
    /// its router.
    Pushed,
    /// No live session (no registry entry, or no forwarding
    /// context for the session): the notification was dropped and
    /// no rate-limit budget was consumed.
    NoLiveSession,
    /// A push to this (consumer, provider) pair already went out
    /// inside [`DIAL_BACK_PUSH_MIN_INTERVAL`]: the notification
    /// was dropped so a flapping consumer cannot hammer the
    /// provider. The consumer's next introduction request after
    /// the window re-pushes.
    RateLimited,
}

/// Per-(consumer, provider) pacing for dial-back pushes: at most
/// one push per [`DIAL_BACK_PUSH_MIN_INTERVAL`]. Pure over an
/// explicit `now`, so the window is unit-testable without sleeping.
/// Stale entries (older than the window) are pruned on every call,
/// so the map holds at most one entry per pair active inside the
/// window — a flapping pair cannot grow it.
#[derive(Default)]
struct DialBackPushLimiter {
    last_push: HashMap<(String, String), Instant>,
}

impl DialBackPushLimiter {
    fn allow(&mut self, consumer: &str, provider: &str, now: Instant) -> bool {
        self.last_push
            .retain(|_, at| now.duration_since(*at) < DIAL_BACK_PUSH_MIN_INTERVAL);
        let key = (consumer.to_owned(), provider.to_owned());
        if self
            .last_push
            .get(&key)
            .is_some_and(|at| now.duration_since(*at) < DIAL_BACK_PUSH_MIN_INTERVAL)
        {
            return false;
        }
        self.last_push.insert(key, now);
        true
    }
}

/// Pushes dial-back notifications onto providers' live sessions.
#[derive(Clone)]
pub struct DialBackPush {
    sessions: SessionRegistry,
    forwarders: DialBackForwarders,
    limiter: Arc<Mutex<DialBackPushLimiter>>,
}

impl DialBackPush {
    pub fn new(sessions: SessionRegistry, forwarders: DialBackForwarders) -> Self {
        Self {
            sessions,
            forwarders,
            limiter: Arc::new(Mutex::new(DialBackPushLimiter::default())),
        }
    }

    /// Last-seen transport source IP for a live session (4.107):
    /// the address introduction minting resolves that device's
    /// network name from. `None` when the device has no live
    /// session — the introduction then carries no network name.
    pub fn session_source_ip(&self, device_public_key: &str) -> Option<std::net::IpAddr> {
        self.sessions.source_ip_for(device_public_key)
    }

    /// Push a dial-back notification to the provider's live session.
    /// A provider with no live session drops the notification
    /// without consuming rate-limit budget; a pair that already
    /// received a push inside [`DIAL_BACK_PUSH_MIN_INTERVAL`] is
    /// [`DialBackPushOutcome::RateLimited`] instead of waking the
    /// provider again.
    pub fn push(
        &self,
        provider_device_public_key: &str,
        notification: &PeerShareDialBackNotification,
    ) -> DialBackPushOutcome {
        let Some(session_id) = self.sessions.session_id_for(provider_device_public_key) else {
            return DialBackPushOutcome::NoLiveSession;
        };
        let Some(session_ctx) = self
            .forwarders
            .read()
            .expect("forwarder registry lock should not be poisoned")
            .get(&session_id)
            .cloned()
        else {
            return DialBackPushOutcome::NoLiveSession;
        };
        let allowed = self
            .limiter
            .lock()
            .expect("dial-back push limiter lock should not be poisoned")
            .allow(
                &notification.consumer_device_public_key,
                provider_device_public_key,
                Instant::now(),
            );
        if !allowed {
            return DialBackPushOutcome::RateLimited;
        }
        session_ctx
            .router
            .requeue(dial_back_frame(session_id, notification));
        DialBackPushOutcome::Pushed
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
    use super::{dial_back_frame, DialBackPush, DialBackPushLimiter, DialBackPushOutcome};
    use super::DIAL_BACK_PUSH_MIN_INTERVAL;
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
                    provider_network_asn_org: None,
                    provider_network_ptr: None,
                    consumer_network_asn_org: None,
                    consumer_network_ptr: None,
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

        assert_eq!(push.push("provider", &notification()), DialBackPushOutcome::Pushed);

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
        assert_eq!(push.push("provider", &notification()), DialBackPushOutcome::NoLiveSession);
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

        assert_eq!(push.push("provider", &notification()), DialBackPushOutcome::NoLiveSession);
    }

    #[test]
    fn dial_back_frame_header_is_session_id_and_max_sequence() {
        let frame = dial_back_frame(7, &notification());
        assert_eq!(frame.header.connection_id, 7);
        assert_eq!(frame.header.sequence, u64::MAX);
        assert_eq!(frame.header.flags, FLAG_PEER_DIAL_BACK);
    }

    /// The churn-loop case (2026-11-11): a consumer re-requesting
    /// introductions several times a second must not push a
    /// dial-back notification per request. The limiter allows the
    /// first push for a pair, drops the rest inside the window,
    /// and allows again once the window has passed.
    #[test]
    fn dial_back_push_limiter_allows_first_then_rate_limits() {
        use std::time::{Duration, Instant};

        let mut limiter = DialBackPushLimiter::default();
        let start = Instant::now();
        assert!(limiter.allow("consumer", "provider", start));
        // A flapping re-auth burst: 10 requests in the same window
        // produce no further pushes.
        for offset_ms in [1, 10, 100, 1000, 5000, 29_000] {
            assert!(
                !limiter.allow("consumer", "provider", start + Duration::from_millis(offset_ms)),
                "push at +{offset_ms}ms should be rate-limited"
            );
        }
        // One window after the first push, the pair may push again.
        assert!(limiter.allow(
            "consumer",
            "provider",
            start + DIAL_BACK_PUSH_MIN_INTERVAL
        ));
        // ...and is immediately limited again.
        assert!(!limiter.allow(
            "consumer",
            "provider",
            start + DIAL_BACK_PUSH_MIN_INTERVAL + Duration::from_millis(1)
        ));
    }

    /// Pacing is per (consumer, provider) pair: one flapping pair
    /// neither starves other pairs nor consumes their budget, and
    /// stale entries are pruned so the map cannot grow unboundedly.
    #[test]
    fn dial_back_push_limiter_is_per_pair_and_prunes_stale_entries() {
        use std::time::{Duration, Instant};

        let mut limiter = DialBackPushLimiter::default();
        let start = Instant::now();
        assert!(limiter.allow("consumer-a", "provider", start));
        assert!(limiter.allow("consumer-b", "provider", start));
        assert!(limiter.allow("consumer-a", "other-provider", start));
        assert_eq!(limiter.last_push.len(), 3);
        // After the window, the next allow for any pair prunes the
        // stale entries: only the fresh one remains.
        let later = start + DIAL_BACK_PUSH_MIN_INTERVAL + Duration::from_secs(1);
        assert!(limiter.allow("consumer-a", "provider", later));
        assert_eq!(limiter.last_push.len(), 1);
    }

    /// End to end through `push`: five rapid pushes for the same
    /// pair deliver exactly one frame to the provider's transport;
    /// the other four are `RateLimited`, not `Pushed`.
    #[tokio::test]
    async fn push_rate_limits_a_flapping_consumer_to_one_frame() {
        let sessions = SessionRegistry::default();
        let handle = sessions.register_client("provider".to_owned());
        let (session_ctx, mut transport_rx) = live_session_context();
        let forwarders: Arc<RwLock<HashMap<u64, Arc<SessionContext>>>> =
            Arc::new(RwLock::new(HashMap::from([(
                handle.session_id,
                session_ctx,
            )])));
        let push = DialBackPush::new(sessions, forwarders);

        assert_eq!(push.push("provider", &notification()), DialBackPushOutcome::Pushed);
        for _ in 0..4 {
            assert_eq!(
                push.push("provider", &notification()),
                DialBackPushOutcome::RateLimited
            );
        }

        // Exactly one frame arrives; nothing further follows the
        // rate-limited pushes.
        let frame = tokio::time::timeout(std::time::Duration::from_secs(2), transport_rx.recv())
            .await
            .expect("first push should deliver promptly")
            .expect("transport should receive the frame");
        assert_ne!(frame.header.flags & FLAG_PEER_DIAL_BACK, 0);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), transport_rx.recv())
                .await
                .is_err(),
            "no second frame should arrive for the rate-limited pushes"
        );
    }

    /// A no-live-session drop does not consume rate-limit budget:
    /// when the provider's session comes up, its first push goes
    /// through even though drops happened inside the window.
    #[tokio::test]
    async fn push_without_live_session_does_not_consume_rate_limit_budget() {
        let sessions = SessionRegistry::default();
        let forwarders: Arc<RwLock<HashMap<u64, Arc<SessionContext>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let push = DialBackPush::new(sessions.clone(), forwarders.clone());

        assert_eq!(
            push.push("provider", &notification()),
            DialBackPushOutcome::NoLiveSession
        );
        assert_eq!(
            push.push("provider", &notification()),
            DialBackPushOutcome::NoLiveSession
        );

        // The provider's session appears; the push goes through
        // despite the earlier drops.
        let handle = sessions.register_client("provider".to_owned());
        let (session_ctx, mut transport_rx) = live_session_context();
        forwarders.write().expect("forwarder registry lock should not be poisoned").insert(
            handle.session_id,
            session_ctx,
        );
        assert_eq!(push.push("provider", &notification()), DialBackPushOutcome::Pushed);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), transport_rx.recv())
                .await
                .is_ok(),
            "push after the session appears should deliver"
        );
    }
}
