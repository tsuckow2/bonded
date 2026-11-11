use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bonded_core::auth::{create_auth_challenge, sign_bytes, DeviceKeypair};
use bonded_core::config::{PeerShareMode, SocketProtectFn};
use bonded_core::peer_share::{
    is_advertisable_ip, PeerShareAdvertisement, PeerShareDialBackNotification,
    PeerShareIntroductionRequest, SignedPeerShareIntroduction,
};
use bonded_core::session::{SessionFrame, FLAG_PEER_DIAL_BACK};
use bonded_core::transport::QuicTransport;
use pnet_datalink::NetworkInterface;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::cert_proof;
use crate::peer_discovery::{PeerShareAdvertiser, PeerShareBrowser, utc_minute};
use crate::peer_listener::{
    accept_peer_relay_any, connect_peer_relay,
    connect_peer_relay_reversed, register_peer_relay_upstream,
    relay_peer_frames_rate_limited, verify_reversed_introduction_for_dialer, AcceptedPeerRelay,
    PeerListenerIdentity, PeerRelayDial, PeerRelayRateLimiter, PeerShareRelayStats,
};
use crate::{
    bootstrap_scheme_candidates, enumerate_interfaces, establish_single_transport_path,
    establish_transport_paths, load_or_create_device_keypair, request_bootstrap_json,
    ClientConfig, ClientTransport, SinglePathResult,
};

pub struct PeerShareRuntime {
    tasks: Vec<JoinHandle<()>>,
    relay_stats: Arc<PeerShareRelayStats>,
    /// Sender for server-pushed dial-back notifications (4.57):
    /// the session workers intercept `FLAG_PEER_DIAL_BACK` frames on
    /// the provider's server session and forward the notification
    /// here; the dial-back handler task dials the consumer back.
    /// None when this runtime never provides (consumer-only mode),
    /// so a notification has nowhere to go and is dropped by the
    /// worker instead.
    dial_back_tx: Option<tokio::sync::mpsc::UnboundedSender<PeerShareDialBackNotification>>,
}

impl PeerShareRuntime {
    /// Aggregate bytes relayed for others by this runtime's provider
    /// legs (up = consumer -> server, down = server -> consumer).
    /// Zero when this runtime never provided (consumer-only mode).
    pub fn relay_stats(&self) -> Arc<PeerShareRelayStats> {
        Arc::clone(&self.relay_stats)
    }

    /// Sender the session workers use to hand server-pushed
    /// dial-back notifications to the dial-back handler (4.57).
    /// None in consumer-only mode (no provider role, no handler).
    pub fn dial_back_tx(
        &self,
    ) -> Option<tokio::sync::mpsc::UnboundedSender<PeerShareDialBackNotification>> {
        self.dial_back_tx.clone()
    }
}

/// Sentinel path index for the default-network slot: a provider with
/// no bound paths at all still relays one leg over the default route,
/// preserving the old single-upstream behavior.
const UNPINNED_PATH_INDEX: usize = usize::MAX;

/// Where the provider reads its own path set for relay claims: the
/// live path map shared with the session worker when running under
/// Android FFI, else the session-start config bind addresses.
pub type LivePathAddresses = Arc<std::sync::RwLock<HashMap<usize, String>>>;

#[derive(Clone)]
pub enum ProviderPathSource {
    Live(LivePathAddresses),
    Config(Vec<String>),
}

impl ProviderPathSource {
    /// Current (path index, bind address) pairs in ascending index
    /// order. A single unpinned slot stands in for the default-network
    /// case (no bound paths at all).
    fn snapshot(&self) -> Vec<(usize, Option<String>)> {
        match self {
            ProviderPathSource::Live(map) => {
                let guard = map.read().expect("live path map lock poisoned");
                let mut paths: Vec<(usize, Option<String>)> = guard
                    .iter()
                    .map(|(index, address)| (*index, Some(address.clone())))
                    .collect();
                paths.sort_by_key(|(index, _)| *index);
                if paths.is_empty() {
                    vec![(UNPINNED_PATH_INDEX, None)]
                } else {
                    paths
                }
            }
            ProviderPathSource::Config(addresses) => {
                if addresses.is_empty() {
                    vec![(UNPINNED_PATH_INDEX, None)]
                } else {
                    addresses
                        .iter()
                        .enumerate()
                        .map(|(index, address)| (index, Some(address.clone())))
                        .collect()
                }
            }
        }
    }

    /// Current bind address for one claimed path index, if the path is
    /// still listed. None when the path was removed mid-relay; the
    /// task then retries until it returns or the leg is evicted.
    fn address_for(&self, path_index: usize) -> Option<String> {
        self.snapshot()
            .into_iter()
            .find(|(index, _)| *index == path_index)
            .and_then(|(_, address)| address)
    }
}

/// Per-consumer provider-path claims for multipath relays: one relay
/// leg per provider path. A claim records the introduction expiry of
/// the leg that holds it, so the takeover rule is total:
/// - a leg claims the lowest path index with no claim, or whose claim
///   is held by an OLDER introduction (a newer generation takes over
///   the path; the old leg keeps its already-established upstream
///   until it expires, and its release is a no-op because the expiry
///   no longer matches);
/// - a leg of the SAME generation cannot take over a path already
///   claimed by that generation, so dial-until-reject stops exactly
///   when every path has a leg.
#[derive(Default)]
struct RelayPathClaims {
    /// consumer device key -> (provider path index -> claim expiry secs)
    claims: HashMap<String, HashMap<usize, u64>>,
}

impl RelayPathClaims {
    fn consumer_count(&self) -> usize {
        self.claims.len()
    }

    fn has_consumer(&self, consumer: &str) -> bool {
        self.claims.contains_key(consumer)
    }

    /// Claim the lowest free path index for `consumer` from `paths`
    /// (provider path indexes in ascending order). Returns the claimed
    /// index, or None when every path is held by a live-or-newer
    /// claim. Never creates an entry for a consumer that claims
    /// nothing, so the consumer count stays exact.
    fn claim(
        &mut self,
        consumer: &str,
        paths: &[usize],
        expires_at: u64,
    ) -> Option<usize> {
        let candidate = paths.iter().copied().find(|path_index| {
            self.claims
                .get(consumer)
                .and_then(|held| held.get(path_index))
                .map_or(true, |held_expiry| *held_expiry < expires_at)
        });
        let index = candidate?;
        self.claims
            .entry(consumer.to_owned())
            .or_default()
            .insert(index, expires_at);
        Some(index)
    }

    /// Release a claim, but only if it still belongs to the ending
    /// leg (same expiry): a newer leg may have taken the path over.
    /// Drops the consumer entry when its last claim is released, so
    /// the consumer count (the provider's cap) stays exact.
    fn release(&mut self, consumer: &str, path_index: usize, expires_at: u64) {
        if let Some(held) = self.claims.get_mut(consumer) {
            if held.get(&path_index).copied() == Some(expires_at) {
                held.remove(&path_index);
            }
            if held.is_empty() {
                self.claims.remove(consumer);
            }
        }
    }
}

pub type PeerShareEventLogger = Arc<dyn Fn(String) + Send + Sync>;

const PEER_RUNTIME_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Delay before re-driving discovery for a peer whose relay path
/// closed, using its last known advertisement. mDNS `ServiceResolved`
/// fires once per service instance, so without a re-drive the browse
/// loop would wait forever for an event that never comes.
const PEER_REDISCOVERY_DELAY: Duration = Duration::from_secs(10);

/// How many times a closed peer's cached advertisement is re-driven
/// before giving up until a fresh mDNS resolution arrives. Bounds the
/// introduction requests made for a peer that has actually left.
const PEER_REDISCOVERY_MAX_ATTEMPTS: u8 = 3;

/// The browse loop's identity for a discovered peer: device key plus
/// the provider instance nonce from its advertisement.
fn peer_share_peer_id(advertisement: &PeerShareAdvertisement) -> String {
    format!(
        "{}:{}",
        advertisement.device_public_key, advertisement.instance_nonce
    )
}

/// Bounded re-drive queue for peers whose relay path closed.
///
/// Holds the last advertisement seen for each closed peer and hands it
/// back a limited number of times so the browse loop can mint a fresh
/// introduction and re-dial without depending on another mDNS
/// resolution event for the same service instance.
#[derive(Default)]
struct RedialQueue {
    queue: VecDeque<PeerShareAdvertisement>,
    queued: HashSet<String>,
    attempts_left: HashMap<String, u8>,
}

impl RedialQueue {
    /// Queue a closed peer for re-discovery. A peer that already has a
    /// redial pending keeps that single pending entry; its attempt
    /// budget is refreshed only once the previous cycle has finished.
    fn enqueue(&mut self, advertisement: PeerShareAdvertisement) {
        let peer_id = peer_share_peer_id(&advertisement);
        if self.queued.contains(&peer_id) {
            return;
        }
        self.attempts_left
            .insert(peer_id.clone(), PEER_REDISCOVERY_MAX_ATTEMPTS);
        self.queued.insert(peer_id);
        self.queue.push_back(advertisement);
    }

    /// Take the next peer to re-drive, if any.
    fn pop(&mut self) -> Option<PeerShareAdvertisement> {
        let advertisement = self.queue.pop_front()?;
        self.queued.remove(&peer_share_peer_id(&advertisement));
        Some(advertisement)
    }

    /// Record a failed re-drive attempt for a peer: re-queue it while
    /// it still has attempts left, otherwise drop it (a fresh mDNS
    /// resolution or a later path close can enqueue it again).
    fn requeue_failed(&mut self, advertisement: &PeerShareAdvertisement) {
        let peer_id = peer_share_peer_id(advertisement);
        let Some(attempts) = self.attempts_left.get_mut(&peer_id) else {
            return;
        };
        *attempts = attempts.saturating_sub(1);
        if *attempts == 0 {
            self.attempts_left.remove(&peer_id);
            return;
        }
        if self.queued.insert(peer_id) {
            self.queue.push_back(advertisement.clone());
        }
    }

    /// Forget a peer's attempt budget once it is connected again.
    fn forget(&mut self, peer_id: &str) {
        self.attempts_left.remove(peer_id);
    }
}

/// Intercept a server-pushed dial-back notification frame (4.57):
/// parse it and forward it to the peer runtime's dial-back handler
/// instead of feeding it to the session reorder buffer or the TUN
/// device. Returns true when the frame carried the dial-back flag
/// (handled, whether the parse/forward succeeded or not — a bad or
/// undeliverable notification is dropped, never retried here; the
/// consumer's next introduction request re-pushes); false otherwise,
/// so the caller keeps processing the frame as usual. Used by both
/// session workers (Linux packet loop, Android FFI worker) at every
/// point they read session frames: the steady-state receive arm AND
/// the session-binding PONG wait, where a notification arriving
/// mid-binding must not fail session start.
/// The flag check comes FIRST, before the PONG check and the data
/// path: the notification's sequence is u64::MAX and its payload is
/// JSON, so the reorder buffer would swallow it and the TUN path
/// would hand it to the kernel as a non-IP packet (4.56).
pub fn forward_dial_back_frame(
    frame: &SessionFrame,
    dial_back_tx: &Option<tokio::sync::mpsc::UnboundedSender<PeerShareDialBackNotification>>,
) -> bool {
    if frame.header.flags & FLAG_PEER_DIAL_BACK == 0 {
        return false;
    }
    match PeerShareDialBackNotification::from_control_frame(frame) {
        Ok(notification) => {
            if let Some(tx) = dial_back_tx {
                if tx.send(notification).is_err() {
                    warn!("dial-back notification dropped: dial-back handler is gone");
                }
            } else {
                warn!("dial-back notification dropped: peer-share runtime is not providing");
            }
        }
        Err(err) => {
            warn!(error = %err, "dial-back notification frame failed to parse; dropped");
        }
    }
    true
}

/// How long before a relay's introduction expires the consumer dials
/// its replacement leg (make-before-break renewal). Introductions live
/// 300 s; renewing 60 s early leaves room for one retry while the old
/// leg is still bound, so a healthy relay no longer drops to zero for
/// the rediscovery gap every five minutes (observed live 2026-10-18:
/// legs died at 301 s / 303 s / on expiry, re-forming 11–60 s later).
const PEER_RELAY_RENEWAL_LEAD_SECS: u64 = 60;

/// Delay for the single renewal retry after a failed renewal dial.
const PEER_RELAY_RENEWAL_RETRY_DELAY: Duration = Duration::from_secs(30);

/// A renewal is only worth retrying while the current leg still has
/// comfortably more than the retry delay left before expiry.
const PEER_RELAY_RENEWAL_RETRY_MIN_REMAINING_SECS: u64 =
    PEER_RELAY_RENEWAL_RETRY_DELAY.as_secs() + 5;

/// Floor for the renewal delay so a nearly-expired introduction still
/// renews promptly instead of waiting for the expiry backstop.
const PEER_RELAY_RENEWAL_MIN_DELAY: Duration = Duration::from_secs(5);

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Delay from `now_secs` until a relay whose introduction expires at
/// `expires_at` should be renewed.
fn renewal_delay(expires_at: u64, now_secs: u64) -> Duration {
    let renew_at = expires_at.saturating_sub(PEER_RELAY_RENEWAL_LEAD_SECS);
    Duration::from_secs(renew_at.saturating_sub(now_secs)).max(PEER_RELAY_RENEWAL_MIN_DELAY)
}

/// Fire a renewal notice for one peer after `delay`. The notice carries
/// the dial generation it was scheduled for; the browse loop ignores
/// notices whose generation a newer dial has superseded.
fn spawn_renewal_notice(
    renewal_tx: &tokio::sync::mpsc::UnboundedSender<(String, u64)>,
    peer_id: String,
    generation: u64,
    delay: Duration,
) {
    let renewal_tx = renewal_tx.clone();
    tokio::spawn(async move {
        sleep(delay).await;
        let _ = renewal_tx.send((peer_id, generation));
    });
}

/// Live relay legs per discovered peer, with the renewal bookkeeping.
///
/// A peer can briefly hold two legs (the renewal overlap), so
/// "connected" is a count, not a flag: discovery is only re-driven
/// when the LAST leg closes. The generation identifies the newest
/// dial; renewal notices scheduled by superseded dials are stale.
#[derive(Default)]
struct PeerLegTracker {
    legs: HashMap<String, usize>,
    generations: HashMap<String, u64>,
    expires_at: HashMap<String, u64>,
    // Direction of the peer's NEWEST leg: true when it arrived via
    // a reversed introduction (4.67). Renewal follows the newest
    // leg's direction, so a reversed leg renews in reverse instead
    // of re-dialing forward into the hotspot case.
    reversed: HashMap<String, bool>,
}

impl PeerLegTracker {
    fn is_connected(&self, peer_id: &str) -> bool {
        self.legs.get(peer_id).copied().unwrap_or(0) > 0
    }

    fn leg_count(&self, peer_id: &str) -> usize {
        self.legs.get(peer_id).copied().unwrap_or(0)
    }

    /// Whether the peer's newest leg arrived via a reversed
    /// introduction. False for forward legs and unknown peers.
    fn is_reversed(&self, peer_id: &str) -> bool {
        self.reversed.get(peer_id).copied().unwrap_or(false)
    }

    /// Record a freshly dialed leg; returns its renewal generation.
    fn note_dial(&mut self, peer_id: &str, expires_at: u64, reversed: bool) -> u64 {
        *self.legs.entry(peer_id.to_owned()).or_default() += 1;
        self.expires_at.insert(peer_id.to_owned(), expires_at);
        self.reversed.insert(peer_id.to_owned(), reversed);
        let generation = self.generations.entry(peer_id.to_owned()).or_default();
        *generation += 1;
        *generation
    }

    /// Record a closed leg. Returns true when the peer has no legs
    /// left (or was never tracked), i.e. discovery should be re-driven.
    fn note_close(&mut self, peer_id: &str) -> bool {
        match self.legs.get_mut(peer_id) {
            Some(count) => {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.legs.remove(peer_id);
                    true
                } else {
                    false
                }
            }
            None => true,
        }
    }

    fn is_current_generation(&self, peer_id: &str, generation: u64) -> bool {
        self.generations.get(peer_id).copied() == Some(generation)
    }

    fn current_generation(&self, peer_id: &str) -> Option<u64> {
        self.generations.get(peer_id).copied()
    }

    fn current_expires_at(&self, peer_id: &str) -> Option<u64> {
        self.expires_at.get(peer_id).copied()
    }
}

/// After a failed renewal dial, schedule one retry notice while the
/// current leg still has enough life left for the retry to land before
/// expiry. Otherwise the expiry + redial machinery is the backstop.
fn schedule_renewal_retry(
    legs: &PeerLegTracker,
    renewal_tx: &tokio::sync::mpsc::UnboundedSender<(String, u64)>,
    peer_id: &str,
) {
    let (Some(expires_at), Some(generation)) = (
        legs.current_expires_at(peer_id),
        legs.current_generation(peer_id),
    ) else {
        return;
    };
    if expires_at.saturating_sub(now_unix_secs()) > PEER_RELAY_RENEWAL_RETRY_MIN_REMAINING_SECS {
        spawn_renewal_notice(
            renewal_tx,
            peer_id.to_owned(),
            generation,
            PEER_RELAY_RENEWAL_RETRY_DELAY,
        );
    }
}

/// Peer ids (device key + instance nonce, as in
/// [`peer_share_peer_id`]) this device currently holds at least one
/// relay leg for, shared between the browse loop (which owns leg
/// tracking) and the accept loop (which must refuse a reversed leg
/// for an already-connected peer). The accept loop checks it BEFORE
/// sending its accept response, so a duplicate reversed leg is
/// refused with `no_path` and the provider never opens an upstream
/// for a leg the consumer would drop; the browse loop is the second
/// layer and drops a reversed leg that arrives anyway (see
/// [`note_reversed_leg`]). The second set tracks peers whose
/// reversed leg is mid-renewal (4.67): the browse loop marks a peer
/// while requesting a fresh reversed introduction, and both dedup
/// layers admit the replacement leg while the old one is still
/// live, so make-before-break holds in the reverse direction too.
#[derive(Clone, Default)]
struct ConnectedPeers {
    connected: Arc<std::sync::Mutex<HashSet<String>>>,
    reversed_renewal_pending: Arc<std::sync::Mutex<HashSet<String>>>,
}

impl ConnectedPeers {
    fn mark_connected(&self, peer_id: &str) {
        self.connected
            .lock()
            .expect("connected peers lock poisoned")
            .insert(peer_id.to_owned());
    }

    fn mark_disconnected(&self, peer_id: &str) {
        self.connected
            .lock()
            .expect("connected peers lock poisoned")
            .remove(peer_id);
    }

    fn is_connected(&self, peer_id: &str) -> bool {
        self.connected
            .lock()
            .expect("connected peers lock poisoned")
            .contains(peer_id)
    }

    fn mark_reversed_renewal_pending(&self, peer_id: &str) {
        self.reversed_renewal_pending
            .lock()
            .expect("connected peers lock poisoned")
            .insert(peer_id.to_owned());
    }

    fn clear_reversed_renewal_pending(&self, peer_id: &str) {
        self.reversed_renewal_pending
            .lock()
            .expect("connected peers lock poisoned")
            .remove(peer_id);
    }

    fn is_reversed_renewal_pending(&self, peer_id: &str) -> bool {
        self.reversed_renewal_pending
            .lock()
            .expect("connected peers lock poisoned")
            .contains(peer_id)
    }
}

/// A reversed leg the accept loop verified and accepted, handed to
/// the browse loop so all leg bookkeeping (tracker, renewal, close
/// re-drive) stays in one place. The peer id is the provider's
/// device key + instance nonce from the reversed introduction, i.e.
/// the same key the browse loop tracks forward legs under.
struct ReversedLeg {
    transport: QuicTransport,
    peer_id: String,
    expires_at: u64,
}

/// Record an incoming reversed leg in the browse loop's tracker
/// (4.57 dedup, consumer side). Returns the renewal generation when
/// the leg is accepted, or None when this device already holds a leg
/// for the peer — the caller then closes the duplicate transport.
/// The peer-level check is all the consumer can observe (it does not
/// know which provider path a reversed leg is pinned to); the
/// path-level dedup lives on the provider in `RelayPathClaims`,
/// shared by the forward accept loop and the dial-back handler, so
/// at most one leg exists per (peer, provider path) in either
/// direction.
///
/// Exception (4.67): when a reversed renewal is pending for the
/// peer, the incoming leg is the replacement for the still-live leg,
/// not a duplicate — it is accepted (the renewal overlap), and the
/// pending mark is cleared. The old leg's close later drops the
/// count back to one.
fn note_reversed_leg(
    legs: &mut PeerLegTracker,
    connected: &ConnectedPeers,
    peer_id: &str,
    expires_at: u64,
) -> Option<u64> {
    if legs.is_connected(peer_id) || connected.is_connected(peer_id) {
        if !connected.is_reversed_renewal_pending(peer_id) {
            return None;
        }
    }
    let generation = legs.note_dial(peer_id, expires_at, true);
    connected.mark_connected(peer_id);
    connected.clear_reversed_renewal_pending(peer_id);
    Some(generation)
}

impl Drop for PeerShareRuntime {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// One relay pump task for a provider-side leg (4.57): shared by
/// the forward accept loop and the dial-back handler, so both
/// directions get the same upstream re-establishment, expiry
/// abandonment, peer-closed detection, claim release, and wakeup
/// accounting. The caller has already verified the introduction,
/// claimed the provider path, and (forward) sent the accept
/// response or (reverse) received it.
#[allow(clippy::too_many_arguments)]
async fn run_relay_task(
    mut peer: QuicTransport,
    introduction: SignedPeerShareIntroduction,
    consumer_key: String,
    claimed_index: usize,
    relay_config: ClientConfig,
    relay_path_source: ProviderPathSource,
    relay_claims: Arc<std::sync::Mutex<RelayPathClaims>>,
    relay_count: Arc<AtomicUsize>,
    relay_stats: Arc<PeerShareRelayStats>,
    bandwidth_kbps: u64,
    relay_logger: Option<PeerShareEventLogger>,
) {
    let introduction_expires_at = introduction.introduction.expires_at;
    let _in_flight = relay_count.fetch_add(1, Ordering::SeqCst);
    // Wakeup accounting (battery profiler): one relay task per
    // accepted leg. Counted here, not in the pump, so a leg that
    // fails before its first pump still counts as started.
    relay_stats
        .relay_tasks_started
        .fetch_add(1, Ordering::Relaxed);
    // Resilience: if the upstream (provider->server) connection fails,
    // re-establish it instead of terminating the relay permanently.
    // The peer (consumer->provider QUIC) connection is kept alive
    // across upstream reconnects.
    let result = async {
        let mut retry_delay = std::time::Duration::from_secs(1);
        const MAX_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(30);
        loop {
            // The introduction is a short-lived credential only
            // the consumer can mint. Once it expires the server
            // rejects every re-registration, so retrying is
            // futile: abandon the relay instead. Dropping the
            // peer connection lets the consumer notice the loss
            // and mint a fresh introduction. (Observed
            // 2026-10-17: ~44 rejected re-registrations over
            // 15 minutes against one expired introduction.)
            if introduction_expired(&introduction) {
                anyhow::bail!(
                    "peer relay introduction expired; abandoning relay so the consumer can re-introduce"
                );
            }
            // One upstream per claimed provider path: the
            // leg pins to its claimed path's current bind
            // address (re-read on every re-establishment, so
            // a re-addressed path is followed and a removed
            // path retries until it returns or the leg is
            // evicted consumer-side). The unpinned slot
            // keeps the old single-upstream behavior.
            let mut upstream =
                match establish_relay_upstream(&relay_config, &relay_path_source, claimed_index).await {
                    Ok(upstream) => upstream,
                    Err(e) => {
                        tracing::warn!(error = %e, "provider: failed to establish relay upstream, retrying");
                        tokio::time::sleep(retry_delay).await;
                        retry_delay =
                            std::cmp::min(retry_delay * 2, MAX_RETRY_DELAY);
                        continue;
                    }
                };
            tracing::warn!("provider: sending relay registration");
            if let Err(e) = register_peer_relay_upstream(&mut upstream, introduction.clone()).await {
                tracing::warn!(error = %e, "provider: relay registration failed, retrying");
                tokio::time::sleep(retry_delay).await;
                retry_delay = std::cmp::min(retry_delay * 2, MAX_RETRY_DELAY);
                continue;
            }
            tracing::warn!("provider: relay registration sent");
            let mut limiter = PeerRelayRateLimiter::new(bandwidth_kbps);
            match relay_peer_frames_rate_limited(
                &mut peer,
                &mut upstream,
                &mut limiter,
                &relay_stats,
            )
            .await
            {
                Ok(()) => {
                    // Relay completed normally (peer disconnected)
                    return Ok(());
                }
                Err(e) => {
                    // A dead peer must end the task (and free
                    // its path claim) instead of looping on
                    // upstream re-establishment until the
                    // introduction expires: the peer QUIC
                    // connection reports closed, while a live
                    // peer with a dead upstream does not.
                    if peer.connection_closed() {
                        tracing::warn!("provider: peer connection closed, ending relay");
                        return Ok(());
                    }
                    tracing::warn!(error = %e, "provider: relay upstream failed, re-establishing");
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = std::cmp::min(retry_delay * 2, MAX_RETRY_DELAY);
                    // Continue loop to re-establish upstream
                }
            }
        }
    }
    .await;
    relay_count.fetch_sub(1, Ordering::SeqCst);
    // Release the path claim (a no-op when a newer leg has
    // already taken the path over) so the path is claimable
    // by the consumer's next dial.
    relay_claims.lock().expect("relay path claims lock poisoned").release(
        &consumer_key,
        claimed_index,
        introduction_expires_at,
    );
    match result {
        Ok(()) => {
            emit_peer_share_event(
                relay_logger.as_ref(),
                format!("relay loop completed for consumer={consumer_key}"),
            );
        }
        Err(err) => {
            warn!(error = %err, consumer = %consumer_key, "peer relay terminated");
            emit_peer_share_event(
                relay_logger.as_ref(),
                format!("relay terminated for consumer={consumer_key}: {err}"),
            );
        }
    }
    // Wakeup accounting (battery profiler). A task dropped
    // mid-flight by runtime shutdown never reaches this line,
    // so `ended` is a lower bound on started tasks.
    relay_stats
        .relay_tasks_ended
        .fetch_add(1, Ordering::Relaxed);
}

/// A dial-back notification the provider is ready to act on (4.57):
/// the reversed introduction verified, the consumer's endpoints
/// parsed, and a provider path claimed for the leg. The claim is
/// what makes the plan exclusive: the forward accept loop claims
/// from the same `RelayPathClaims`, so a forward and a reversed leg
/// for the same consumer can never hold the same provider path.
#[derive(Debug)]
struct DialBackPlan {
    consumer_key: String,
    endpoints: Vec<SocketAddr>,
    introduction: SignedPeerShareIntroduction,
    claimed_path: usize,
    expires_at: u64,
}

/// Decide whether a server-pushed dial-back notification should be
/// dialed, and claim the provider path for it first (4.57 dedup,
/// provider side). Pure over the claims map apart from the mutex
/// the caller holds, so the duplicate-leg cases are unit-testable
/// without a QUIC connection. Drops (Err) when the reversed
/// introduction does not verify, no consumer endpoint parses, or
/// every provider path is already held by a live-or-newer claim for
/// this consumer — the last case is the dedup working: a leg for
/// that (peer, path) already exists, so dialing would only duplicate
/// it. The caller releases the claim when the dial does not produce
/// a leg; a leg that is established hands the claim to its relay
/// task, which releases it when the leg ends.
fn plan_dial_back(
    server_public_key: &str,
    own_device_public_key: &str,
    notification: &PeerShareDialBackNotification,
    claims: &mut RelayPathClaims,
    path_indexes: &[usize],
) -> anyhow::Result<DialBackPlan> {
    verify_reversed_introduction_for_dialer(
        server_public_key,
        own_device_public_key,
        &notification.introduction,
    )?;
    let introduction_claims = &notification.introduction.introduction;
    let endpoints: Vec<SocketAddr> = introduction_claims
        .consumer_endpoints
        .iter()
        .filter_map(|endpoint| endpoint.parse().ok())
        .collect();
    if endpoints.is_empty() {
        anyhow::bail!("reversed peer introduction names no dialable consumer endpoint");
    }
    let consumer_key = introduction_claims
        .consumer_device_public_key
        .clone();
    let expires_at = introduction_claims.expires_at;
    let Some(claimed_path) = claims.claim(&consumer_key, path_indexes, expires_at) else {
        anyhow::bail!(
            "no free provider path for consumer={consumer_key}: every path already holds a leg"
        );
    };
    Ok(DialBackPlan {
        consumer_key,
        endpoints,
        introduction: notification.introduction.clone(),
        claimed_path,
        expires_at,
    })
}

/// Handle server-pushed dial-back notifications (4.57): for each one,
/// verify + claim a provider path (the dedup), dial the consumer's
/// endpoints in order with the reversed introduction, and — when the
/// consumer accepts — open the relayed server session on the claimed
/// path with the same relay task the forward accept loop uses. A
/// `no_path` accept means the consumer already holds a leg for this
/// peer (its own dedup refused the leg); a failed dial releases the
/// claim and drops the notification — the consumer's next
/// introduction request re-pushes. No retries here: the push is the
/// retry mechanism.
#[allow(clippy::too_many_arguments)]
async fn run_dial_back_handler(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<PeerShareDialBackNotification>,
    server_key: String,
    own_device_public_key: String,
    config: ClientConfig,
    socket_protect: Option<SocketProtectFn>,
    bind_ip: Option<IpAddr>,
    path_claims: Arc<std::sync::Mutex<RelayPathClaims>>,
    active_relays: Arc<AtomicUsize>,
    relay_stats: Arc<PeerShareRelayStats>,
    path_source: ProviderPathSource,
    bandwidth_kbps: u64,
    logger: Option<PeerShareEventLogger>,
) {
    while let Some(notification) = rx.recv().await {
        let consumer_key = notification.consumer_device_public_key.clone();
        let plan = {
            let mut claims = path_claims
                .lock()
                .expect("relay path claims lock poisoned");
            let path_indexes: Vec<usize> = path_source
                .snapshot()
                .iter()
                .map(|(index, _)| *index)
                .collect();
            plan_dial_back(
                &server_key,
                &own_device_public_key,
                &notification,
                &mut claims,
                &path_indexes,
            )
        };
        let plan = match plan {
            Ok(plan) => plan,
            Err(err) => {
                warn!(consumer = %consumer_key, error = %err, "dial-back dropped");
                emit_peer_share_event(
                    logger.as_ref(),
                    format!("dial-back dropped for consumer={consumer_key}: {err}"),
                );
                continue;
            }
        };
        let claimed_path = plan.claimed_path;
        let expires_at = plan.expires_at;
        info!(
            consumer = %plan.consumer_key,
            endpoints = %plan.endpoints.iter().map(SocketAddr::to_string).collect::<Vec<_>>().join(","),
            claimed_path = claimed_path,
            "dialing back consumer"
        );
        emit_peer_share_event(
            logger.as_ref(),
            format!(
                "dialing back consumer={} path={}",
                plan.consumer_key, claimed_path
            ),
        );
        match connect_peer_relay_reversed(
            &server_key,
            &own_device_public_key,
            &plan.introduction,
            socket_protect.as_ref(),
            bind_ip,
            &plan.endpoints,
        )
        .await
        {
            Ok(PeerRelayDial::Accepted(transport)) => {
                info!(
                    consumer = %plan.consumer_key,
                    claimed_path = claimed_path,
                    "dial-back relay accepted"
                );
                emit_peer_share_event(
                    logger.as_ref(),
                    format!(
                        "dial-back relay accepted for consumer={} path={}",
                        plan.consumer_key, claimed_path
                    ),
                );
                tokio::spawn(run_relay_task(
                    transport,
                    plan.introduction,
                    plan.consumer_key,
                    claimed_path,
                    config.clone(),
                    path_source.clone(),
                    path_claims.clone(),
                    active_relays.clone(),
                    relay_stats.clone(),
                    bandwidth_kbps,
                    logger.clone(),
                ));
            }
            Ok(PeerRelayDial::NoPath) => {
                // The consumer refused with no_path: it already
                // holds a leg for this peer (consumer-side dedup).
                // Release the claim so the path stays available.
                path_claims
                    .lock()
                    .expect("relay path claims lock poisoned")
                    .release(&plan.consumer_key, claimed_path, expires_at);
                warn!(
                    consumer = %plan.consumer_key,
                    "dial-back refused: consumer reports no free path (duplicate leg)"
                );
                emit_peer_share_event(
                    logger.as_ref(),
                    format!(
                        "dial-back refused for consumer={}: no free path",
                        plan.consumer_key
                    ),
                );
            }
            Err(err) => {
                path_claims
                    .lock()
                    .expect("relay path claims lock poisoned")
                    .release(&plan.consumer_key, claimed_path, expires_at);
                warn!(consumer = %plan.consumer_key, error = %err, "dial-back dial failed");
                emit_peer_share_event(
                    logger.as_ref(),
                    format!("dial-back dial failed for consumer={}: {err}", plan.consumer_key),
                );
            }
        }
    }
}

/// Accept loop for one peer-share listener endpoint: verify introductions,
/// claim provider paths, and spawn relay tasks. One loop runs per bound
/// endpoint; the advertise watcher spawns a new loop on re-bind and aborts
/// loops whose IP is no longer assigned, so existing legs on a surviving
/// endpoint are never disturbed by a re-bind.
#[allow(clippy::too_many_arguments)]
async fn run_peer_accept_loop(
    endpoint: quinn::Endpoint,
    server_key: String,
    identity: PeerListenerIdentity,
    logger: Option<PeerShareEventLogger>,
    max_consumers: usize,
    bandwidth_kbps: u64,
    path_claims: Arc<std::sync::Mutex<RelayPathClaims>>,
    active_relays: Arc<AtomicUsize>,
    relay_stats: Arc<PeerShareRelayStats>,
    path_source: ProviderPathSource,
    config: ClientConfig,
    // Consumer-side handoff for reversed legs (4.57): None in
    // provider-only mode, where no browse loop exists to take the
    // leg. `connected_peers` is the browse loop's live leg set, so
    // a duplicate reversed leg is refused before it is accepted.
    reversed_leg_tx: Option<tokio::sync::mpsc::UnboundedSender<ReversedLeg>>,
    connected_peers: ConnectedPeers,
) {
    while let Some(incoming) = endpoint.accept().await {
        let connection = match incoming.await {
            Ok(connection) => connection,
            Err(err) => {
                warn!(error = %err, "peer-share QUIC accept failed");
                emit_peer_share_event(
                    logger.as_ref(),
                    format!("QUIC accept failed: {err}"),
                );
                continue;
            }
        };

        let AcceptedPeerRelay {
            transport: mut peer,
            introduction,
        } = match accept_peer_relay_any(&server_key, &identity, connection).await {
            Ok(peer) => peer,
            Err(err) => {
                warn!(error = %err, "peer-share introduction verification failed");
                emit_peer_share_event(
                    logger.as_ref(),
                    format!("introduction verification failed: {err}"),
                );
                continue;
            }
        };
        // Reversed leg (4.57): the provider dialed this consumer's
        // listener, and the introduction verified as listener. This
        // device is the consumer here, so there is no provider path
        // to claim and no upstream to open — the transport goes to
        // the browse loop, which turns it into a session path exactly
        // like a forward dial it made itself. A provider-only
        // runtime has no consumer side and rejects the leg; a
        // duplicate (this device already holds a leg for the peer)
        // is refused with no_path, which is the dial-back handler's
        // stop signal. Exception (4.67): when a reversed renewal is
        // pending for the peer, the leg is the replacement for the
        // still-live leg, not a duplicate, so it is accepted.
        if introduction.introduction.is_reverse() {
            let provider_key = introduction
                .introduction
                .provider_device_public_key
                .clone();
            let peer_id = format!(
                "{}:{}",
                provider_key, introduction.introduction.provider_instance_nonce
            );
            let expires_at = introduction.introduction.expires_at;
            let Some(reversed_tx) = reversed_leg_tx.as_ref() else {
                warn!(provider = %provider_key, "reversed relay rejected: provider-only runtime has no consumer side");
                if peer.send_text(r#"{"status":"rejected"}"#).await.is_err() {
                    warn!(provider = %provider_key, "reversed relay reject response send failed");
                }
                continue;
            };
            if connected_peers.is_connected(&peer_id)
                && !connected_peers.is_reversed_renewal_pending(&peer_id)
            {
                warn!(peer = %peer_id, "reversed relay refused: duplicate leg for already-connected peer");
                emit_peer_share_event(
                    logger.as_ref(),
                    format!("reversed relay refused for peer={peer_id}: duplicate leg"),
                );
                if peer.send_text(r#"{"status":"no_path"}"#).await.is_err() {
                    warn!(peer = %peer_id, "reversed relay no_path response send failed");
                }
                continue;
            }
            if peer.send_text(r#"{"status":"ok"}"#).await.is_err() {
                warn!(peer = %peer_id, "reversed relay accept response send failed");
                continue;
            }
            info!(peer = %peer_id, "peer-share reversed relay accepted");
            emit_peer_share_event(
                logger.as_ref(),
                format!("accepted reversed relay for peer={peer_id}"),
            );
            if reversed_tx
                .send(ReversedLeg {
                    transport: peer,
                    peer_id,
                    expires_at,
                })
                .is_err()
            {
                warn!("reversed relay handoff channel closed; leg dropped");
            }
            continue;
        }
        let consumer_key = introduction.introduction.consumer_device_public_key.clone();
        let introduction_expires_at = introduction.introduction.expires_at;
        // Cap counts distinct consumers, not legs: one consumer
        // with N provider paths holds N legs but one consumer slot.
        // Claim the lowest provider path not held by a live-or-newer
        // claim (see RelayPathClaims); a leg with no free path is
        // rejected with no_path, which is the consumer's stop signal.
        let snapshot = path_source.snapshot();
        let snapshot_indexes: Vec<usize> =
            snapshot.iter().map(|(index, _)| *index).collect();
        enum RelayAccept {
            Accepted(usize),
            NoPath,
            CapReached,
        }
        let decision = {
            let mut claims = path_claims.lock().expect("relay path claims lock poisoned");
            if claims.consumer_count() >= max_consumers
                && !claims.has_consumer(&consumer_key)
            {
                RelayAccept::CapReached
            } else {
                match claims.claim(&consumer_key, &snapshot_indexes, introduction_expires_at)
                {
                    Some(index) => RelayAccept::Accepted(index),
                    None => RelayAccept::NoPath,
                }
            }
        };
        let claimed_index = match decision {
            RelayAccept::Accepted(index) => index,
            RelayAccept::NoPath | RelayAccept::CapReached => {
                // The cap rejection keeps the consumer's existing
                // error path (requeue/retry), while no_path ends the
                // dial loop with the legs already won.
                let (status, reason) = match decision {
                    RelayAccept::NoPath => ("no_path", "no free provider path"),
                    RelayAccept::CapReached => ("rejected", "consumer cap reached"),
                    RelayAccept::Accepted(_) => unreachable!(),
                };
                warn!(
                    consumer = %consumer_key,
                    status = status,
                    "peer-share relay rejected: {reason}"
                );
                emit_peer_share_event(
                    logger.as_ref(),
                    format!("relay rejected for consumer={consumer_key}: {reason}"),
                );
                if peer
                    .send_text(&format!(r#"{{"status":"{status}"}}"#))
                    .await
                    .is_err()
                {
                    warn!(consumer = %consumer_key, "peer-share reject response send failed");
                }
                continue;
            }
        };
        if peer.send_text(r#"{"status":"ok"}"#).await.is_err() {
            // The leg is gone before it started; release the claim
            // so the path stays available for the next dial.
            path_claims.lock().expect("relay path claims lock poisoned").release(
                &consumer_key,
                claimed_index,
                introduction_expires_at,
            );
            warn!(consumer = %consumer_key, "peer-share accept response send failed");
            continue;
        }
        info!(
            consumer = %consumer_key,
            provider_nonce = %introduction.introduction.provider_instance_nonce,
            claimed_path = claimed_index,
            "peer-share relay accepted"
        );
        emit_peer_share_event(
            logger.as_ref(),
            format!(
                "accepted relay for consumer={} provider_nonce={} path={}",
                consumer_key, introduction.introduction.provider_instance_nonce, claimed_index,
            ),
        );
        tokio::spawn(run_relay_task(
            peer,
            introduction,
            consumer_key,
            claimed_index,
            config.clone(),
            path_source.clone(),
            path_claims.clone(),
            active_relays.clone(),
            relay_stats.clone(),
            bandwidth_kbps,
            logger.clone(),
        ));
    }
}

/// How often the advertise watcher re-resolves the provider's advertise
/// IP. Path changes are rare; a few seconds of staleness is covered by
/// the consumer's redial/renewal recovery.
const PEER_ADVERTISE_POLL: Duration = Duration::from_secs(5);

/// Advertise-watcher poll while the session is idle with the screen
/// off (4.58): 30 s instead of 5 s. The watcher still wakes at the
/// next UTC minute boundary when it comes first, so the window
/// re-announce still lands inside the 10 s lock window.
const PEER_ADVERTISE_POLL_IDLE: Duration = Duration::from_secs(30);

/// Browse-recv timeout while the session is idle with the screen off
/// (4.58): the 1 s timeout exists only to notice a new UTC minute
/// within a second so the window re-query lands inside the 10 s lock
/// window; 5 s still lands inside the window and wakes the task 5x
/// less often.
const BROWSE_RECV_TIMEOUT_IDLE: Duration = Duration::from_secs(5);
const BROWSE_RECV_TIMEOUT: Duration = Duration::from_secs(1);

/// The single accept loop for the wildcard listener. The listener
/// binds the wildcard of the advertised address family, so one loop
/// serves every advertised address and no re-bind is ever needed;
/// dropping the watcher (e.g. on runtime shutdown) aborts the loop.
struct AcceptLoop {
    handle: JoinHandle<()>,
}

impl Drop for AcceptLoop {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Watch the provider's interfaces; when the advertised address list
/// changes (e.g. a hotspot is turned on or off), re-register the mDNS
/// advertisement under the same instance nonce, so consumers keep
/// treating this provider as the same peer. The listener binds the
/// wildcard of the advertised address family, so it already serves
/// every address in the new list — no re-bind, no accept-loop churn,
/// and existing legs are never disturbed. The previous advertisement
/// is shut down before the new one registers (the same instance name
/// would probe-conflict); if the new registration fails, the previous
/// advertisement is restored and the next poll retries.
async fn run_advertise_watcher(
    config: ClientConfig,
    path_source: ProviderPathSource,
    logger: Option<PeerShareEventLogger>,
    port: u16,
    initial_ips: Vec<IpAddr>,
    initial_advertisement: PeerShareAdvertisement,
    initial_advertiser: PeerShareAdvertiser,
    initial_loop: JoinHandle<()>,
    pacing_idle: Arc<AtomicBool>,
) {
    let _accept_loop = AcceptLoop {
        handle: initial_loop,
    };
    let mut current_ips = initial_ips;
    let mut current_advertisement = initial_advertisement;
    let mut advertiser: Option<PeerShareAdvertiser> = Some(initial_advertiser);
    let mut last_window_minute = utc_minute(now_unix_secs());
    loop {
        // Idle pacing (4.58): poll every 30 s instead of 5 s while
        // the session is idle with the screen off — but wake at the
        // next UTC minute boundary when it comes first, so the
        // window re-announce below still lands inside the 10 s lock
        // window even on the idle poll.
        let poll = if pacing_idle.load(Ordering::Relaxed) {
            PEER_ADVERTISE_POLL_IDLE
        } else {
            PEER_ADVERTISE_POLL
        };
        let now = now_unix_secs();
        let to_boundary = Duration::from_secs(60 - (now % 60));
        sleep(poll.min(to_boundary)).await;
        // Windowed discovery: re-announce at the start of each UTC
        // minute so a consumer whose lock is only held for the 10s
        // window still sees us. This runs every poll iteration,
        // independent of the list-change check below, which only acts
        // when the advertised addresses actually change.
        let minute = utc_minute(now_unix_secs());
        if minute != last_window_minute {
            last_window_minute = minute;
            if let Some(advertiser) = advertiser.as_ref() {
                if let Err(err) = advertiser.reannounce() {
                    warn!(error = %err, "peer-share window re-announce failed");
                }
            }
        }
        let interfaces = enumerate_interfaces();
        let Some(desired) = desired_advertise_ips(&config, &path_source, &interfaces) else {
            continue;
        };
        if desired == current_ips {
            continue;
        }
        let mut new_advertisement = current_advertisement.clone();
        new_advertisement.set_endpoints(&desired, port);
        if let Some(old) = advertiser.take() {
            let _ = old.shutdown();
        }
        match PeerShareAdvertiser::start(&new_advertisement) {
            Ok(new_adv) => {
                advertiser = Some(new_adv);
                current_ips = desired;
                current_advertisement = new_advertisement;
                info!(endpoints = %current_advertisement.endpoints.join(","), "peer-share re-advertised on new addresses");
                emit_peer_share_event(
                    logger.as_ref(),
                    format!(
                        "re-advertised endpoints={}",
                        current_advertisement.endpoints.join(",")
                    ),
                );
            }
            Err(err) => {
                warn!(error = %err, desired = ?desired, "peer-share re-advertise failed, restoring previous advertisement");
                match PeerShareAdvertiser::start(&current_advertisement) {
                    Ok(old_adv) => advertiser = Some(old_adv),
                    Err(err) => warn!(error = %err, "peer-share previous advertisement restore failed; next poll retries"),
                }
            }
        }
    }
}

/// Receives the next discovered advertisement, re-querying at the
/// start of each UTC minute for windowed discovery. mdns-sd backs a
/// long-running browse's retransmissions off to one query per hour,
/// so without an explicit re-query a consumer could sit through the
/// whole 10s lock window without sending any query. The 1s timeout
/// notices a new minute within a second; the re-query is a queued
/// command to the browser's drain task, so it is safe to issue
/// between recv calls.
/// Cached advertisements, redials, and renewals bypass this entirely:
/// they are unicast dials from the cached advertisement and need no
/// multicast lock, so a previously seen peer can be re-dialed outside
/// any window.
///
/// While the session is idle with the screen off (`pacing_idle`,
/// 4.58) the timeout is 5 s instead of 1 s: the re-query then lands
/// within 5 s of the minute boundary, still inside the 10 s window,
/// and the task wakes 5x less often.
async fn recv_discovery_in_window(
    browser: &mut PeerShareBrowser,
    last_window_minute: &mut u64,
    pacing_idle: &AtomicBool,
) -> anyhow::Result<PeerShareAdvertisement> {
    loop {
        let timeout = if pacing_idle.load(Ordering::Relaxed) {
            BROWSE_RECV_TIMEOUT_IDLE
        } else {
            BROWSE_RECV_TIMEOUT
        };
        match tokio::time::timeout(timeout, browser.recv()).await {
            Ok(result) => return result,
            Err(_) => {
                let minute = utc_minute(now_unix_secs());
                if minute != *last_window_minute {
                    *last_window_minute = minute;
                    browser.requery()?;
                }
            }
        }
    }
}

pub async fn start_peer_share_runtime(
    config: &ClientConfig,
    peer_transport_tx: tokio::sync::mpsc::UnboundedSender<ClientTransport>,
    event_logger: Option<PeerShareEventLogger>,
    provider_paths: Option<ProviderPathSource>,
    // Idle-pacing flag (4.58), shared with the session worker: set
    // while the session is idle (no traffic for 60 s+) with the
    // screen off. The browse loop and the advertise watcher slow
    // down while it is set. `None` (e.g. the Linux CLI, which has
    // no screen) means never paced.
    idle_pacing: Option<Arc<AtomicBool>>,
) -> anyhow::Result<PeerShareRuntime> {
    let private_key_path = crate::expand_home_path(&config.client.private_key_path);
    let public_key_path = crate::expand_home_path(&config.client.public_key_path);
    let device_keypair = load_or_create_device_keypair(&private_key_path, &public_key_path)?;
    let mode = config.client.peer_share_mode;
    let is_provider = mode == PeerShareMode::Both || mode == PeerShareMode::ProviderOnly;
    let is_consumer = mode == PeerShareMode::Both || mode == PeerShareMode::ConsumerOnly;

    // Provider side: QUIC listener + mDNS advertiser + accept loop.
    // The listener binds the wildcard of the advertised address
    // family, so one accept loop serves every advertised address and
    // the advertise watcher only ever re-registers the advertisement
    // (never re-binds). The certificate is embedded in the endpoint;
    // the raw DER is persisted next to the device keypair, so the
    // listener fingerprint survives a runtime restart (4.68).
    let (
        listener_endpoint,
        listener_identity,
        advertisement,
        advertiser,
        listener_advertise_ips,
        listener_port,
    ) = if is_provider {
        let (endpoint, identity, adv, advertise_ips, port) =
            build_listener_runtime(config, &device_keypair, provider_paths.as_ref()).await?;
        let advertiser = PeerShareAdvertiser::start(&adv)?;
        (
            Some(endpoint),
            Some(identity),
            Some(adv),
            Some(advertiser),
            Some(advertise_ips),
            Some(port),
        )
    } else {
        (None, None, None, None, None, None)
    };
    // Consumer side: mDNS browser
    let browser = if is_consumer {
        Some(PeerShareBrowser::start()?)
    } else {
        None
    };

    if let (Some(adv), Some(identity)) = (advertisement.as_ref(), listener_identity.as_ref()) {
        info!(
            endpoints = %adv.endpoints.join(","),
            nonce = %identity.instance_nonce,
            "peer-share runtime started"
        );
        emit_peer_share_event(
            event_logger.as_ref(),
            format!(
                "runtime started endpoints={} nonce={}",
                adv.endpoints.join(","),
                identity.instance_nonce
            ),
        );
    } else {
        info!("peer-share runtime started (consumer-only mode)");
        emit_peer_share_event(
            event_logger.as_ref(),
            "runtime started (consumer-only mode)".to_owned(),
        );
    }

    // Aggregate relayed-bytes counters for the provider legs, shared
    // with the FFI snapshot. Created in all modes so the runtime
    // always carries one; a consumer-only runtime stays at zero.
    let relay_stats = Arc::new(PeerShareRelayStats::default());

    // Provider-side shared state (4.57): ONE claim set for the whole
    // provider, shared by the forward accept loop and the dial-back
    // handler — the (peer, path) dedup lives here, so a forward and
    // a reversed leg for the same consumer can never hold the same
    // provider path. `active_relays` is likewise shared by both
    // directions' relay tasks. `connected_peers` is the browse
    // loop's live leg set, shared with the accept loop so a
    // duplicate reversed leg is refused before it is accepted.
    let path_claims = Arc::new(std::sync::Mutex::new(RelayPathClaims::default()));
    let active_relays = Arc::new(AtomicUsize::new(0));
    let connected_peers = ConnectedPeers::default();

    // Dial-back notifications (4.57): the session workers forward
    // server-pushed notifications into this channel; the handler
    // task below dials the consumer back. Created in all modes so
    // the sender can be handed out unconditionally; only a provider
    // runtime spawns the handler, so a consumer-only sender's
    // messages are dropped (nothing ever pushes to it — a
    // consumer-only device never asked for dial-back).
    let (dial_back_tx, dial_back_rx) =
        tokio::sync::mpsc::unbounded_channel::<PeerShareDialBackNotification>();
    // Reversed legs (4.57): the accept loop hands verified reversed
    // legs to the browse loop, which owns all leg bookkeeping. Only
    // meaningful in Both mode (a provider-only runtime has no browse
    // loop to take the leg; a consumer-only runtime has no accept
    // loop to produce one).
    let (reversed_leg_tx, reversed_leg_rx) =
        tokio::sync::mpsc::unbounded_channel::<ReversedLeg>();

    // The provider-path source falls back to the session-start
    // config bind addresses when no live map was supplied
    // (non-FFI clients). Computed once: the accept loop and the
    // dial-back handler share it.
    let provider_path_source = provider_paths.unwrap_or_else(|| {
        ProviderPathSource::Config(config.client.path_bind_addresses.clone())
    });

    // Idle pacing (4.58): when the session is idle with the screen
    // off, the browse loop and the advertise watcher slow down.
    // The session worker owns the flag and flips it; `None` (the
    // Linux CLI) paces nothing.
    let pacing_idle = idle_pacing.unwrap_or_default();

    // Provider side: one accept loop on the wildcard listener, owned
    // by the advertise watcher. The watcher only re-registers the
    // advertisement when the address list changes; the loop is never
    // re-bound, so existing legs are never disturbed by an interface
    // change. Dropping the runtime aborts the watcher, whose Drop
    // aborts the loop.
    let watcher_task = if is_provider {
        let accept_server_key = config.client.server_public_key.clone();
        let accept_identity = listener_identity.clone().expect("provider mode requires identity");
        let accept_logger = event_logger.clone();
        let accept_max_consumers = config.client.peer_share_max_consumers.max(1) as usize;
        let accept_bandwidth_kbps = config.client.peer_share_relay_bandwidth_kbps;
        let path_source = provider_path_source.clone();
        let initial_ips = listener_advertise_ips.expect("provider mode requires advertise IPs");
        let initial_endpoint = listener_endpoint
            .clone()
            .expect("provider mode requires listener");
        // A reversed leg only has somewhere to go when this runtime
        // is also a consumer; a provider-only runtime rejects
        // reversed introductions at the accept loop instead.
        let accept_reversed_tx = if is_consumer {
            Some(reversed_leg_tx)
        } else {
            None
        };
        let initial_handle = tokio::spawn(run_peer_accept_loop(
            initial_endpoint,
            accept_server_key,
            accept_identity.clone(),
            accept_logger.clone(),
            accept_max_consumers,
            accept_bandwidth_kbps,
            path_claims.clone(),
            active_relays.clone(),
            relay_stats.clone(),
            path_source.clone(),
            config.clone(),
            accept_reversed_tx,
            connected_peers.clone(),
        ));
        Some(tokio::spawn(run_advertise_watcher(
            config.clone(),
            path_source,
            accept_logger,
            listener_port.expect("provider mode requires listener port"),
            initial_ips,
            advertisement.clone().expect("provider mode requires advertisement"),
            advertiser.expect("provider mode requires advertiser"),
            initial_handle,
            pacing_idle.clone(),
        )))
    } else {
        None
    };

    // Dial-back handler (4.57): provider mode only. The handler
    // owns the receiver half; the runtime struct below hands the
    // sender half to the session workers. The handler shares the
    // provider's claim set, relay counters, and path source with the
    // accept loop, so its legs are deduped and accounted exactly
    // like forward legs.
    let dial_back_task = if is_provider {
        Some(tokio::spawn(run_dial_back_handler(
            dial_back_rx,
            config.client.server_public_key.clone(),
            device_keypair.public_key_b64.clone(),
            config.clone(),
            config.socket_protect.clone(),
            peer_relay_bind_ip(config)?,
            path_claims.clone(),
            active_relays.clone(),
            relay_stats.clone(),
            provider_path_source.clone(),
            config.client.peer_share_relay_bandwidth_kbps,
            event_logger.clone(),
        )))
    } else {
        None
    };
    let dial_back_tx = if is_provider {
        Some(dial_back_tx)
    } else {
        None
    };

    let browse_task = if is_consumer {
        let browse_config = config.clone();
        let browse_server_key = config.client.server_public_key.clone();
        let browse_device_keypair = device_keypair.clone();
        let browse_self_key = device_keypair.public_key_b64.clone();
        let browse_bind_ip = peer_relay_bind_ip(config)?;
        let browse_logger = event_logger.clone();
        // Reverse dial (4.56): this device can be dialed back only
        // when it runs a peer listener, i.e. in provider mode — then
        // its own advertised endpoints and listener cert fingerprint
        // ride on every introduction request, and the server mints a
        // reversed introduction and pushes a dial-back notification
        // to the provider. A consumer-only runtime requests no
        // dial-back: it has no listener, so nothing could dial it.
        // The endpoints are the STARTUP list; the advertise watcher
        // may re-register a changed list later, and the provider
        // dials the endpoints named in the minted introduction, so a
        // list change between request and dial is a known staleness
        // window (the next introduction cycle refreshes it).
        let browse_dial_back = match (advertisement.as_ref(), listener_identity.as_ref()) {
            (Some(adv), Some(identity)) => Some(DialBackParams {
                consumer_endpoints: adv.endpoints.clone(),
                consumer_listener_cert_fingerprint: identity
                    .listener_cert_fingerprint
                    .clone(),
            }),
            _ => None,
        };
        let (closed_peer_tx, mut closed_peer_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (renewal_tx, mut renewal_rx) =
            tokio::sync::mpsc::unbounded_channel::<(String, u64)>();
        let mut browser = browser.expect("consumer mode requires browser");
        // UTC minute of the last discovery-window re-query. The 1s
        // recv timeout below notices a new minute within a second, so
        // the re-query lands inside the 10s window the Kotlin lock
        // scheduler holds on the same clock (5 s while idle-paced,
        // still inside the window).
        let browse_pacing_idle = pacing_idle.clone();
        let mut last_window_minute = utc_minute(now_unix_secs());
        // Reversed legs (4.57) only arrive when this runtime also
        // provides (Both mode): the accept loop hands them over on
        // this channel. A consumer-only runtime has no accept loop,
        // so its receiver stays pending forever.
        let mut reversed_leg_rx = if is_provider {
            Some(reversed_leg_rx)
        } else {
            None
        };
        let browse_connected_peers = connected_peers.clone();
        Some(tokio::spawn(async move {
        let mut legs = PeerLegTracker::default();
        // Last advertisement seen per peer. mDNS resolves each service
        // instance only once, so when a relay path closes, the cached
        // advertisement is the only way to re-drive discovery for that
        // peer without a runtime restart.
        let mut last_seen: HashMap<String, PeerShareAdvertisement> = HashMap::new();
        let mut redials = RedialQueue::default();
        loop {
            let (advertisement, is_redial, is_renewal) = if let Some(advertisement) = redials.pop() {
                // Space re-drives out so a flapping path cannot spin
                // introduction requests.
                sleep(PEER_REDISCOVERY_DELAY).await;
                (advertisement, true, false)
            } else {
                tokio::select! {
                    Some(peer_id) = closed_peer_rx.recv() => {
                        if legs.note_close(&peer_id) {
                            browse_connected_peers.mark_disconnected(&peer_id);
                            // A dead renewal is dead: the replacement
                            // leg never arrived, so no pending
                            // renewal may admit a later leg for this
                            // peer (the redial below re-drives it).
                            browse_connected_peers
                                .clear_reversed_renewal_pending(&peer_id);
                            info!(peer = %peer_id, "peer-share path closed; allowing rediscovery");
                            emit_peer_share_event(
                                browse_logger.as_ref(),
                                format!("path closed for peer={peer_id}; allowing rediscovery"),
                            );
                            if let Some(advertisement) = last_seen.get(&peer_id) {
                                redials.enqueue(advertisement.clone());
                            }
                        } else {
                            info!(
                                peer = %peer_id,
                                remaining = legs.leg_count(&peer_id),
                                "peer-share relay leg closed; peer still connected"
                            );
                        }
                        continue;
                    }
                    Some(leg) = async {
                        match reversed_leg_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        // A leg the provider dialed to us (4.57),
                        // already verified and accepted by the accept
                        // loop. It becomes a session path exactly
                        // like a forward leg this loop dialed itself,
                        // with the same renewal and close handling.
                        // Dedup (second layer — the accept loop
                        // refused duplicates first): drop the leg
                        // when one for the peer already exists.
                        let peer_id = leg.peer_id.clone();
                        match note_reversed_leg(
                            &mut legs,
                            &browse_connected_peers,
                            &peer_id,
                            leg.expires_at,
                        ) {
                            Some(generation) => {
                                info!(peer = %peer_id, "peer-share reversed relay leg received");
                                emit_peer_share_event(
                                    browse_logger.as_ref(),
                                    format!("reversed relay leg received for peer={peer_id}"),
                                );
                                if peer_transport_tx
                                    .send(ClientTransport::peer_relay(
                                        leg.transport,
                                        peer_id.clone(),
                                        closed_peer_tx.clone(),
                                        leg.expires_at,
                                    ))
                                    .is_err()
                                {
                                    // The session worker is gone;
                                    // forget the leg we just noted.
                                    if legs.note_close(&peer_id) {
                                        browse_connected_peers.mark_disconnected(&peer_id);
                                    }
                                    break;
                                }
                                spawn_renewal_notice(
                                    &renewal_tx,
                                    peer_id.clone(),
                                    generation,
                                    renewal_delay(leg.expires_at, now_unix_secs()),
                                );
                            }
                            None => {
                                warn!(peer = %peer_id, "dropping duplicate reversed relay leg");
                                emit_peer_share_event(
                                    browse_logger.as_ref(),
                                    format!("duplicate reversed relay leg dropped for peer={peer_id}"),
                                );
                                let mut transport = leg.transport;
                                let _ = transport.close().await;
                            }
                        }
                        continue;
                    }
                    Some((peer_id, generation)) = renewal_rx.recv() => {
                        // Make-before-break renewal: dial the replacement
                        // leg while the current one is still bound.
                        if !legs.is_connected(&peer_id)
                            || !legs.is_current_generation(&peer_id, generation)
                        {
                            continue;
                        }
                        match last_seen.get(&peer_id) {
                            Some(advertisement) => {
                                info!(peer = %peer_id, "peer-share relay renewal due");
                                emit_peer_share_event(
                                    browse_logger.as_ref(),
                                    format!("relay renewal due for peer={peer_id}"),
                                );
                                if legs.is_reversed(&peer_id) && browse_dial_back.is_some() {
                                    // Reverse-aware renewal (4.67): the
                                    // live leg arrived via a reversed
                                    // introduction, so the forward dial
                                    // below would fail in the hotspot
                                    // case — the provider's forward
                                    // addresses are unreachable from
                                    // here. Request a fresh
                                    // introduction with dial-back
                                    // instead; the server mints a
                                    // reversed introduction and pushes
                                    // a dial-back notification, and the
                                    // provider dials the replacement
                                    // leg to this device's listener.
                                    // The pending mark admits that leg
                                    // while the old one is still live
                                    // (make-before-break); the retry
                                    // notice is the backstop when the
                                    // dial-back never arrives. A
                                    // consumer-only runtime has no
                                    // dial-back params and can never
                                    // hold a reversed leg, so the
                                    // forward path below is only a
                                    // defensive fallback there.
                                    browse_connected_peers
                                        .mark_reversed_renewal_pending(&peer_id);
                                    match request_peer_share_introduction(
                                        &browse_config,
                                        &browse_device_keypair,
                                        &advertisement,
                                        browse_dial_back.as_ref(),
                                    )
                                    .await
                                    {
                                        Ok(_) => {
                                            info!(peer = %peer_id, "peer-share reversed relay renewal requested; awaiting dial-back");
                                            emit_peer_share_event(
                                                browse_logger.as_ref(),
                                                format!("reversed relay renewal requested for peer={peer_id}; awaiting dial-back"),
                                            );
                                        }
                                        Err(err) => {
                                            warn!(error = %err, peer = %peer_id, "peer-share reversed renewal introduction request failed");
                                            emit_peer_share_event(
                                                browse_logger.as_ref(),
                                                format!("reversed renewal introduction request failed for peer={peer_id}: {err}"),
                                            );
                                        }
                                    }
                                    schedule_renewal_retry(&legs, &renewal_tx, &peer_id);
                                    continue;
                                }
                                (advertisement.clone(), false, true)
                            }
                            None => continue,
                        }
                    }
                    advertisement = recv_discovery_in_window(
                        &mut browser,
                        &mut last_window_minute,
                        &browse_pacing_idle,
                    ) => {
                        match advertisement {
                            Ok(advertisement) => (advertisement, false, false),
                            Err(err) => {
                                warn!(error = %err, "peer-share browser stopped");
                                emit_peer_share_event(
                                    browse_logger.as_ref(),
                                    format!("browser stopped: {err}"),
                                );
                                break;
                            }
                        }
                    }
                }
            };

            if !should_accept_discovered_peer(&advertisement, &browse_server_key, &browse_self_key)
            {
                continue;
            }

            let peer_id = peer_share_peer_id(&advertisement);
            if !is_renewal && legs.is_connected(&peer_id) {
                continue;
            }
            last_seen.insert(peer_id.clone(), advertisement.clone());
            info!(
                peer = %peer_id,
                endpoints = %advertisement.endpoints.join(","),
                "discovered peer-share advertisement"
            );
            emit_peer_share_event(
                browse_logger.as_ref(),
                format!(
                    "discovered peer={peer_id} endpoints={}",
                    advertisement.endpoints.join(",")
                ),
            );

            let introduction = match request_peer_share_introduction(
                &browse_config,
                &browse_device_keypair,
                &advertisement,
                browse_dial_back.as_ref(),
            )
            .await
            {
                Ok(introduction) => introduction,
                Err(err) => {
                    warn!(error = %err, peer = %peer_id, "peer-share introduction request failed");
                    emit_peer_share_event(
                        browse_logger.as_ref(),
                        format!("introduction request failed for peer={peer_id}: {err}"),
                    );
                    if is_redial {
                        redials.requeue_failed(&advertisement);
                    }
                    if is_renewal {
                        schedule_renewal_retry(&legs, &renewal_tx, &peer_id);
                    }
                    sleep(PEER_RUNTIME_RETRY_DELAY).await;
                    continue;
                }
            };
            info!(peer = %peer_id, "peer-share introduction issued");
            emit_peer_share_event(
                browse_logger.as_ref(),
                format!("introduction issued for peer={peer_id}"),
            );

            // One leg per provider path: dial legs with the same
            // introduction until the provider answers no_path (every
            // path has a leg) or a dial fails. Each leg dial tries
            // every advertised address in order until one connects —
            // a dead address is not a failed peer. A failed first leg
            // keeps the old error path; a failed later leg keeps the
            // legs already won (they converge to the full set at the
            // next renewal, at most one introduction cycle away).
            let relay_expires_at = introduction.introduction.expires_at;
            let mut legs_dialed = 0usize;
            let mut generation = 0u64;
            let mut dial_failed = false;
            let mut transport_channel_closed = false;
            let dial_endpoints = advertisement.endpoint_addrs();
            loop {
                match connect_peer_relay(
                    &browse_server_key,
                    &advertisement.device_public_key,
                    &introduction,
                    browse_config.socket_protect.as_ref(),
                    browse_bind_ip,
                    &dial_endpoints,
                )
                .await
                {
                    Ok(PeerRelayDial::Accepted(transport)) => {
                        emit_peer_share_event(
                            browse_logger.as_ref(),
                            format!("relay dial succeeded for peer={peer_id}"),
                        );
                        if peer_transport_tx
                            .send(ClientTransport::peer_relay(
                                transport,
                                peer_id.clone(),
                                closed_peer_tx.clone(),
                                relay_expires_at,
                            ))
                            .is_err()
                        {
                            transport_channel_closed = true;
                            break;
                        }
                        legs_dialed += 1;
                        generation = legs.note_dial(&peer_id, relay_expires_at, false);
                        browse_connected_peers.mark_connected(&peer_id);
                    }
                    Ok(PeerRelayDial::NoPath) => {
                        break;
                    }
                    Err(err) => {
                        if legs_dialed == 0 {
                            warn!(error = %err, peer = %peer_id, "peer-share relay dial failed");
                            emit_peer_share_event(
                                browse_logger.as_ref(),
                                format!("relay dial failed for peer={peer_id}: {err}"),
                            );
                            if is_redial {
                                redials.requeue_failed(&advertisement);
                            }
                            if is_renewal {
                                schedule_renewal_retry(&legs, &renewal_tx, &peer_id);
                            }
                            sleep(PEER_RUNTIME_RETRY_DELAY).await;
                            dial_failed = true;
                        } else {
                            warn!(
                                error = %err,
                                peer = %peer_id,
                                legs = legs_dialed,
                                "peer-share additional leg dial failed; keeping legs won"
                            );
                            emit_peer_share_event(
                                browse_logger.as_ref(),
                                format!(
                                    "additional leg dial failed for peer={peer_id}: {err}; keeping {legs_dialed} legs"
                                ),
                            );
                        }
                        break;
                    }
                }
            }
            if transport_channel_closed {
                break;
            }
            if legs_dialed == 0 {
                if !dial_failed {
                    // NoPath on the very first leg: the provider has no
                    // free path at all right now. Retry later like any
                    // failed dial instead of spinning on discovery.
                    warn!(peer = %peer_id, "peer-share relay dial refused: no free provider path");
                    emit_peer_share_event(
                        browse_logger.as_ref(),
                        format!("relay dial refused for peer={peer_id}: no free provider path"),
                    );
                    if is_redial {
                        redials.requeue_failed(&advertisement);
                    }
                    if is_renewal {
                        schedule_renewal_retry(&legs, &renewal_tx, &peer_id);
                    }
                    sleep(PEER_RUNTIME_RETRY_DELAY).await;
                }
                continue;
            }
            redials.forget(&peer_id);
            spawn_renewal_notice(
                &renewal_tx,
                peer_id.clone(),
                generation,
                renewal_delay(relay_expires_at, now_unix_secs()),
            );
            if is_renewal {
                emit_peer_share_event(
                    browse_logger.as_ref(),
                    format!("relay renewed for peer={peer_id}"),
                );
            }
        }
        }))
    } else {
        None
    };

    let mut tasks = Vec::new();
    if let Some(task) = watcher_task {
        tasks.push(task);
    }
    if let Some(task) = dial_back_task {
        tasks.push(task);
    }
    if let Some(task) = browse_task {
        tasks.push(task);
    }

    // Endpoints are owned by their accept loops (spawned by the watcher),
    // never by the runtime struct, so pruning an endpoint actually tears
    // it down instead of lingering on a struct-kept clone.
    Ok(PeerShareRuntime {
        tasks,
        relay_stats,
        dial_back_tx,
    })
}

/// Upstream protocols for relay legs: QUIC/WebSocket only, no
/// NaiveTCP (the old single-upstream restriction, kept for pinned
/// upstreams too).
fn relay_upstream_protocols(config: &ClientConfig) -> Vec<String> {
    let filtered: Vec<String> = config
        .client
        .preferred_protocols
        .iter()
        .filter(|protocol| {
            protocol.eq_ignore_ascii_case("wss")
                || protocol.eq_ignore_ascii_case("websocket_tls")
                || protocol.eq_ignore_ascii_case("h3")
                || protocol.eq_ignore_ascii_case("quic")
        })
        .cloned()
        .collect();
    if filtered.is_empty() {
        vec!["h3".to_owned(), "wss".to_owned()]
    } else {
        filtered
    }
}

/// Establish one relay upstream pinned to a claimed provider path:
/// the path's current bind address (re-read per attempt) via the
/// single-path dial. A stale/unassignable bind address fails fast
/// inside that dial (pre-flight), so the task's retry loop paces
/// re-establishment instead of burning establish timeouts. The
/// unpinned slot falls back to the old any-path upstream.
async fn establish_relay_upstream(
    config: &ClientConfig,
    paths: &ProviderPathSource,
    claimed_index: usize,
) -> anyhow::Result<ClientTransport> {
    if claimed_index == UNPINNED_PATH_INDEX {
        let mut upstreams = establish_peer_upstream_paths(config).await?;
        return upstreams
            .into_iter()
            .next()
            .context("peer-share relay accept produced no upstream transport paths");
    }
    let mut relay_config = config.clone();
    relay_config.client.preferred_protocols = relay_upstream_protocols(config);
    let Some(address) = paths.address_for(claimed_index) else {
        anyhow::bail!("claimed provider path {claimed_index} is no longer listed");
    };
    let mut observer = |_: String| {};
    match establish_single_transport_path(
        &relay_config,
        claimed_index,
        1,
        Some(&address),
        &mut observer,
    )
    .await?
    {
        SinglePathResult::Connected(transport) => Ok(transport),
        SinglePathResult::Failed(reason) => Err(anyhow::anyhow!(
            "relay upstream for path {claimed_index} failed: {reason}"
        )),
    }
}

async fn establish_peer_upstream_paths(
    config: &ClientConfig,
) -> anyhow::Result<Vec<ClientTransport>> {
    let mut peer_config = config.clone();
    peer_config.client.preferred_protocols = relay_upstream_protocols(config);
    Ok(establish_transport_paths(&peer_config, 1)
        .await?
        .into_iter()
        .map(|(_, transport)| transport)
        .collect())
}

/// Maximum bind attempts for the peer-share listener when the port
/// is already held (4.69): a second session worker starting while the
/// first still holds 0.0.0.0:54443 retries instead of dropping
/// peer-share on the first EADDRINUSE. The race is transient — the
/// previous worker's runtime drop releases the socket — so a short
/// bounded retry recovers it; a genuinely duplicate session (first
/// worker still alive) exhausts the budget and the error propagates
/// to the caller instead of spinning forever.
const PEER_LISTENER_BIND_MAX_ATTEMPTS: usize = 10;

/// Backoff between peer-share listener bind attempts (4.69): 100 ms,
/// doubling to a 500 ms cap. The whole retry budget is ~3.7 s — long
/// enough for a previous worker's runtime to drop and release the
/// port, short enough that session start is not stalled by a port a
/// live duplicate session will never release.
fn peer_listener_bind_retry_delay(attempt: usize) -> Duration {
    Duration::from_millis(100u64.saturating_mul(2u64.saturating_pow(attempt as u32)).min(500))
}

/// Retry a bind closure while it fails with `AddrInUse` (4.69).
/// Only address-in-use is retried: any other failure (permission,
/// invalid address, …) is not transient and returns immediately, as
/// does an `AddrInUse` once the attempt budget is spent. The delay
/// is injected so tests can run the loop with a zero delay and no
/// real sockets.
async fn retry_bind_on_addr_in_use<T>(
    mut bind: impl FnMut() -> std::io::Result<T>,
    delay_for_attempt: impl Fn(usize) -> Duration,
) -> std::io::Result<T> {
    let mut attempt = 0;
    loop {
        match bind() {
            Ok(value) => return Ok(value),
            Err(err)
                if err.kind() == std::io::ErrorKind::AddrInUse
                    && attempt + 1 < PEER_LISTENER_BIND_MAX_ATTEMPTS =>
            {
                let delay = delay_for_attempt(attempt);
                warn!(
                    attempt = attempt + 1,
                    max_attempts = PEER_LISTENER_BIND_MAX_ATTEMPTS,
                    delay_ms = delay.as_millis(),
                    "peer-share listener bind address in use; retrying"
                );
                sleep(delay).await;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Bind a peer-share QUIC listener endpoint with an existing certificate.

/// The cert is the persisted pair from `load_or_create_peer_listener_cert`,
/// so the listener fingerprint peers pin never changes across re-binds
/// or runtime restarts (4.68).
async fn bind_peer_listener_endpoint(

    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    bind_addr: SocketAddr,
    socket_protect: Option<&SocketProtectFn>,
) -> anyhow::Result<quinn::Endpoint> {
    let socket = retry_bind_on_addr_in_use(
        || std::net::UdpSocket::bind(bind_addr),
        peer_listener_bind_retry_delay,
    )
    .await
    .map_err(|err| anyhow::anyhow!("failed to bind peer-share listener on {bind_addr}: {err}"))?;
    #[cfg(unix)]
    if let Some(protect) = socket_protect {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        if !protect.0(fd) {
            anyhow::bail!(
                "failed to protect peer-share listener socket from VPN capture (fd={fd})"
            );
        }
    }
    quinn::Endpoint::new(
        Default::default(),
        Some(build_peer_server_config(cert_der, key_der)),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|err| anyhow::anyhow!("failed to bind peer-share listener on {bind_addr}: {err}"))
}


/// File names for the persisted peer-share listener certificate, kept
/// next to the device keypair (the same storage dir on Android, the
/// same `~/.local/share/bonded` dir on Linux). DER bytes, not PEM:
/// the loader hands them straight to rustls with no parsing step.
const PEER_LISTENER_CERT_FILE: &str = "peer-listener-cert.der";
const PEER_LISTENER_KEY_FILE: &str = "peer-listener-key.der";

/// Load the peer-share listener certificate, creating and persisting
/// one on first run (4.68).
///
/// Diagnosis (2026-11-11 morning window, OnePlus on vc265 as
/// consumer, 6a dialing back): the listener certificate was minted
/// fresh on every `start_peer_share_runtime` call, so its SHA-256
/// fingerprint — the value peers pin in mDNS advertisements,
/// `DialBackParams`, and server-minted introductions — changed on
/// every session-worker restart. A restart between an introduction
/// being minted and the provider dialing it left the dialer pinning
/// the old fingerprint while the listener presented the new cert,
/// and the handshake died with `server-identity-mismatch: TLS
/// certificate fingerprint mismatch` (37 such failures in the 07:xx
/// window; the same mismatch had already shown once in the 11-08
/// bench test). Nothing in the dial path can recover: the provider
/// has no channel to learn the consumer's new fingerprint except the
/// consumer's next introduction request, and in a restart storm each
/// new request is stale again by dial time. Persisting the cert
/// makes the fingerprint stable for the life of the device — an
/// introduction minted before a restart still verifies after it —
/// which fixes the reversed leg and the forward leg (stale cached
/// `last_seen` advertisement) the same way. Deleting the two files
/// rotates the identity, exactly like deleting the device keypair.
/// A write failure degrades to the old ephemeral behaviour (fresh
/// in-memory cert, warning logged) rather than failing the runtime:
/// peer-share is an enhancement, not the session itself.
fn load_or_create_peer_listener_cert(config: &ClientConfig) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let dir = crate::expand_home_path(&config.client.private_key_path)
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_default();
    let cert_path = dir.join(PEER_LISTENER_CERT_FILE);
    let key_path = dir.join(PEER_LISTENER_KEY_FILE);
    if let Ok(pair) = read_peer_listener_cert(&cert_path, &key_path) {
        return Ok(pair);
    }
    // No usable persisted pair: first run, or a corrupt/truncated
    // file (or a key that does not match the cert). Mint a fresh one.
    let cert = generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .context("failed to generate peer-share listener certificate")?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
    if let Err(err) = persist_peer_listener_cert(&cert_path, &key_path, &cert_der, &key_der) {
        warn!(error = %err, "peer-share listener certificate not persisted; its fingerprint will rotate on the next runtime restart");
    }
    Ok((cert_der, key_der))
}

/// Read a persisted listener cert/key pair, validating that the key
/// matches the cert by building the server config the listener will
/// serve. Any failure (missing file, bad DER, key/cert mismatch) is
/// an error so the caller mints a fresh pair.
fn read_peer_listener_cert(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let cert_der = std::fs::read(cert_path)?;
    let key_der = std::fs::read(key_path)?;
    try_build_peer_server_config(cert_der.clone(), key_der.clone())?;
    Ok((cert_der, key_der))
}

/// Write a listener cert/key pair to disk. The key goes first: a
/// crash between the writes leaves either no pair or a key with no
/// cert, both of which the loader regenerates — never a cert whose
/// key is missing.
fn persist_peer_listener_cert(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    cert_der: &[u8],
    key_der: &[u8],
) -> anyhow::Result<()> {
    if let Some(parent) = cert_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(key_path, key_der)?;
    std::fs::write(cert_path, cert_der)?;
    Ok(())
}

async fn build_listener_runtime(
    config: &ClientConfig,
    device_keypair: &DeviceKeypair,
    provider_paths: Option<&ProviderPathSource>,
) -> anyhow::Result<(
    quinn::Endpoint,
    PeerListenerIdentity,
    PeerShareAdvertisement,
    Vec<IpAddr>,
    u16,
)> {
    // The listener certificate is loaded-or-created from disk (4.68):
    // it is the identity peers pin, so it must survive a peer-runtime
    // restart. A fresh cert per start (the old behaviour) invalidated
    // every in-flight introduction — forward and reversed — the moment
    // the session worker restarted, and the dialer then failed the
    // handshake with a pinned-fingerprint mismatch.
    let (cert_der, key_der) = load_or_create_peer_listener_cert(config)?;
    let fingerprint = cert_proof::compute_fingerprint(&cert_der);
    let bind_addr: SocketAddr =
        config
            .client
            .peer_share_bind_address
            .parse()
            .with_context(|| {
                format!(
                    "invalid peer_share_bind_address: {}",
                    config.client.peer_share_bind_address
                )
            })?;
    // The initial selection prefers the live path set when one was
    // supplied (same basis the advertise watcher re-resolves on), so the
    // first advertisement already matches the watcher's steady state.
    let binds: Vec<String> = match provider_paths {
        Some(ProviderPathSource::Live(map)) => map
            .read()
            .expect("live path map lock poisoned")
            .values()
            .cloned()
            .collect(),
        Some(ProviderPathSource::Config(addresses)) => addresses.clone(),
        None => config.client.path_bind_addresses.clone(),
    };
    let advertise_ips = resolve_advertise_ips(
        &config.client.peer_share_advertise_ip,
        bind_addr,
        &binds,
        &enumerate_interfaces(),
        &config.client.tun_name,
    )?;
    // An unspecified bind listens on the wildcard of the primary's
    // address family, so every advertised address is dialable. A
    // pinned bind listens on that one address only, and the list is
    // a single element holding it (see resolve_advertise_ips) — but
    // only when the pinned address is itself in the advertised list.
    // A pin the allow-list dropped from the advertisement (e.g. a
    // public cellular bind) must not be bound either: the listener
    // would serve no advertised address. In that case bind the
    // wildcard of the primary's family instead, so the advertised
    // addresses are the ones actually served.
    let primary_ip = advertise_ips[0];
    let listener_bind_addr = if bind_addr.ip().is_unspecified()
        || !advertise_ips.contains(&bind_addr.ip())
    {
        let wildcard = if primary_ip.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        SocketAddr::new(wildcard, bind_addr.port())
    } else {
        bind_addr
    };
    let endpoint = bind_peer_listener_endpoint(
        cert_der.clone(),
        key_der.clone(),
        listener_bind_addr,
        config.socket_protect.as_ref(),
    )
    .await?;
    let listen_addr = endpoint.local_addr()?;
    let instance_nonce = create_auth_challenge();
    let listener_identity = PeerListenerIdentity {
        provider_device_public_key: device_keypair.public_key_b64.clone(),
        instance_nonce: instance_nonce.clone(),
        listener_transport: "quic".to_owned(),
        listener_cert_fingerprint: fingerprint.clone(),
    };
    let mut advertisement = PeerShareAdvertisement {
        version: 1,
        device_public_key: device_keypair.public_key_b64.clone(),
        server_public_key: config.client.server_public_key.clone(),
        instance_nonce,
        endpoint: String::new(),
        endpoints: Vec::new(),
        listener_cert_fingerprint: fingerprint,
        capabilities: vec!["relay".to_owned(), "quic".to_owned()],
    };
    advertisement.set_endpoints(&advertise_ips, listen_addr.port());
    Ok((
        endpoint,
        listener_identity,
        advertisement,
        advertise_ips,
        listen_addr.port(),
    ))
}

/// Whether a signed peer-share introduction has passed its expiry
/// (Unix epoch seconds, matching the server's issuance and the
/// verification-side `ensure_not_expired` check).
fn introduction_expired(introduction: &SignedPeerShareIntroduction) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    introduction.introduction.expires_at <= now
}

fn peer_relay_bind_ip(config: &ClientConfig) -> anyhow::Result<Option<IpAddr>> {
    let bind_ip = config.client.peer_share_advertise_ip.trim();
    if bind_ip.is_empty() {
        return Ok(None);
    }

    bind_ip
        .parse()
        .with_context(|| {
            format!(
                "invalid peer_share_advertise_ip for peer relay dial: {}",
                config.client.peer_share_advertise_ip
            )
        })
        .map(Some)
}

fn emit_peer_share_event(logger: Option<&PeerShareEventLogger>, message: String) {
    if let Some(logger) = logger {
        logger(message);
    }
}

async fn request_peer_share_introduction(
    config: &ClientConfig,
    consumer_keypair: &DeviceKeypair,
    advertisement: &PeerShareAdvertisement,
    dial_back: Option<&DialBackParams>,
) -> anyhow::Result<SignedPeerShareIntroduction> {
    let bootstrap_address = config.client.server_public_address.trim();
    if bootstrap_address.is_empty() {
        anyhow::bail!("server_public_address is required for peer-share introduction bootstrap");
    }

    let request = build_peer_introduction_request(consumer_keypair, advertisement, dial_back)?;
    let request_body = serde_json::to_string(&request)?;
    let mut errors = Vec::new();
    for scheme in bootstrap_scheme_candidates(config) {
        let response = match request_bootstrap_json(
            config,
            scheme,
            bootstrap_address,
            "POST",
            "/v1/bootstrap/peer-share/introduction",
            Some(&request_body),
        )
        .await
        {
            Ok(body) => body,
            Err(err) => {
                errors.push(format!("scheme={scheme:?}: {err:#}"));
                continue;
            }
        };
        return serde_json::from_str(&response)
            .map_err(|err| anyhow::anyhow!("invalid peer-share introduction JSON: {err}"));
    }

    anyhow::bail!(
        "failed to request peer-share introduction via {}: {}",
        bootstrap_address,
        errors.join(" | ")
    )
}

/// What a consumer that can itself be dialed back asks the server
/// to put in a reversed introduction (4.56): its own advertised
/// endpoints, and the cert fingerprint of its own peer listener
/// (the consumer is the listener on a reversed leg). Only built
/// when this device runs a peer listener (provider mode); a
/// consumer-only runtime has no listener to dial back to, so it
/// requests no dial-back and behaves exactly as before.
#[derive(Debug, Clone)]
pub struct DialBackParams {
    pub consumer_endpoints: Vec<String>,
    pub consumer_listener_cert_fingerprint: String,
}

fn build_peer_introduction_request(
    consumer_keypair: &DeviceKeypair,
    advertisement: &PeerShareAdvertisement,
    dial_back: Option<&DialBackParams>,
) -> anyhow::Result<PeerShareIntroductionRequest> {
    let listener_transport = advertised_listener_transport(advertisement)?;
    let mut request = PeerShareIntroductionRequest {
        consumer_device_public_key: consumer_keypair.public_key_b64.clone(),
        provider_device_public_key: advertisement.device_public_key.clone(),
        provider_instance_nonce: advertisement.instance_nonce.clone(),
        provider_endpoint: advertisement.endpoint.clone(),
        listener_transport,
        listener_cert_fingerprint: advertisement.listener_cert_fingerprint.clone(),
        consumer_signature: String::new(),
        dial_back: dial_back.is_some(),
        consumer_endpoints: dial_back
            .map(|params| params.consumer_endpoints.clone())
            .unwrap_or_default(),
        consumer_listener_cert_fingerprint: dial_back
            .map(|params| params.consumer_listener_cert_fingerprint.clone())
            .unwrap_or_default(),
    };
    request.consumer_signature = sign_bytes(consumer_keypair, &request.signed_payload()?)?;
    Ok(request)
}

fn advertised_listener_transport(advertisement: &PeerShareAdvertisement) -> anyhow::Result<String> {
    if advertisement
        .capabilities
        .iter()
        .any(|capability| capability.eq_ignore_ascii_case("quic"))
    {
        Ok("quic".to_owned())
    } else {
        anyhow::bail!("peer advertisement did not include a supported listener transport")
    }
}

fn should_accept_discovered_peer(
    advertisement: &PeerShareAdvertisement,
    expected_server_public_key: &str,
    self_public_key: &str,
) -> bool {
    advertisement.server_public_key == expected_server_public_key
        && advertisement.device_public_key != self_public_key
}

/// The client's own tunnel addresses: the VPN builder assigns
/// 10.8.0.2 (and fd00:10:8::2) to the client; the server is .1. The
/// address is identical on every client, so a peer dialing it would
/// reach its own tunnel, not this provider — never advertise it.
const TUNNEL_CLIENT_IPV4: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
const TUNNEL_CLIENT_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x10, 0x8, 0, 0, 0, 0, 2);

/// Whether an interface is the VPN tunnel: its name is the configured
/// tun device (Linux `bonded0`) or a `tun*` device (Android VpnService
/// creates tun0/tun1/…), or its address is one of the client's own
/// tunnel addresses.
fn is_tunnel_interface(name: &str, tun_name: &str, ip: &IpAddr) -> bool {
    if !tun_name.is_empty() && name == tun_name {
        return true;
    }
    if name.to_ascii_lowercase().starts_with("tun") {
        return true;
    }
    match ip {
        IpAddr::V4(ip) => *ip == TUNNEL_CLIENT_IPV4,
        IpAddr::V6(ip) => *ip == TUNNEL_CLIENT_IPV6,
    }
}

/// All addresses this provider can be dialed on: every bindable
/// address in a private/link-local block on a non-tunnel interface,
/// in a stable (sorted) order. Public addresses are excluded by the
/// block filter (a LAN peer cannot dial them — carrier NAT), as are
/// the VPN tunnel addresses (identical on every client). The caller
/// picks the primary from this list; the rest are fallbacks for the
/// consumer to try.
fn advertisable_ips_from_pairs(pairs: &[(&str, IpAddr)], tun_name: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for (name, ip) in pairs {
        if !is_advertisable_ip(ip) {
            continue;
        }
        if is_tunnel_interface(name, tun_name, ip) {
            continue;
        }
        if !is_bindable_advertise_ip(ip) {
            continue;
        }
        ips.push(*ip);
    }
    ips.sort();
    ips.dedup();
    ips
}

/// The same filter over enumerated interfaces.
fn advertisable_interface_ips(
    interfaces: &[NetworkInterface],
    tun_name: &str,
) -> Vec<IpAddr> {
    let pairs: Vec<(&str, IpAddr)> = interfaces
        .iter()
        .flat_map(|interface| {
            interface
                .ips
                .iter()
                .map(move |network| (interface.name.as_str(), network.ip()))
        })
        .collect();
    advertisable_ips_from_pairs(&pairs, tun_name)
}

/// Resolve ALL addresses to advertise for the peer-share listener.
/// An explicit `peer_share_advertise_ip` pins a single address (as
/// before); a pinned bind address likewise advertises only itself
/// (the listener only serves that address) — but only when the
/// pinned address passes the allow-list (`is_advertisable_ip`); an
/// unadvertisable pin is ignored with a warning and the enumeration
/// below decides, so a stale pin can never advertise a public
/// address. Otherwise every private/link-local, non-tunnel bindable
/// address is advertised, primary first (the existing path-subnet
/// preference), so a consumer can fall through to any address it can
/// actually reach. The list is scoped to the primary's address
/// family: the listener binds the wildcard of that family, so an
/// address of the other family would not be dialable.
fn resolve_advertise_ips(
    explicit_ip: &str,
    listen_addr: SocketAddr,
    binds: &[String],
    interfaces: &[NetworkInterface],
    tun_name: &str,
) -> anyhow::Result<Vec<IpAddr>> {
    // A pinned value is still subject to the allow-list: the pins
    // are persisted per paired server and settable from an adb-pair
    // intent or a deep link, so a stale pin naming a public address
    // (e.g. a cellular 192.0.0.4 recorded before 4.59) would
    // otherwise bypass the filter entirely and advertise an
    // unreachable address. An unadvertisable pin is ignored with a
    // warning and the filtered enumeration below decides instead —
    // the provider keeps working on its reachable addresses. (The
    // listener bind follows the same rule in
    // `build_listener_runtime`: a pin that is not itself advertised
    // is not bound.)
    if !explicit_ip.trim().is_empty() {
        let parsed: IpAddr = explicit_ip
            .parse()
            .with_context(|| format!("invalid peer_share_advertise_ip: {explicit_ip}"))?;
        if is_advertisable_ip(&parsed) {
            return Ok(vec![parsed]);
        }
        warn!(
            explicit_ip = %explicit_ip,
            "peer_share_advertise_ip is not a private/link-local address; ignoring the pin"
        );
    }

    match listen_addr.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => {
            if is_advertisable_ip(&IpAddr::V4(ip)) {
                return Ok(vec![IpAddr::V4(ip)]);
            }
            warn!(
                listen_addr = %listen_addr,
                "peer_share_bind_address is not a private/link-local address; ignoring the pin for advertisement"
            );
        }
        IpAddr::V6(ip) if !ip.is_unspecified() => {
            if is_advertisable_ip(&IpAddr::V6(ip)) {
                return Ok(vec![IpAddr::V6(ip)]);
            }
            warn!(
                listen_addr = %listen_addr,
                "peer_share_bind_address is not a private/link-local address; ignoring the pin for advertisement"
            );
        }
        _ => {}
    }

    let all = advertisable_interface_ips(interfaces, tun_name);
    if all.is_empty() {
        anyhow::bail!("failed to determine a non-loopback peer-share advertise IP");
    }
    let primary = select_advertise_ip_for_binds(binds, &all).ok_or_else(|| {
        anyhow::anyhow!("failed to determine a non-loopback peer-share advertise IP")
    })?;
    let mut list = vec![primary];
    list.extend(
        all.into_iter()
            .filter(|ip| *ip != primary && ip.is_ipv4() == primary.is_ipv4()),
    );
    Ok(list)
}

/// Pick the advertise IP from interface candidates given the provider's
/// path bind addresses: prefer an address on the same link as one of the
/// client's server paths, else the default selection. Interface
/// enumeration order is arbitrary, and on Android it includes the VPN's
/// own tunnel interface — whose address is not a LAN address a peer can
/// dial (and is identical on every client), so first-bindable-wins can
/// advertise the tunnel address and make the provider unreachable. A
/// candidate sharing a /24 with a path bind address is on the link the
/// client actually uses.
///
/// Callers pass an already-filtered candidate list (public and
/// tunnel addresses removed by `advertisable_interface_ips`); this
/// helper only picks the primary from that list. Its unit tests keep
/// the tunnel address in the candidate list to pin the preference
/// behaviour itself.
fn select_advertise_ip_for_binds(binds: &[String], candidates: &[IpAddr]) -> Option<IpAddr> {
    prefer_path_subnet_candidate(candidates, binds).or_else(|| select_advertise_ip(candidates))
}

/// Recompute the provider's advertise addresses from the CURRENT path
/// set and interfaces (the advertise watcher's view). Returns None
/// when no bindable address exists or a configured value cannot be
/// parsed; the caller then keeps the current advertisement. Pinned
/// configurations (explicit advertise IP or explicit bind address)
/// always return the pinned address, so the watcher is a no-op for
/// them. The live path set is used for the subnet preference (not the
/// session-start config), so a path change that moves the provider to
/// a new subnet re-selects onto the new link instead of clinging to
/// the old one.
fn desired_advertise_ips(
    config: &ClientConfig,
    path_source: &ProviderPathSource,
    interfaces: &[NetworkInterface],
) -> Option<Vec<IpAddr>> {
    let binds: Vec<String> = match path_source {
        ProviderPathSource::Live(map) => map.read().ok()?.values().cloned().collect(),
        ProviderPathSource::Config(addresses) => addresses.clone(),
    };
    let bind_addr = config.client.peer_share_bind_address.parse::<SocketAddr>().ok()?;
    resolve_advertise_ips(
        &config.client.peer_share_advertise_ip,
        bind_addr,
        &binds,
        interfaces,
        &config.client.tun_name,
    )
    .ok()
}

/// Pick the first bindable IPv4 candidate that shares its /24 with one of
/// the configured path bind addresses (the local addresses of the
/// client's server transports). Returns None when no candidate matches,
/// leaving default selection to apply.
fn prefer_path_subnet_candidate(candidates: &[IpAddr], bind_addresses: &[String]) -> Option<IpAddr> {
    let bind_ips: Vec<Ipv4Addr> = bind_addresses
        .iter()
        .filter_map(|raw| raw.trim().parse::<IpAddr>().ok())
        .filter_map(|ip| match ip {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect();
    if bind_ips.is_empty() {
        return None;
    }
    candidates.iter().copied().find(|candidate| {
        let IpAddr::V4(candidate_v4) = candidate else {
            return false;
        };
        if !is_bindable_advertise_ip(candidate) {
            return false;
        }
        let candidate_octets = candidate_v4.octets();
        bind_ips
            .iter()
            .any(|bind_ip| candidate_octets[..3] == bind_ip.octets()[..3])
    })
}

/// Whether the peer-share listener can actually bind and advertise this
/// address: not loopback/unspecified/multicast, and not IPv6
/// link-local. An IPv6 link-local address (fe80::/10) cannot be bound
/// without a scope id, so `UdpSocket::bind` rejects it with EINVAL —
/// and interface enumeration on phones commonly lists a link-local
/// IPv6 address ahead of the usable LAN IPv4 address. An IPv4
/// link-local address (169.254.0.0/16) binds like any IPv4 address
/// and is advertisable (see `is_advertisable_ip`).
fn is_bindable_advertise_ip(ip: &IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(_) => true,
        IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) != 0xfe80,
    }
}

/// Pick the address to advertise for the peer-share listener: a bindable
/// IPv4 address first, then any bindable address, then — so unusual setups
/// keep working — the first non-loopback address of any kind.
fn select_advertise_ip(candidates: &[IpAddr]) -> Option<IpAddr> {
    candidates
        .iter()
        .copied()
        .find(|ip| ip.is_ipv4() && is_bindable_advertise_ip(ip))
        .or_else(|| {
            candidates
                .iter()
                .copied()
                .find(|ip| is_bindable_advertise_ip(ip))
        })
        .or_else(|| {
            candidates
                .iter()
                .copied()
                .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
        })
}

fn build_peer_server_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> quinn::ServerConfig {
    try_build_peer_server_config(cert_der, key_der).expect("valid peer listener certificate")
}

/// Fallible form of `build_peer_server_config`: the listener-cert
/// loader uses it to validate a persisted pair (a key that does not
/// match its cert, or bad DER, is an error so the pair is regenerated
/// instead of served).
fn try_build_peer_server_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> anyhow::Result<quinn::ServerConfig> {
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::try_from(key_der)
        .map_err(|err| anyhow::anyhow!("invalid peer listener private key: {err}"))?;
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|err| anyhow::anyhow!("invalid peer listener certificate: {err}"))?;
    tls_config.alpn_protocols = vec![b"bonded-peer".to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .expect("QUIC crypto config should build"),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4u32.into());
    // Peer relays are standby failover paths: they sit idle until the primary
    // path fails. Quinn's default 30s max idle timeout would silently kill an
    // idle relay, so send periodic PINGs to keep the QUIC connection alive.
    // 25 s is the longest cadence that still stays under that 30 s
    // timeout (and under typical NAT timeouts); it matches the
    // session-level idle heartbeat, so a parked relay can be re-pinged
    // on demand without a fresh handshake.
    transport.keep_alive_interval(Some(Duration::from_secs(25)));
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

#[cfg(test)]
mod tests {
    use bonded_core::auth::{sign_bytes, verify_signature};

    use super::{
        advertisable_ips_from_pairs, build_peer_introduction_request, forward_dial_back_frame,

        introduction_expired, is_tunnel_interface,
        load_or_create_peer_listener_cert, note_reversed_leg, peer_listener_bind_retry_delay,
        peer_share_peer_id, plan_dial_back, prefer_path_subnet_candidate, renewal_delay,
        resolve_advertise_ips, retry_bind_on_addr_in_use, select_advertise_ip,
        select_advertise_ip_for_binds, should_accept_discovered_peer, ConnectedPeers,
        DialBackParams, PeerLegTracker, RedialQueue, RelayPathClaims,
        PEER_LISTENER_BIND_MAX_ATTEMPTS, PEER_REDISCOVERY_MAX_ATTEMPTS,
        PEER_RELAY_RENEWAL_LEAD_SECS, PEER_RELAY_RENEWAL_MIN_DELAY,


    };
    use bonded_core::auth::DeviceKeypair;
    use bonded_core::config::{ClientConfig, PeerShareMode};
    use bonded_core::peer_share::{
        PeerShareAdvertisement, PeerShareDialBackNotification, PeerShareIntroductionClaims,
        PeerShareIntroductionRequest, SignedPeerShareIntroduction,
    };
    use bonded_core::session::{SessionFrame, SessionHeader, FLAG_PEER_DIAL_BACK};
    use bytes::Bytes;
    use pnet_datalink::NetworkInterface;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn leg_tracker_counts_overlapping_legs_per_peer() {
        let mut tracker = PeerLegTracker::default();
        assert!(!tracker.is_connected("peer-a"));

        // First dial: connected with one leg; rediscovery signal only
        // fires when the LAST leg closes.
        tracker.note_dial("peer-a", 1_000, false);
        assert!(tracker.is_connected("peer-a"));
        assert_eq!(tracker.leg_count("peer-a"), 1);

        // Renewal overlap: a second leg for the same peer.
        tracker.note_dial("peer-a", 1_240, false);
        assert_eq!(tracker.leg_count("peer-a"), 2);
        assert!(!tracker.note_close("peer-a"));
        assert!(tracker.is_connected("peer-a"));

        // Last leg closing signals rediscovery.
        assert!(tracker.note_close("peer-a"));
        assert!(!tracker.is_connected("peer-a"));

        // A close for an unknown peer still signals rediscovery (the
        // pre-tracker behaviour for late close notices).
        assert!(tracker.note_close("peer-never-seen"));
    }

    #[test]
    fn relay_path_claims_take_paths_in_order_then_stop() {
        let mut claims = RelayPathClaims::default();
        assert_eq!(claims.claim("consumer-a", &[0, 1], 1_000), Some(0));
        assert_eq!(claims.claim("consumer-a", &[0, 1], 1_000), Some(1));
        assert_eq!(claims.claim("consumer-a", &[0, 1], 1_000), None);
        assert_eq!(claims.consumer_count(), 1);
        assert!(claims.has_consumer("consumer-a"));
    }

    #[test]
    fn relay_path_claims_newer_generation_takes_over_older_releases_cleanly() {
        let mut claims = RelayPathClaims::default();
        assert_eq!(claims.claim("consumer-a", &[0, 1], 1_000), Some(0));
        // Same generation cannot take over its own claim.
        assert_eq!(claims.claim("consumer-a", &[0, 1], 1_000), Some(1));
        assert_eq!(claims.claim("consumer-a", &[0, 1], 1_000), None);
        // Renewal generation takes over path 0; the old leg's release
        // is then a no-op because the expiry no longer matches.
        assert_eq!(claims.claim("consumer-a", &[0, 1], 1_300), Some(0));
        claims.release("consumer-a", 0, 1_000);
        assert_eq!(claims.claim("consumer-a", &[0, 1], 1_300), Some(1));
        assert_eq!(claims.claim("consumer-a", &[0, 1], 1_300), None);
        // Releasing the newer legs empties the consumer entry, so the
        // consumer count (the provider's cap) stays exact.
        claims.release("consumer-a", 0, 1_300);
        claims.release("consumer-a", 1, 1_300);
        assert_eq!(claims.consumer_count(), 0);
        assert!(!claims.has_consumer("consumer-a"));
    }

    #[test]
    fn relay_path_claims_failed_claim_creates_no_consumer_entry() {
        let mut claims = RelayPathClaims::default();
        assert_eq!(claims.claim("consumer-a", &[], 1_000), None);
        assert_eq!(claims.consumer_count(), 0);
        assert!(!claims.has_consumer("consumer-a"));
    }

    #[test]
    fn leg_tracker_generations_invalidate_stale_renewal_notices() {
        let mut tracker = PeerLegTracker::default();
        let first = tracker.note_dial("peer-a", 1_000, false);
        assert!(tracker.is_current_generation("peer-a", first));
        assert_eq!(tracker.current_expires_at("peer-a"), Some(1_000));

        // A renewal dial supersedes the first dial's schedule.
        let second = tracker.note_dial("peer-a", 1_240, false);
        assert_ne!(first, second);
        assert!(!tracker.is_current_generation("peer-a", first));
        assert!(tracker.is_current_generation("peer-a", second));
        assert_eq!(tracker.current_generation("peer-a"), Some(second));
        assert_eq!(tracker.current_expires_at("peer-a"), Some(1_240));
    }

    #[test]
    fn renewal_delay_fires_one_lead_before_expiry() {
        let now = 10_000;
        let expires_at = now + 300;
        assert_eq!(
            renewal_delay(expires_at, now),
            std::time::Duration::from_secs(300 - PEER_RELAY_RENEWAL_LEAD_SECS)
        );
        // Inside the lead window the floor applies, so renewal is
        // attempted promptly instead of after expiry.
        assert_eq!(
            renewal_delay(now + 30, now),
            PEER_RELAY_RENEWAL_MIN_DELAY
        );
        assert_eq!(
            renewal_delay(now - 5, now),
            PEER_RELAY_RENEWAL_MIN_DELAY
        );
    }

    #[test]
    fn discovered_peers_ignore_self_and_other_servers() {
        let advertisement = PeerShareAdvertisement {
            version: 1,
            device_public_key: "peer-a".to_owned(),
            server_public_key: "server-a".to_owned(),
            instance_nonce: "nonce-1".to_owned(),
            endpoint: "192.168.1.20:54443".to_owned(),
            endpoints: vec!["192.168.1.20:54443".to_owned()],
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            capabilities: vec!["relay".to_owned(), "quic".to_owned()],
        };
        assert!(should_accept_discovered_peer(
            &advertisement,
            "server-a",
            "self"
        ));
        assert!(!should_accept_discovered_peer(
            &advertisement,
            "server-b",
            "self"
        ));
        assert!(!should_accept_discovered_peer(
            &advertisement,
            "server-a",
            "peer-a"
        ));
    }

    fn sample_advertisement(nonce: &str) -> PeerShareAdvertisement {
        PeerShareAdvertisement {
            version: 1,
            device_public_key: "peer-a".to_owned(),
            server_public_key: "server-a".to_owned(),
            instance_nonce: nonce.to_owned(),
            endpoint: "192.168.1.20:54443".to_owned(),
            endpoints: vec!["192.168.1.20:54443".to_owned()],
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            capabilities: vec!["relay".to_owned(), "quic".to_owned()],
        }
    }

    #[test]
    fn redial_queue_dedupes_pending_peer() {
        let mut queue = RedialQueue::default();
        let advertisement = sample_advertisement("nonce-1");
        queue.enqueue(advertisement.clone());
        queue.enqueue(advertisement.clone());
        assert_eq!(queue.pop(), Some(advertisement));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn redial_queue_exhausts_attempts_then_allows_fresh_enqueue() {
        let mut queue = RedialQueue::default();
        let advertisement = sample_advertisement("nonce-1");
        queue.enqueue(advertisement.clone());
        // Each pop + failure consumes one attempt; after
        // PEER_REDISCOVERY_MAX_ATTEMPTS failures nothing is re-queued.
        for _ in 0..PEER_REDISCOVERY_MAX_ATTEMPTS {
            let popped = queue.pop().expect("a redial should be pending");
            queue.requeue_failed(&popped);
        }
        assert_eq!(queue.pop(), None);
        // A later path close can still start a fresh cycle.
        queue.enqueue(advertisement.clone());
        assert_eq!(queue.pop(), Some(advertisement));
    }

    #[test]
    fn redial_queue_forget_clears_attempt_budget() {
        let mut queue = RedialQueue::default();
        let advertisement = sample_advertisement("nonce-1");
        let peer_id = peer_share_peer_id(&advertisement);
        queue.enqueue(advertisement.clone());
        let popped = queue.pop().expect("a redial should be pending");
        queue.forget(&peer_id);
        // Requeueing after forget is a no-op: the peer connected again,
        // so its stale attempt budget must not resurrect a redial.
        queue.requeue_failed(&popped);
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn introduction_expiry_gate() {
        let claims = bonded_core::peer_share::PeerShareIntroductionClaims {
            consumer_device_public_key: "consumer".to_owned(),
            provider_device_public_key: "provider".to_owned(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            expires_at: 0,
            direction: "forward".to_owned(),
            consumer_endpoints: Vec::new(),
        };
        let mut introduction = SignedPeerShareIntroduction {
            introduction: claims,
            server_signature: "signature".to_owned(),
        };
        // expires_at = 0 is long past: the provider must abandon the relay
        // instead of re-registering with this introduction.
        assert!(introduction_expired(&introduction));

        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs()
            + 300;
        introduction.introduction.expires_at = future;
        assert!(!introduction_expired(&introduction));
    }

    #[test]
    fn introduction_request_is_signed_with_consumer_key() {
        let consumer = DeviceKeypair::generate();
        let advertisement = PeerShareAdvertisement {
            version: 1,
            device_public_key: "provider".to_owned(),
            server_public_key: "server-a".to_owned(),
            instance_nonce: "nonce-1".to_owned(),
            endpoint: "192.168.1.20:54443".to_owned(),
            endpoints: vec!["192.168.1.20:54443".to_owned()],
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            capabilities: vec!["relay".to_owned(), "quic".to_owned()],
        };

        // No dial-back: the request is exactly the pre-4.56 shape —
        // flag off, no endpoints, no listener fingerprint — and the
        // signature still verifies over the unchanged six-field
        // payload, so an old server accepts it.
        let request = build_peer_introduction_request(&consumer, &advertisement, None)
            .expect("request should build");
        assert!(!request.dial_back);
        assert!(request.consumer_endpoints.is_empty());
        assert!(request.consumer_listener_cert_fingerprint.is_empty());
        verify_signature(
            &consumer.public_key_b64,
            &request
                .signed_payload()
                .expect("request payload should serialize"),
            &request.consumer_signature,
        )
        .expect("request signature should verify");
    }

    #[test]
    fn introduction_request_carries_dial_back_flag_and_endpoints() {
        let consumer = DeviceKeypair::generate();
        let advertisement = PeerShareAdvertisement {
            version: 1,
            device_public_key: "provider".to_owned(),
            server_public_key: "server-a".to_owned(),
            instance_nonce: "nonce-1".to_owned(),
            endpoint: "192.168.1.20:54443".to_owned(),
            endpoints: vec!["192.168.1.20:54443".to_owned()],
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            capabilities: vec!["relay".to_owned(), "quic".to_owned()],
        };
        let dial_back = DialBackParams {
            consumer_endpoints: vec![
                "192.168.43.10:54443".to_owned(),
                "10.0.0.5:54443".to_owned(),
            ],
            consumer_listener_cert_fingerprint: "sha256:consumer-listener".to_owned(),
        };

        let request =
            build_peer_introduction_request(&consumer, &advertisement, Some(&dial_back))
                .expect("request should build");
        assert!(request.dial_back);
        assert_eq!(
            request.consumer_endpoints,
            vec![
                "192.168.43.10:54443".to_owned(),
                "10.0.0.5:54443".to_owned(),
            ]
        );
        assert_eq!(
            request.consumer_listener_cert_fingerprint,
            "sha256:consumer-listener"
        );
        // The dial-back fields round-trip through JSON (the server
        // reads them from the request body) while the signature
        // still covers only the six core fields.
        let parsed: PeerShareIntroductionRequest = serde_json::from_str(
            &serde_json::to_string(&request).expect("request should serialize"),
        )
        .expect("request should parse");
        assert_eq!(parsed, request);
        verify_signature(
            &consumer.public_key_b64,
            &request
                .signed_payload()
                .expect("request payload should serialize"),
            &request.consumer_signature,
        )
        .expect("request signature should verify");
    }

    #[test]
    fn advertise_ips_uses_explicit_override() {
        // An explicit advertise pin wins over enumeration (empty
        // interfaces still resolve) — the pinned address itself must
        // be advertisable; an unadvertisable pin is ignored instead
        // (see advertise_ips_ignores_unadvertisable_explicit_ip_pin),
        // so the override here pins a LAN address.
        let ips = resolve_advertise_ips(
            "192.168.1.99",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 54443),
            &[],
            &Vec::<NetworkInterface>::new(),
            "bonded0",
        )
        .expect("override should parse");
        assert_eq!(
            ips,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99))]
        );
    }

    #[test]
    fn advertise_ips_pinned_bind_advertises_only_itself() {
        // A pinned bind address listens on that address only, so the
        // list is a single element holding it — even when other
        // interfaces exist.
        let interfaces = vec![test_interface(
            "wlan0",
            Ipv4Addr::new(192, 168, 1, 20),
        )];
        let ips = resolve_advertise_ips(
            "",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 54443),
            &[],
            &interfaces,
            "bonded0",
        )
        .expect("pinned bind should resolve");
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))]);
    }

    #[test]
    fn advertisable_ips_excludes_public_and_tunnel() {
        // The hotspot failure mode: the provider's public cellular
        // address (rmnet) and the VPN tunnel address (10.8.0.2,
        // identical on every client) must never be advertised — a LAN
        // peer cannot dial either. Only the Wi-Fi address survives.
        let pairs: Vec<(&str, IpAddr)> = vec![
            ("rmnet_data0", IpAddr::V4(Ipv4Addr::new(100, 64, 1, 2))),
            ("wlan0", IpAddr::V4(Ipv4Addr::new(192, 168, 43, 1))),
            ("tun0", IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
            ("bonded0", IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
            ("lo", IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        assert_eq!(
            advertisable_ips_from_pairs(&pairs, "bonded0"),
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 43, 1))]
        );
    }

    #[test]
    fn advertisable_ips_excludes_v4_rmnet1_public_cellular_address() {
        // The 6a regression: its cellular interface is named
        // `v4-rmnet1` (not a `rmnet` prefix), so the old
        // interface-name exclusion missed it and its public address
        // 192.0.0.4 became the primary advertised endpoint. The
        // IP-block filter drops it regardless of the name, while the
        // Wi-Fi, hotspot, and link-local addresses survive.
        let pairs: Vec<(&str, IpAddr)> = vec![
            ("v4-rmnet1", IpAddr::V4(Ipv4Addr::new(192, 0, 0, 4))),
            ("wlan0", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140))),
            ("ap_br_wlan2", IpAddr::V4(Ipv4Addr::new(172, 20, 72, 22))),
            ("eth0", IpAddr::V4(Ipv4Addr::new(169, 254, 1, 2))),
            ("tun0", IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
        ];
        assert_eq!(
            advertisable_ips_from_pairs(&pairs, "bonded0"),
            vec![
                IpAddr::V4(Ipv4Addr::new(169, 254, 1, 2)),
                IpAddr::V4(Ipv4Addr::new(172, 20, 72, 22)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140)),
            ]
        );
    }

    #[test]
    fn tunnel_interface_matches_name_or_tunnel_address() {
        // Linux tun device by configured name, Android VpnService
        // tun0 by prefix, and the known tunnel addresses regardless
        // of the interface name.
        assert!(is_tunnel_interface(
            "bonded0",
            "bonded0",
            &IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))
        ));
        assert!(is_tunnel_interface(
            "tun0",
            "bonded0",
            &IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))
        ));
        assert!(is_tunnel_interface(
            "eth0",
            "bonded0",
            &IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))
        ));
        assert!(!is_tunnel_interface(
            "wlan0",
            "bonded0",
            &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))
        ));
    }

    #[test]
    fn advertise_ips_returns_all_private_primary_first() {
        // A phone with two LAN addresses advertises both, primary
        // first: the address sharing a /24 with a live path bind
        // wins the primary slot (the existing preference), and the
        // other LAN address is still listed as a fallback.
        let interfaces = vec![
            test_interface("wlan0", Ipv4Addr::new(192, 168, 1, 20)),
            test_interface("eth0", Ipv4Addr::new(10, 0, 0, 5)),
            test_interface("rmnet_data0", Ipv4Addr::new(100, 64, 1, 2)),
        ];
        let binds = vec!["10.0.0.5".to_owned()];
        let ips = resolve_advertise_ips(
            "",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 54443),
            &binds,
            &interfaces,
            "bonded0",
        )
        .expect("list should resolve");
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            ]
        );
    }

    #[test]
    fn advertise_ips_errors_when_only_public_and_tunnel_exist() {
        // A hotspot-only phone with no LAN address at all (public +
        // tunnel only) has nothing dialable to advertise: error, so
        // the watcher keeps the previous advertisement instead of
        // publishing an unreachable one.
        let interfaces = vec![
            test_interface("rmnet_data0", Ipv4Addr::new(100, 64, 1, 2)),
            test_interface("tun0", Ipv4Addr::new(10, 8, 0, 2)),
        ];
        let err = resolve_advertise_ips(
            "",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 54443),
            &[],
            &interfaces,
            "bonded0",
        )
        .expect_err("no dialable address should fail");
        assert!(err.to_string().contains("non-loopback"));
    }

    #[test]
    fn advertise_ips_ignores_unadvertisable_explicit_ip_pin() {
        // A pinned peer_share_advertise_ip naming a public address
        // (e.g. a cellular 192.0.0.4 recorded in the paired-server
        // record before 4.59) must not bypass the allow-list: the pin
        // is ignored and the filtered enumeration decides instead.
        let interfaces = vec![test_interface("wlan0", Ipv4Addr::new(192, 168, 1, 140))];
        let ips = resolve_advertise_ips(
            "192.0.0.4",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 54443),
            &[],
            &interfaces,
            "bonded0",
        )
        .expect("list should resolve from enumeration");
        assert_eq!(
            ips,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140))]
        );
    }

    #[test]
    fn advertise_ips_ignores_unadvertisable_pinned_bind() {
        // Same bypass through a pinned peer_share_bind_address: a
        // public bind address is ignored for advertisement and the
        // filtered enumeration decides instead.
        let interfaces = vec![test_interface("wlan0", Ipv4Addr::new(192, 168, 1, 140))];
        let ips = resolve_advertise_ips(
            "",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 4)), 54443),
            &[],
            &interfaces,
            "bonded0",
        )
        .expect("list should resolve from enumeration");
        assert_eq!(
            ips,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140))]
        );
    }

    fn test_interface(name: &str, ip: Ipv4Addr) -> NetworkInterface {
        use ipnetwork::{IpNetwork, Ipv4Network};

        NetworkInterface {
            name: name.to_owned(),
            description: String::new(),
            index: 1,
            mac: None,
            ips: vec![IpNetwork::V4(
                Ipv4Network::new(ip, 24).expect("test network should build"),
            )],
            flags: 0,
        }
    }

    #[test]
    fn advertise_ip_prefers_path_subnet_over_tunnel_address() {
        // The Android failure mode: enumeration lists the VPN tunnel
        // address (10.8.0.2, the same on every client) before the Wi-Fi
        // address. The Wi-Fi address shares a /24 with the Wi-Fi path
        // bind address and must win; otherwise the provider advertises
        // an address no peer can dial.
        let candidates = vec![
            IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140)),
        ];
        let binds = vec!["192.168.1.140".to_owned(), "192.0.0.4".to_owned()];
        assert_eq!(
            prefer_path_subnet_candidate(&candidates, &binds),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140)))
        );
    }

    #[test]
    fn advertise_ip_path_subnet_no_match_without_binds() {
        let candidates = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140))];
        assert_eq!(prefer_path_subnet_candidate(&candidates, &[]), None);
        assert_eq!(
            prefer_path_subnet_candidate(&candidates, &["203.0.113.9".to_owned()]),
            None
        );
    }
    #[test]
    fn advertise_ip_skips_link_local_ipv6_for_lan_ipv4() {
        // The phone failure mode: enumeration lists a link-local IPv6
        // address first; binding it would fail with EINVAL, so the LAN
        // IPv4 address must win.
        let candidates = vec![
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
        ];
        assert_eq!(
            select_advertise_ip(&candidates),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)))
        );
    }

    #[test]
    fn advertise_ip_prefers_link_local_ipv4_over_global_ipv6() {
        // IPv4 link-local is a valid advertised address (it is in the
        // IP-block allow-list and binds like any IPv4 address), while
        // a global IPv6 address is not advertised at all — so the
        // link-local IPv4 wins as the first bindable IPv4.
        let candidates = vec![
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2600, 0, 0, 0, 0, 0, 0, 5)),
        ];
        assert_eq!(
            select_advertise_ip(&candidates),
            Some(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)))
        );
    }

    #[test]
    fn advertise_ip_falls_back_when_only_link_local_exists() {
        let candidates = vec![IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 9))];
        assert_eq!(
            select_advertise_ip(&candidates),
            Some(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 9)))
        );
    }

    #[test]
    fn advertise_ip_rejects_loopback_only() {
        let candidates = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        assert_eq!(select_advertise_ip(&candidates), None);
    }

    #[test]
    fn advertise_ip_for_binds_prefers_path_subnet_over_first_bindable() {
        // Same shape as the Android failure mode, through the shared
        // selection helper the watcher re-resolves on: the tunnel
        // address sorts first in enumeration, but the Wi-Fi address
        // shares a /24 with a live path bind and must win.
        let candidates = vec![
            IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140)),
        ];
        let binds = vec!["192.168.1.140".to_owned()];
        assert_eq!(
            select_advertise_ip_for_binds(&binds, &candidates),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140)))
        );
        // Without a matching bind, the first bindable address wins.
        assert_eq!(
            select_advertise_ip_for_binds(&[], &candidates),
            Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)))
        );
    }

    fn now_plus(offset_secs: u64) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time should be after unix epoch")
            .as_secs()
            .saturating_add(offset_secs)
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

    fn dial_back_notification(
        server: &DeviceKeypair,
        consumer_key: &str,
        provider_key: &str,
        expires_at: u64,
    ) -> PeerShareDialBackNotification {
        let claims = PeerShareIntroductionClaims {
            consumer_device_public_key: consumer_key.to_owned(),
            provider_device_public_key: provider_key.to_owned(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:consumer-listener".to_owned(),
            expires_at,
            direction: "reverse".to_owned(),
            consumer_endpoints: vec!["192.168.43.10:54443".to_owned()],
        };
        PeerShareDialBackNotification {
            consumer_device_public_key: consumer_key.to_owned(),
            consumer_endpoints: vec!["192.168.43.10:54443".to_owned()],
            introduction: sign_introduction(server, claims),
        }
    }

    #[test]
    fn dial_back_plan_claims_single_path_for_reversed_leg() {
        // The hotspot case: the provider has one path, the consumer
        // cannot dial it, and the server pushes a dial-back. The
        // plan verifies, parses the consumer endpoint, and claims
        // the provider's only path for the reversed leg.
        let server = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let consumer = DeviceKeypair::generate();
        let expires_at = now_plus(300);
        let notification = dial_back_notification(
            &server,
            &consumer.public_key_b64,
            &provider.public_key_b64,
            expires_at,
        );
        let mut claims = RelayPathClaims::default();
        let plan = plan_dial_back(
            &server.public_key_b64,
            &provider.public_key_b64,
            &notification,
            &mut claims,
            &[0],
        )
        .expect("dial-back plan should succeed");
        assert_eq!(plan.consumer_key, consumer.public_key_b64);
        assert_eq!(plan.claimed_path, 0);
        assert_eq!(plan.expires_at, expires_at);
        assert_eq!(
            plan.endpoints,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 43, 10)), 54443)]
        );
    }

    #[test]
    fn dial_back_plan_drops_duplicate_leg_for_same_peer_and_path() {
        // Both sides initiating for the same (peer, path) yields
        // exactly one leg: a forward leg already holds the only
        // provider path for this consumer at the same introduction
        // expiry, so the reversed plan is dropped instead of
        // dialing a duplicate leg for that path.
        let server = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let consumer = DeviceKeypair::generate();
        let expires_at = now_plus(300);
        let notification = dial_back_notification(
            &server,
            &consumer.public_key_b64,
            &provider.public_key_b64,
            expires_at,
        );
        let mut claims = RelayPathClaims::default();
        let claimed = claims.claim(&consumer.public_key_b64, &[0], expires_at);
        assert_eq!(claimed, Some(0));
        let error = plan_dial_back(
            &server.public_key_b64,
            &provider.public_key_b64,
            &notification,
            &mut claims,
            &[0],
        )
        .expect_err("reversed plan should drop when the path is held");
        assert!(error.to_string().contains("no free provider path"));
    }

    #[test]
    fn dial_back_plan_claims_second_path_when_first_is_held() {
        // Two provider paths, one already held by a forward leg:
        // the reversed leg is complementary, not a duplicate — it
        // claims the free path, so the pair converges to full path
        // coverage instead of dropping the leg.
        let server = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let consumer = DeviceKeypair::generate();
        let expires_at = now_plus(300);
        let notification = dial_back_notification(
            &server,
            &consumer.public_key_b64,
            &provider.public_key_b64,
            expires_at,
        );
        let mut claims = RelayPathClaims::default();
        assert_eq!(
            claims.claim(&consumer.public_key_b64, &[0, 1], expires_at),
            Some(0)
        );
        let plan = plan_dial_back(
            &server.public_key_b64,
            &provider.public_key_b64,
            &notification,
            &mut claims,
            &[0, 1],
        )
        .expect("reversed plan should claim the free path");
        assert_eq!(plan.claimed_path, 1);
    }

    #[test]
    fn dial_back_plan_newer_generation_takes_over_path() {
        // The takeover rule still holds across directions: a
        // reversed leg from a NEWER introduction generation takes
        // over a path held by an older forward leg (the old leg
        // keeps its upstream until it expires; its release is a
        // no-op because the expiry no longer matches).
        let server = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let consumer = DeviceKeypair::generate();
        let mut claims = RelayPathClaims::default();
        assert_eq!(
            claims.claim(&consumer.public_key_b64, &[0], now_plus(300)),
            Some(0)
        );
        let notification = dial_back_notification(
            &server,
            &consumer.public_key_b64,
            &provider.public_key_b64,
            now_plus(600),
        );
        let plan = plan_dial_back(
            &server.public_key_b64,
            &provider.public_key_b64,
            &notification,
            &mut claims,
            &[0],
        )
        .expect("newer generation should take the path over");
        assert_eq!(plan.claimed_path, 0);
    }

    #[test]
    fn dial_back_plan_rejects_forward_introduction() {
        // A forward introduction must never produce a dial-back
        // plan: the direction check runs before any claim or dial.
        let server = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let consumer = DeviceKeypair::generate();
        let claims = PeerShareIntroductionClaims {
            consumer_device_public_key: consumer.public_key_b64.clone(),
            provider_device_public_key: provider.public_key_b64.clone(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:consumer-listener".to_owned(),
            expires_at: now_plus(300),
            direction: "forward".to_owned(),
            consumer_endpoints: Vec::new(),
        };
        let notification = PeerShareDialBackNotification {
            consumer_device_public_key: consumer.public_key_b64.clone(),
            consumer_endpoints: vec!["192.168.43.10:54443".to_owned()],
            introduction: sign_introduction(&server, claims),
        };
        let mut path_claims = RelayPathClaims::default();
        let error = plan_dial_back(
            &server.public_key_b64,
            &provider.public_key_b64,
            &notification,
            &mut path_claims,
            &[0],
        )
        .expect_err("forward introduction should fail dial-back planning");
        assert!(error.to_string().contains("not reversed"));
        // And no path was claimed for it.
        assert_eq!(
            path_claims.claim(&consumer.public_key_b64, &[0], now_plus(300)),
            Some(0)
        );
    }

    #[test]
    fn dial_back_plan_rejects_unparseable_endpoints() {
        // A reversed introduction whose consumer endpoints do not
        // parse to socket addresses is undiallable: drop it before
        // claiming a path, so the claim is never wasted. (The bad
        // endpoints are signed in, not mutated after signing —
        // mutating signed claims fails the signature check first.)
        let server = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let consumer = DeviceKeypair::generate();
        let claims = PeerShareIntroductionClaims {
            consumer_device_public_key: consumer.public_key_b64.clone(),
            provider_device_public_key: provider.public_key_b64.clone(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:consumer-listener".to_owned(),
            expires_at: now_plus(300),
            direction: "reverse".to_owned(),
            consumer_endpoints: vec!["not-an-address".to_owned()],
        };
        let notification = PeerShareDialBackNotification {
            consumer_device_public_key: consumer.public_key_b64.clone(),
            consumer_endpoints: vec!["not-an-address".to_owned()],
            introduction: sign_introduction(&server, claims),
        };
        let mut path_claims = RelayPathClaims::default();
        let error = plan_dial_back(
            &server.public_key_b64,
            &provider.public_key_b64,
            &notification,
            &mut path_claims,
            &[0],
        )
        .expect_err("undiallable endpoints should fail dial-back planning");
        assert!(error.to_string().contains("no dialable consumer endpoint"));
    }

    #[test]
    fn reversed_leg_accepted_when_peer_not_connected() {
        // The hotspot case at the consumer layer: no forward leg
        // exists for the peer, so the reversed leg is recorded and
        // its renewal generation returned.
        let mut legs = PeerLegTracker::default();
        let connected = ConnectedPeers::default();
        let generation = note_reversed_leg(&mut legs, &connected, "peer-a:nonce-1", 1_000)
            .expect("reversed leg should be accepted");
        assert_eq!(generation, 1);
        assert!(legs.is_connected("peer-a:nonce-1"));
        assert!(connected.is_connected("peer-a:nonce-1"));
    }

    #[test]
    fn reversed_leg_dropped_when_peer_already_connected() {
        // Both sides initiating for the same peer: the consumer
        // already holds a forward leg, so the reversed leg is a
        // duplicate and is dropped (the accept loop refuses it
        // first with no_path; this is the browse loop's backstop
        // for the race where the forward leg lands between the
        // accept check and the handoff).
        let mut legs = PeerLegTracker::default();
        let connected = ConnectedPeers::default();
        legs.note_dial("peer-a:nonce-1", 1_000, false);
        connected.mark_connected("peer-a:nonce-1");
        assert_eq!(
            note_reversed_leg(&mut legs, &connected, "peer-a:nonce-1", 1_000),
            None
        );
        assert_eq!(legs.leg_count("peer-a:nonce-1"), 1);
    }

    #[test]
    fn reversed_leg_accepted_again_after_last_leg_closes() {
        // Once the last leg for a peer closes, a reversed leg for
        // the same peer is a fresh leg, not a duplicate.
        let mut legs = PeerLegTracker::default();
        let connected = ConnectedPeers::default();
        assert!(note_reversed_leg(&mut legs, &connected, "peer-a:nonce-1", 1_000).is_some());
        assert!(legs.note_close("peer-a:nonce-1"));
        connected.mark_disconnected("peer-a:nonce-1");
        assert!(note_reversed_leg(&mut legs, &connected, "peer-a:nonce-1", 1_300).is_some());
        assert!(legs.is_connected("peer-a:nonce-1"));
    }

    #[test]
    fn leg_tracker_records_direction_of_newest_leg() {
        // Renewal direction selection (4.67): the tracker remembers
        // how the peer's NEWEST leg was established, so a reversed
        // leg renews in reverse and a forward leg renews forward.
        let mut tracker = PeerLegTracker::default();
        assert!(!tracker.is_reversed("peer-a"));

        tracker.note_dial("peer-a", 1_000, false);
        assert!(!tracker.is_reversed("peer-a"));

        // A reversed leg supersedes the forward one (renewal
        // overlap): the newest leg governs the next renewal.
        tracker.note_dial("peer-a", 1_240, true);
        assert!(tracker.is_reversed("peer-a"));

        // And a later forward leg flips it back.
        tracker.note_dial("peer-a", 1_480, false);
        assert!(!tracker.is_reversed("peer-a"));
    }

    #[test]
    fn reversed_leg_accepted_as_renewal_replacement_while_connected() {
        // Reverse-aware renewal (4.67): the consumer holds a live
        // leg for the peer and a reversed renewal is pending, so the
        // incoming reversed leg is the replacement, not a duplicate
        // — it is accepted with a fresh renewal generation, the
        // pending mark is cleared, and the leg count briefly holds
        // both legs (make-before-break); the old leg's close drops
        // it back to one.
        let mut legs = PeerLegTracker::default();
        let connected = ConnectedPeers::default();
        legs.note_dial("peer-a:nonce-1", 1_000, true);
        connected.mark_connected("peer-a:nonce-1");
        assert!(legs.is_reversed("peer-a:nonce-1"));

        connected.mark_reversed_renewal_pending("peer-a:nonce-1");
        let generation =
            note_reversed_leg(&mut legs, &connected, "peer-a:nonce-1", 1_300)
                .expect("renewal replacement should be accepted");
        assert_eq!(generation, 2);
        assert_eq!(legs.leg_count("peer-a:nonce-1"), 2);
        assert!(legs.is_reversed("peer-a:nonce-1"));
        assert!(!connected.is_reversed_renewal_pending("peer-a:nonce-1"));

        // The old leg closing leaves the replacement standing.
        assert!(!legs.note_close("peer-a:nonce-1"));
        assert!(legs.is_connected("peer-a:nonce-1"));
        assert_eq!(legs.leg_count("peer-a:nonce-1"), 1);

        // Without a pending renewal the same situation is still a
        // duplicate: the next reversed leg is dropped.
        assert_eq!(
            note_reversed_leg(&mut legs, &connected, "peer-a:nonce-1", 1_600),
            None
        );
        assert_eq!(legs.leg_count("peer-a:nonce-1"), 1);
    }

    #[test]
    fn dial_back_frame_intercepted_before_data_path() {
        // The session workers call forward_dial_back_frame on every
        // inbound frame before the PONG check and the data path:
        // a dial-back frame is forwarded to the handler (the
        // notification round-trips through the channel), a data
        // frame is untouched, and a frame with the wrong flag is
        // untouched.
        let server = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let consumer = DeviceKeypair::generate();
        let notification = dial_back_notification(
            &server,
            &consumer.public_key_b64,
            &provider.public_key_b64,
            now_plus(300),
        );
        let frame = notification
            .clone()
            .into_control_frame()
            .expect("notification should serialize");
        // The control frame's header is rewritten by the server push
        // (session connection id + sequence u64::MAX); the helper
        // only reads the flag, so rebuild it as the push sends it.
        let pushed = SessionFrame {
            header: SessionHeader {
                connection_id: 7,
                sequence: u64::MAX,
                flags: FLAG_PEER_DIAL_BACK,
            },
            payload: frame.payload,
        };
        let (tx, mut rx) =
            tokio::sync::mpsc::unbounded_channel::<PeerShareDialBackNotification>();
        assert!(forward_dial_back_frame(&pushed, &Some(tx)));
        let received = rx.try_recv().expect("notification should be forwarded");
        assert_eq!(received, notification);

        // A plain data frame passes through untouched.
        let data = SessionFrame {
            header: SessionHeader {
                connection_id: 7,
                sequence: 1,
                flags: 0,
            },
            payload: Bytes::from_static(b"not a notification"),
        };
        assert!(!forward_dial_back_frame(&data, &None));
        assert!(rx.try_recv().is_err());

        // A dial-back flag with an unparseable payload is still
        // intercepted (dropped, never fed to the data path).
        let garbage = SessionFrame {
            header: SessionHeader {
                connection_id: 7,
                sequence: u64::MAX,
                flags: FLAG_PEER_DIAL_BACK,
            },
            payload: Bytes::from_static(b"{not json"),
        };
        assert!(forward_dial_back_frame(&garbage, &None));
    }


    /// Fresh temp dir per listener-cert test, unique across the
    /// parallel test threads in one process.
    fn listener_cert_test_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bonded-listener-cert-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir should create");
        dir
    }

    fn listener_cert_test_config(dir: &std::path::Path) -> ClientConfig {
        let mut config = ClientConfig::default();
        config.client.private_key_path = dir.join("bonded-device-key.pem").display().to_string();
        config
    }

    #[test]
    fn listener_cert_fingerprint_is_stable_across_rebuilds() {
        // 4.68: the whole point of persisting the listener cert is
        // that a second runtime start presents the same fingerprint
        // — an introduction minted before a restart still verifies
        // after it. Two loads from the same storage dir must return
        // byte-identical cert and key.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = listener_cert_test_dir("stable");
        let config = listener_cert_test_config(&dir);
        let (cert_a, key_a) =
            load_or_create_peer_listener_cert(&config).expect("first load should mint a pair");
        let (cert_b, key_b) =
            load_or_create_peer_listener_cert(&config).expect("second load should reuse it");
        assert_eq!(cert_a, cert_b);
        assert_eq!(key_a, key_b);
        assert_eq!(
            crate::cert_proof::compute_fingerprint(&cert_a),
            crate::cert_proof::compute_fingerprint(&cert_b),
        );
        assert!(dir.join("peer-listener-cert.der").exists());
        assert!(dir.join("peer-listener-key.der").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn listener_cert_regenerates_from_corrupt_key_and_stabilises() {
        // A truncated/corrupt key file must not wedge the runtime:
        // the loader mints a fresh pair, and the fresh pair is then
        // stable across loads.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = listener_cert_test_dir("corrupt");
        let config = listener_cert_test_config(&dir);
        let (cert_a, _) =
            load_or_create_peer_listener_cert(&config).expect("first load should mint a pair");
        let fingerprint_a = crate::cert_proof::compute_fingerprint(&cert_a);
        std::fs::write(dir.join("peer-listener-key.der"), b"not a der key")
            .expect("corrupt key should write");
        let (cert_b, _) =
            load_or_create_peer_listener_cert(&config).expect("corrupt key should regenerate");
        assert_ne!(
            crate::cert_proof::compute_fingerprint(&cert_b),
            fingerprint_a,
            "a regenerated pair must not reuse the corrupt pair's fingerprint"
        );
        let (cert_c, _) =
            load_or_create_peer_listener_cert(&config).expect("regenerated pair should load");
        assert_eq!(cert_b, cert_c);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn listener_cert_regenerates_when_cert_file_is_missing() {
        // Half a pair (key present, cert deleted) is not a usable
        // pair: the loader mints a fresh one and the fresh one is
        // stable afterwards.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = listener_cert_test_dir("missing-cert");
        let config = listener_cert_test_config(&dir);
        load_or_create_peer_listener_cert(&config).expect("first load should mint a pair");
        std::fs::remove_file(dir.join("peer-listener-cert.der")).expect("cert file should delete");
        let (cert_b, _) =
            load_or_create_peer_listener_cert(&config).expect("missing cert should regenerate");
        let (cert_c, _) =
            load_or_create_peer_listener_cert(&config).expect("regenerated pair should load");
        assert_eq!(cert_b, cert_c);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_listener_bind_retry_delay_backs_off_and_caps() {
        // 100 ms, doubling, capped at 500 ms (4.69).
        assert_eq!(
            peer_listener_bind_retry_delay(0),
            Duration::from_millis(100)
        );
        assert_eq!(
            peer_listener_bind_retry_delay(1),
            Duration::from_millis(200)
        );
        assert_eq!(
            peer_listener_bind_retry_delay(2),
            Duration::from_millis(400)
        );
        assert_eq!(
            peer_listener_bind_retry_delay(3),
            Duration::from_millis(500)
        );
        assert_eq!(
            peer_listener_bind_retry_delay(10),
            Duration::from_millis(500)
        );
    }

    #[tokio::test]
    async fn listener_bind_retries_addr_in_use_then_succeeds() {
        // The 4.69 race: a second worker binds while the first still
        // holds the port, then the first releases it. No real socket
        // is involved — the closure stands in for the bind — so this
        // runs in the UDP-blocked sandbox.
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let result = retry_bind_on_addr_in_use(
            move || {
                let n = calls_clone.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err(std::io::Error::from(std::io::ErrorKind::AddrInUse))
                } else {
                    Ok(42u32)
                }
            },
            |_| Duration::from_millis(0),
        )
        .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn listener_bind_gives_up_after_max_attempts() {
        // A genuinely duplicate session (first worker still alive)
        // never releases the port: the retry is bounded, not a spin.
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let result = retry_bind_on_addr_in_use(
            move || {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Err::<u32, _>(std::io::Error::from(std::io::ErrorKind::AddrInUse))
            },
            |_| Duration::from_millis(0),
        )
        .await;
        let err = result.expect_err("exhausted retry should fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            PEER_LISTENER_BIND_MAX_ATTEMPTS
        );
    }

    #[tokio::test]
    async fn listener_bind_does_not_retry_other_errors() {
        // Only AddrInUse is transient: a permission failure returns
        // on the first attempt instead of burning the budget.
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let result = retry_bind_on_addr_in_use(
            move || {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                Err::<u32, _>(std::io::Error::from(
                    std::io::ErrorKind::PermissionDenied,
                ))
            },
            |_| Duration::from_millis(0),
        )
        .await;
        let err = result.expect_err("permission failure should fail");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

    }
}
