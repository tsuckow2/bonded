use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bonded_core::auth::{create_auth_challenge, sign_bytes, DeviceKeypair};
use bonded_core::config::{PeerShareMode, SocketProtectFn};
use bonded_core::peer_share::{
    PeerShareAdvertisement, PeerShareIntroductionRequest, SignedPeerShareIntroduction,
};
use pnet_datalink::NetworkInterface;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::cert_proof;
use crate::peer_discovery::{PeerShareAdvertiser, PeerShareBrowser};
use crate::peer_listener::{
    accept_peer_relay, connect_peer_relay, register_peer_relay_upstream,
    relay_peer_frames_rate_limited, AcceptedPeerRelay, PeerListenerIdentity, PeerRelayDial,
    PeerRelayRateLimiter,
};
use crate::{
    bootstrap_scheme_candidates, enumerate_interfaces, establish_single_transport_path,
    establish_transport_paths, load_or_create_device_keypair, request_bootstrap_json,
    ClientConfig, ClientTransport, SinglePathResult,
};

pub struct PeerShareRuntime {
    tasks: Vec<JoinHandle<()>>,
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
}

impl PeerLegTracker {
    fn is_connected(&self, peer_id: &str) -> bool {
        self.legs.get(peer_id).copied().unwrap_or(0) > 0
    }

    fn leg_count(&self, peer_id: &str) -> usize {
        self.legs.get(peer_id).copied().unwrap_or(0)
    }

    /// Record a freshly dialed leg; returns its renewal generation.
    fn note_dial(&mut self, peer_id: &str, expires_at: u64) -> u64 {
        *self.legs.entry(peer_id.to_owned()).or_default() += 1;
        self.expires_at.insert(peer_id.to_owned(), expires_at);
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

impl Drop for PeerShareRuntime {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
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
    path_source: ProviderPathSource,
    config: ClientConfig,
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
        } = match accept_peer_relay(&server_key, &identity, connection).await {
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
        let _in_flight = active_relays.fetch_add(1, Ordering::SeqCst);
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

        let relay_config = config.clone();
        let relay_logger = logger.clone();
        let relay_claims = path_claims.clone();
        let relay_path_source = path_source.clone();
        let relay_count = active_relays.clone();
        tokio::spawn(async move {
            let mut peer = peer;
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
                    match relay_peer_frames_rate_limited(&mut peer, &mut upstream, &mut limiter).await {
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
        });
    }
}

/// How often the advertise watcher re-resolves the provider's advertise
/// IP. Path changes are rare; a few seconds of staleness is covered by
/// the consumer's redial/renewal recovery.
const PEER_ADVERTISE_POLL: Duration = Duration::from_secs(5);

/// One accept loop per bound endpoint, owned by the advertise watcher.
/// Dropping the set aborts every loop it holds, so aborting the watcher
/// (e.g. on runtime shutdown) tears down all provider endpoints.
struct AcceptLoopSet {
    loops: Vec<(IpAddr, JoinHandle<()>)>,
}

impl AcceptLoopSet {
    fn new(loops: Vec<(IpAddr, JoinHandle<()>)>) -> Self {
        Self { loops }
    }

    fn push(&mut self, ip: IpAddr, handle: JoinHandle<()>) {
        self.loops.push((ip, handle));
    }

    /// Abort loops whose IP is neither the newly advertised one nor
    /// still assigned to an interface. Loops on surviving addresses
    /// keep serving their existing legs undisturbed.
    fn prune(&mut self, current_ip: IpAddr, live_ips: &HashSet<IpAddr>) {
        let mut kept = Vec::new();
        for (ip, handle) in self.loops.drain(..) {
            if keep_accept_loop(ip, current_ip, live_ips) {
                kept.push((ip, handle));
            } else {
                handle.abort();
            }
        }
        self.loops = kept;
    }
}

impl Drop for AcceptLoopSet {
    fn drop(&mut self) {
        for (_, handle) in self.loops.drain(..) {
            handle.abort();
        }
    }
}

/// Whether an accept loop survives a re-bind: its IP is the newly
/// advertised one, or it is still assigned to an interface.
fn keep_accept_loop(ip: IpAddr, current_ip: IpAddr, live_ips: &HashSet<IpAddr>) -> bool {
    ip == current_ip || live_ips.contains(&ip)
}

/// Watch the provider's path set and interfaces; when the advertise IP
/// changes, bind a new listener on the new address (reusing the original
/// certificate, so the fingerprint consumers pin never changes) and
/// re-register the mDNS advertisement under the same instance nonce, so
/// consumers keep treating this provider as the same peer. The previous
/// advertisement is shut down before the new one registers (the same
/// instance name would probe-conflict); if the new registration fails,
/// the previous advertisement is restored and the next poll retries.
/// A failed re-bind keeps the old endpoint serving.
#[allow(clippy::too_many_arguments)]
async fn run_advertise_watcher(
    config: ClientConfig,
    path_source: ProviderPathSource,
    identity: PeerListenerIdentity,
    logger: Option<PeerShareEventLogger>,
    max_consumers: usize,
    bandwidth_kbps: u64,
    path_claims: Arc<std::sync::Mutex<RelayPathClaims>>,
    active_relays: Arc<AtomicUsize>,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    port: u16,
    initial_ip: IpAddr,
    initial_advertisement: PeerShareAdvertisement,
    initial_advertiser: PeerShareAdvertiser,
    initial_loops: Vec<(IpAddr, JoinHandle<()>)>,
) {
    let mut loops = AcceptLoopSet::new(initial_loops);
    let mut current_ip = initial_ip;
    let mut current_advertisement = initial_advertisement;
    let mut advertiser: Option<PeerShareAdvertiser> = Some(initial_advertiser);
    loop {
        sleep(PEER_ADVERTISE_POLL).await;
        let interfaces = enumerate_interfaces();
        let Some(desired) = desired_advertise_ip(&config, &path_source, &interfaces) else {
            continue;
        };
        if desired == current_ip {
            continue;
        }
        // Bind first: if the new address cannot be bound, keep serving
        // the old one and retry on the next poll.
        let new_endpoint = match bind_peer_listener_endpoint(
            cert_der.clone(),
            key_der.clone(),
            SocketAddr::new(desired, port),
            config.socket_protect.as_ref(),
        ) {
            Ok(endpoint) => endpoint,
            Err(err) => {
                warn!(error = %err, desired = %desired, "peer-share re-bind failed, keeping old endpoint");
                continue;
            }
        };
        let mut new_advertisement = current_advertisement.clone();
        new_advertisement.endpoint = SocketAddr::new(desired, port).to_string();
        if let Some(old) = advertiser.take() {
            let _ = old.shutdown();
        }
        match PeerShareAdvertiser::start(&new_advertisement) {
            Ok(new_adv) => {
                advertiser = Some(new_adv);
                let handle = tokio::spawn(run_peer_accept_loop(
                    new_endpoint,
                    config.client.server_public_key.clone(),
                    identity.clone(),
                    logger.clone(),
                    max_consumers,
                    bandwidth_kbps,
                    path_claims.clone(),
                    active_relays.clone(),
                    path_source.clone(),
                    config.clone(),
                ));
                loops.push(desired, handle);
                let live_ips: HashSet<IpAddr> = interfaces
                    .iter()
                    .flat_map(|interface| interface.ips.iter())
                    .map(|network| network.ip())
                    .collect();
                loops.prune(desired, &live_ips);
                current_ip = desired;
                current_advertisement = new_advertisement;
                info!(endpoint = %current_advertisement.endpoint, "peer-share re-advertised on new path");
                emit_peer_share_event(
                    logger.as_ref(),
                    format!("re-advertised endpoint={}", current_advertisement.endpoint),
                );
            }
            Err(err) => {
                warn!(error = %err, desired = %desired, "peer-share re-advertise failed, restoring previous advertisement");
                match PeerShareAdvertiser::start(&current_advertisement) {
                    Ok(old_adv) => advertiser = Some(old_adv),
                    Err(err) => warn!(error = %err, "peer-share previous advertisement restore failed; next poll retries"),
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
) -> anyhow::Result<PeerShareRuntime> {
    let private_key_path = crate::expand_home_path(&config.client.private_key_path);
    let public_key_path = crate::expand_home_path(&config.client.public_key_path);
    let device_keypair = load_or_create_device_keypair(&private_key_path, &public_key_path)?;
    let mode = config.client.peer_share_mode;
    let is_provider = mode == PeerShareMode::Both || mode == PeerShareMode::ProviderOnly;
    let is_consumer = mode == PeerShareMode::Both || mode == PeerShareMode::ConsumerOnly;

    // Provider side: QUIC listener + mDNS advertiser + accept loops.
    // The listener certificate/key, advertise IP, and port are carried
    // alongside so the advertise watcher can re-bind the same identity
    // on a new address when the provider's paths change.
    let (
        listener_endpoint,
        listener_identity,
        advertisement,
        advertiser,
        listener_cert_der,
        listener_key_der,
        listener_advertise_ip,
        listener_port,
    ) = if is_provider {
        let (endpoint, identity, adv, cert_der, key_der, advertise_ip, port) =
            build_listener_runtime(config, &device_keypair, provider_paths.as_ref())?;
        let advertiser = PeerShareAdvertiser::start(&adv)?;
        (
            Some(endpoint),
            Some(identity),
            Some(adv),
            Some(advertiser),
            Some(cert_der),
            Some(key_der),
            Some(advertise_ip),
            Some(port),
        )
    } else {
        (None, None, None, None, None, None, None, None)
    };
    // Consumer side: mDNS browser
    let browser = if is_consumer {
        Some(PeerShareBrowser::start()?)
    } else {
        None
    };

    if let (Some(adv), Some(identity)) = (advertisement.as_ref(), listener_identity.as_ref()) {
        info!(
            endpoint = %adv.endpoint,
            nonce = %identity.instance_nonce,
            "peer-share runtime started"
        );
        emit_peer_share_event(
            event_logger.as_ref(),
            format!(
                "runtime started endpoint={} nonce={}",
                adv.endpoint, identity.instance_nonce
            ),
        );
    } else {
        info!("peer-share runtime started (consumer-only mode)");
        emit_peer_share_event(
            event_logger.as_ref(),
            "runtime started (consumer-only mode)".to_owned(),
        );
    }

    // Provider side: accept loops + advertise watcher. One accept loop
    // runs per bound endpoint; the watcher spawns a new loop on re-bind
    // and aborts loops whose IP is no longer assigned, so a path change
    // never disturbs legs on a surviving endpoint. The initial loop is
    // handed to the watcher, which owns the loop set; dropping the
    // runtime aborts the watcher, whose Drop aborts the loops.
    let watcher_task = if is_provider {
        let accept_server_key = config.client.server_public_key.clone();
        let accept_identity = listener_identity.clone().expect("provider mode requires identity");
        let accept_logger = event_logger.clone();
        let accept_max_consumers = config.client.peer_share_max_consumers.max(1) as usize;
        let accept_bandwidth_kbps = config.client.peer_share_relay_bandwidth_kbps;
        let active_relays = Arc::new(AtomicUsize::new(0));
        // One claim set for the whole provider (shared with the relay
        // tasks for release on end). The provider-path source falls back
        // to the session-start config bind addresses when no live map
        // was supplied (non-FFI clients).
        let path_claims = Arc::new(std::sync::Mutex::new(RelayPathClaims::default()));
        let path_source = provider_paths.unwrap_or_else(|| {
            ProviderPathSource::Config(config.client.path_bind_addresses.clone())
        });
        let initial_ip = listener_advertise_ip.expect("provider mode requires advertise IP");
        let initial_endpoint = listener_endpoint
            .clone()
            .expect("provider mode requires listener");
        let initial_handle = tokio::spawn(run_peer_accept_loop(
            initial_endpoint,
            accept_server_key,
            accept_identity.clone(),
            accept_logger.clone(),
            accept_max_consumers,
            accept_bandwidth_kbps,
            path_claims.clone(),
            active_relays.clone(),
            path_source.clone(),
            config.clone(),
        ));
        Some(tokio::spawn(run_advertise_watcher(
            config.clone(),
            path_source,
            accept_identity,
            accept_logger,
            accept_max_consumers,
            accept_bandwidth_kbps,
            path_claims,
            active_relays,
            listener_cert_der.expect("provider mode requires listener cert"),
            listener_key_der.expect("provider mode requires listener key"),
            listener_port.expect("provider mode requires listener port"),
            initial_ip,
            advertisement.clone().expect("provider mode requires advertisement"),
            advertiser.expect("provider mode requires advertiser"),
            vec![(initial_ip, initial_handle)],
        )))
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
        let (closed_peer_tx, mut closed_peer_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (renewal_tx, mut renewal_rx) =
            tokio::sync::mpsc::unbounded_channel::<(String, u64)>();
        let browser = browser.expect("consumer mode requires browser");
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
                                (advertisement.clone(), false, true)
                            }
                            None => continue,
                        }
                    }
                    advertisement = browser.recv() => {
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
                endpoint = %advertisement.endpoint,
                "discovered peer-share advertisement"
            );
            emit_peer_share_event(
                browse_logger.as_ref(),
                format!(
                    "discovered peer={peer_id} endpoint={}",
                    advertisement.endpoint
                ),
            );

            let introduction = match request_peer_share_introduction(
                &browse_config,
                &browse_device_keypair,
                &advertisement,
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
            // path has a leg) or a dial fails. A failed first leg
            // keeps the old error path; a failed later leg keeps the
            // legs already won (they converge to the full set at the
            // next renewal, at most one introduction cycle away).
            let relay_expires_at = introduction.introduction.expires_at;
            let mut legs_dialed = 0usize;
            let mut generation = 0u64;
            let mut dial_failed = false;
            let mut transport_channel_closed = false;
            loop {
                match connect_peer_relay(
                    &browse_server_key,
                    &advertisement.device_public_key,
                    &introduction,
                    browse_config.socket_protect.as_ref(),
                    browse_bind_ip,
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
                        generation = legs.note_dial(&peer_id, relay_expires_at);
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
    if let Some(task) = browse_task {
        tasks.push(task);
    }

    // Endpoints are owned by their accept loops (spawned by the watcher),
    // never by the runtime struct, so pruning an endpoint actually tears
    // it down instead of lingering on a struct-kept clone.
    Ok(PeerShareRuntime { tasks })
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
        vec!["wss".to_owned(), "h3".to_owned()]
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

/// Bind a peer-share QUIC listener endpoint with an existing certificate.
/// Re-binds reuse the original cert, so the listener fingerprint consumers
/// pin never changes across re-advertises.
fn bind_peer_listener_endpoint(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    bind_addr: SocketAddr,
    socket_protect: Option<&SocketProtectFn>,
) -> anyhow::Result<quinn::Endpoint> {
    quinn::Endpoint::new(
        Default::default(),
        Some(build_peer_server_config(cert_der, key_der)),
        bind_peer_listener_socket(bind_addr, socket_protect)?,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|err| anyhow::anyhow!("failed to bind peer-share listener on {bind_addr}: {err}"))
}

fn build_listener_runtime(
    config: &ClientConfig,
    device_keypair: &DeviceKeypair,
    provider_paths: Option<&ProviderPathSource>,
) -> anyhow::Result<(
    quinn::Endpoint,
    PeerListenerIdentity,
    PeerShareAdvertisement,
    Vec<u8>,
    Vec<u8>,
    IpAddr,
    u16,
)> {
    let cert = generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .context("failed to generate peer-share listener certificate")?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
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
    let advertise_ip = resolve_advertise_ip(
        &config.client.peer_share_advertise_ip,
        bind_addr,
        &binds,
        &enumerate_interfaces(),
    )?;
    let listener_bind_addr = match bind_addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => SocketAddr::new(advertise_ip, bind_addr.port()),
        IpAddr::V6(ip) if ip.is_unspecified() => SocketAddr::new(advertise_ip, bind_addr.port()),
        _ => bind_addr,
    };
    let endpoint = bind_peer_listener_endpoint(
        cert_der.clone(),
        key_der.clone(),
        listener_bind_addr,
        config.socket_protect.as_ref(),
    )?;
    let listen_addr = endpoint.local_addr()?;
    let endpoint_str = SocketAddr::new(advertise_ip, listen_addr.port()).to_string();
    let instance_nonce = create_auth_challenge();
    let listener_identity = PeerListenerIdentity {
        provider_device_public_key: device_keypair.public_key_b64.clone(),
        instance_nonce: instance_nonce.clone(),
        listener_transport: "quic".to_owned(),
        listener_cert_fingerprint: fingerprint.clone(),
    };
    let advertisement = PeerShareAdvertisement {
        version: 1,
        device_public_key: device_keypair.public_key_b64.clone(),
        server_public_key: config.client.server_public_key.clone(),
        instance_nonce,
        endpoint: endpoint_str,
        listener_cert_fingerprint: fingerprint,
        capabilities: vec!["relay".to_owned(), "quic".to_owned()],
    };
    Ok((
        endpoint,
        listener_identity,
        advertisement,
        cert_der,
        key_der,
        advertise_ip,
        listen_addr.port(),
    ))
}

fn bind_peer_listener_socket(
    bind_addr: SocketAddr,
    socket_protect: Option<&SocketProtectFn>,
) -> anyhow::Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(bind_addr)?;
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

    Ok(socket)
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
) -> anyhow::Result<SignedPeerShareIntroduction> {
    let bootstrap_address = config.client.server_public_address.trim();
    if bootstrap_address.is_empty() {
        anyhow::bail!("server_public_address is required for peer-share introduction bootstrap");
    }

    let request = build_peer_introduction_request(consumer_keypair, advertisement)?;
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

fn build_peer_introduction_request(
    consumer_keypair: &DeviceKeypair,
    advertisement: &PeerShareAdvertisement,
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

fn resolve_advertise_ip(
    explicit_ip: &str,
    listen_addr: SocketAddr,
    binds: &[String],
    interfaces: &[NetworkInterface],
) -> anyhow::Result<IpAddr> {
    if !explicit_ip.trim().is_empty() {
        return explicit_ip
            .parse()
            .with_context(|| format!("invalid peer_share_advertise_ip: {explicit_ip}"));
    }

    match listen_addr.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => return Ok(IpAddr::V4(ip)),
        IpAddr::V6(ip) if !ip.is_unspecified() => return Ok(IpAddr::V6(ip)),
        _ => {}
    }

    let candidates: Vec<IpAddr> = interfaces
        .iter()
        .flat_map(|interface| interface.ips.iter())
        .map(|network| network.ip())
        .collect();
    select_advertise_ip_for_binds(binds, &candidates).ok_or_else(|| {
        anyhow::anyhow!("failed to determine a non-loopback peer-share advertise IP")
    })
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
fn select_advertise_ip_for_binds(binds: &[String], candidates: &[IpAddr]) -> Option<IpAddr> {
    prefer_path_subnet_candidate(candidates, binds).or_else(|| select_advertise_ip(candidates))
}

/// Recompute the provider's advertise IP from the CURRENT path set and
/// interfaces (the advertise watcher's view). Returns None when no
/// bindable address exists or a configured value cannot be parsed; the
/// caller then keeps the current advertisement. Pinned configurations
/// (explicit advertise IP or explicit bind address) always return the
/// pinned IP, so the watcher is a no-op for them. The live path set is
/// used for the subnet preference (not the session-start config), so a
/// path change that moves the provider to a new subnet re-selects onto
/// the new link instead of clinging to the old one.
fn desired_advertise_ip(
    config: &ClientConfig,
    path_source: &ProviderPathSource,
    interfaces: &[NetworkInterface],
) -> Option<IpAddr> {
    let binds: Vec<String> = match path_source {
        ProviderPathSource::Live(map) => map.read().ok()?.values().cloned().collect(),
        ProviderPathSource::Config(addresses) => addresses.clone(),
    };
    let bind_addr = config.client.peer_share_bind_address.parse::<SocketAddr>().ok()?;
    resolve_advertise_ip(
        &config.client.peer_share_advertise_ip,
        bind_addr,
        &binds,
        interfaces,
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
/// address: not loopback/unspecified/multicast, and not link-local. A
/// link-local address (169.254.0.0/16, fe80::/10) cannot be bound without
/// a scope id, so `UdpSocket::bind` rejects it with EINVAL — and interface
/// enumeration on phones commonly lists a link-local IPv6 address ahead of
/// the usable LAN IPv4 address.
fn is_bindable_advertise_ip(ip: &IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => !ip.is_link_local(),
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
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::try_from(key_der).expect("valid private key DER");
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server TLS config should build");
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
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    server_config.transport_config(Arc::new(transport));
    server_config
}

#[cfg(test)]
mod tests {
    use bonded_core::auth::verify_signature;

    use super::{
        build_peer_introduction_request, introduction_expired, keep_accept_loop,
        peer_share_peer_id, prefer_path_subnet_candidate, renewal_delay, resolve_advertise_ip,
        select_advertise_ip, select_advertise_ip_for_binds, should_accept_discovered_peer,
        PeerLegTracker, RedialQueue, RelayPathClaims, PEER_REDISCOVERY_MAX_ATTEMPTS,
        PEER_RELAY_RENEWAL_LEAD_SECS, PEER_RELAY_RENEWAL_MIN_DELAY,
    };
    use bonded_core::auth::DeviceKeypair;
    use bonded_core::config::{ClientConfig, PeerShareMode};
    use bonded_core::peer_share::{PeerShareAdvertisement, SignedPeerShareIntroduction};
    use pnet_datalink::NetworkInterface;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn leg_tracker_counts_overlapping_legs_per_peer() {
        let mut tracker = PeerLegTracker::default();
        assert!(!tracker.is_connected("peer-a"));

        // First dial: connected with one leg; rediscovery signal only
        // fires when the LAST leg closes.
        tracker.note_dial("peer-a", 1_000);
        assert!(tracker.is_connected("peer-a"));
        assert_eq!(tracker.leg_count("peer-a"), 1);

        // Renewal overlap: a second leg for the same peer.
        tracker.note_dial("peer-a", 1_240);
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
        let first = tracker.note_dial("peer-a", 1_000);
        assert!(tracker.is_current_generation("peer-a", first));
        assert_eq!(tracker.current_expires_at("peer-a"), Some(1_000));

        // A renewal dial supersedes the first dial's schedule.
        let second = tracker.note_dial("peer-a", 1_240);
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
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            capabilities: vec!["relay".to_owned(), "quic".to_owned()],
        };

        let request = build_peer_introduction_request(&consumer, &advertisement)
            .expect("request should build");
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
    fn advertise_ip_uses_explicit_override() {
        let ip = resolve_advertise_ip(
            "127.0.0.1",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 54443),
            &[],
            &Vec::<NetworkInterface>::new(),
        )
        .expect("override should parse");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
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
    fn advertise_ip_skips_link_local_ipv4_for_global_ipv6() {
        let candidates = vec![
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2600, 0, 0, 0, 0, 0, 0, 5)),
        ];
        assert_eq!(
            select_advertise_ip(&candidates),
            Some(IpAddr::V6(Ipv6Addr::new(0x2600, 0, 0, 0, 0, 0, 0, 5)))
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

    #[test]
    fn accept_loop_prune_keeps_current_and_live_only() {
        let current = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let live: std::collections::HashSet<IpAddr> = [
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        ]
        .into_iter()
        .collect();
        // The newly advertised IP survives even if enumeration has not
        // caught up with it yet.
        assert!(keep_accept_loop(
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 9)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 9)),
            &live
        ));
        // A surviving address keeps its loop (existing legs undisturbed).
        assert!(keep_accept_loop(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            current,
            &live
        ));
        // A dead address loses its loop.
        assert!(!keep_accept_loop(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99)),
            current,
            &live
        ));
    }
}
