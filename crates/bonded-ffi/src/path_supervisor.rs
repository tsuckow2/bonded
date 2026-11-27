//! F4: the direct-path supervisor.
//!
//! Before this module, a direct transport path (wifi, cellular, …) was
//! dialed exactly once at session start and never re-dialed: when the
//! server silently reaped an idle standby, or the path otherwise died,
//! the session stayed single-path (or failed over onto a corpse) until
//! the next full session restart. The supervisor gives each direct
//! path an identity (`path_index`, matching session start's bind
//! address and protocol rotation) and a lifecycle owner: the worker
//! reports losses, the supervisor re-dials the path in place with
//! backoff, completes the PING/PONG session-binding exchange, and
//! hands the bound transport back to the worker for insertion.
//!
//! Two failures are fatal rather than retryable, because both mean the
//! session this worker belongs to no longer exists as-is:
//! - a server-identity failure while dialing (fail-closed, exactly as
//!   at session start), and
//! - a binding PONG naming a different session id (the server reaped
//!   the whole session and started a new one; only a full session
//!   restart can reconcile that cleanly).
//! Both surface as [`RedialOutcome::SessionDead`] and the worker tears
//! the session down so the platform layer restarts it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bonded_client::{
    establish_single_transport_path, ClientTransport, SinglePathResult,
};
use bonded_core::config::ClientConfig;
use bonded_core::session::{
    SessionFrame, SessionHeader, FLAG_MULTIPATH_RECV, FLAG_PING, FLAG_PONG,
};
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::SessionWakeupStats;

/// Delay between a path being reported lost and the first re-dial.
/// Loss detection (heartbeat eviction) already lags the real death by
/// ~20 s, so the first attempt should be prompt.
const FIRST_RETRY_DELAY: Duration = Duration::from_secs(3);
/// Delay before the first re-dial of a path that was already missing
/// when the session started.
const INITIAL_MISSING_DELAY: Duration = Duration::from_secs(5);
/// Whole-attempt deadline for one path's dial (each protocol inside
/// has its own shorter timeout; this caps the rotation).
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
/// Deadline for the binding PONG, mirroring session-start discovery.
const BIND_TIMEOUT: Duration = Duration::from_secs(10);

/// Backoff after the n-th consecutive failed re-dial attempt.
fn backoff_delay(failed_attempts: u32) -> Duration {
    match failed_attempts {
        0 | 1 => Duration::from_secs(10),
        2 => Duration::from_secs(20),
        3 => Duration::from_secs(40),
        _ => Duration::from_secs(60),
    }
}

/// Cooldown after a bind PONG timeout (4.58): the dial succeeded
/// — the server authenticated us — but the first session frame
/// never arrived (the server logs "failed to receive initial
/// session frame"). Re-dialing such a path on the 60 s backoff cap
/// just burns battery on QUIC handshakes that die the same way
/// (88 overnight on one bench phone, ~15-20/hr); the path waits
/// 10 minutes before its next attempt instead.
const BIND_TIMEOUT_COOLDOWN: Duration = Duration::from_secs(600);

/// What the supervisor hands back to the worker loop.
pub enum RedialOutcome {
    /// The path was re-dialed and bound to the live session; insert
    /// this transport as that path's standby. `bind_address` is the
    /// address the dial actually used, so the worker can discard a
    /// re-dial that went stale while it was in flight (its path was
    /// removed, or re-addressed, by a path-set change meanwhile).
    Bound {
        path_index: usize,
        transport: ClientTransport,
        bind_address: Option<String>,
    },
    /// The session is unrecoverable in place; the worker must tear it
    /// down so the platform layer restarts it.
    SessionDead {
        reason: String,
        /// The path whose dial produced the fatal outcome, when the
        /// outcome came from dialing a specific path (used to attribute
        /// a server-identity failure to the connection that presented
        /// the bad credentials).
        path_index: Option<usize>,
    },
}

/// A path-set change for the supervisor: interfaces that appeared
/// (dial them) and interfaces that vanished (stop dialing them).
/// Addresses travel separately, through the shared address map the
/// supervisor reads at dial time, so this carries indexes only.
///
/// `parked` / `unparked` are the battery-saver suppression set
/// (4.64): paths the worker says are parked — a dead cellular path
/// while battery saver + idle + a non-cellular path is up. Parked
/// paths are never re-dialed; unparking one makes it due at once
/// (see `PathSupervisorState::note_unparked`). A park-only update
/// (empty `added`/`removed`) is not a network change: it does not
/// reset bind-timeout cooldowns.
///
/// `server_resolved_address` (4.116) is a fresh pre-resolved
/// "ip:port" dial target for the server, replacing the frozen
/// session-start address: the DNS record changed under a dead
/// tunnel and the supervisor has been re-dialing the stale IP.
/// `None` means "no address change" — the ordinary path-set
/// update. `Some` carries the new address even when it equals the
/// supervisor's current one (the supervisor itself no-ops on
/// equality); the worker is the one that validates and dedupes.
pub struct PathsUpdate {
    pub added: Vec<usize>,
    pub removed: Vec<usize>,
    pub parked: Vec<usize>,
    pub unparked: Vec<usize>,
    pub server_resolved_address: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathStatus {
    Present,
    Missing {
        failed_attempts: u32,
        next_due: Instant,
        /// True while the path waits out a bind-timeout cooldown
        /// (`BIND_TIMEOUT_COOLDOWN`) rather than the ordinary
        /// backoff. Only a cooldown is reset by a path-set change;
        /// an ordinary backoff keeps its schedule.
        cooling_down: bool,
    },
}

/// Pure bookkeeping for the supervisor: which direct paths exist,
/// which are missing, and when each missing path is next due a
/// re-dial attempt. Kept separate from the async runner so the
/// scheduling rules are unit-testable without sockets.
///
/// `parked` (4.64) is the battery-saver suppression set: paths the
/// worker says are parked (a dead cellular path while battery saver
/// + idle + a non-cellular path is up). A parked path is never due
/// — `due_paths` and `next_wakeup` skip it — so the supervisor
/// sleeps instead of waking the cellular modem every 60 s for a
/// path the saver already parked. Parking is a separate dimension
/// from Present/Missing: a parked path keeps its status, and
/// unparking it makes it due at once (see `note_unparked`).
pub struct PathSupervisorState {
    paths: BTreeMap<usize, PathStatus>,
    parked: HashSet<usize>,
}

impl PathSupervisorState {
    /// `desired` is every direct path the session wants; `present` is
    /// the subset currently established. Missing paths become due
    /// after [`INITIAL_MISSING_DELAY`]. `initially_parked` is the
    /// suppression set at spawn time (empty at session start — the
    /// session is not idle yet — non-empty for a mid-session spawn
    /// while battery saver already parks cellular).
    pub fn new(
        desired: &[usize],
        present: &[usize],
        initially_parked: &[usize],
        now: Instant,
    ) -> Self {
        let mut paths = BTreeMap::new();
        for &path in desired {
            paths.insert(
                path,
                if present.contains(&path) {
                    PathStatus::Present
                } else {
                    PathStatus::Missing {
                        failed_attempts: 0,
                        next_due: now + INITIAL_MISSING_DELAY,
                        cooling_down: false,
                    }
                },
            );
        }
        Self {
            paths,
            parked: initially_parked.iter().copied().collect(),
        }
    }

    /// Record that a path's transport is gone. Duplicate notices for
    /// an already-missing path do not reset its backoff.
    pub fn note_lost(&mut self, path: usize, now: Instant) {
        if let Some(status) = self.paths.get_mut(&path) {
            if *status == PathStatus::Present {
                *status = PathStatus::Missing {
                    failed_attempts: 0,
                    next_due: now + FIRST_RETRY_DELAY,
                    cooling_down: false,
                };
            }
        }
    }

    /// Record that a path is established again.
    pub fn note_bound(&mut self, path: usize) {
        if let Some(status) = self.paths.get_mut(&path) {
            *status = PathStatus::Present;
        }
    }

    /// Record that a path newly appeared (an interface came back).
    /// Absent paths join as due immediately, and a path already
    /// missing (backing off a failed dial) has its backoff reset to
    /// due now: unlike a path missing since session start (which
    /// just failed a dial and waits out [`INITIAL_MISSING_DELAY`]),
    /// a newly appeared interface has never been dialed in this
    /// state, so there is nothing to back off from. Present paths
    /// are untouched (no disturbance to a healthy path).
    pub fn note_added(&mut self, path: usize, now: Instant) {
        match self.paths.get_mut(&path) {
            Some(PathStatus::Missing {
                failed_attempts,
                next_due,
                cooling_down,
            }) => {
                *failed_attempts = 0;
                *next_due = now;
                *cooling_down = false;
            }
            Some(PathStatus::Present) => {}
            None => {
                self.paths.insert(
                    path,
                    PathStatus::Missing {
                        failed_attempts: 0,
                        next_due: now,
                        cooling_down: false,
                    },
                );
            }
        }
    }

    /// Forget a path entirely (its interface is gone): no further
    /// re-dials. A dial already in flight for it completes into the
    /// worker's stale-dial discard, and a later failure notice for
    /// it is a no-op. Its parked entry goes with it.
    pub fn note_removed(&mut self, path: usize) {
        self.paths.remove(&path);
        self.parked.remove(&path);
    }

    /// Suppress re-dials for a path (4.64): the worker says battery
    /// saver parked it. The path keeps its status; `due_paths` and
    /// `next_wakeup` simply skip it while parked, so the supervisor
    /// sleeps instead of waking the modem. Recording a park for a
    /// path not in the map is harmless — the entry is inert until
    /// the path is added, and `note_removed` clears it.
    pub fn note_parked(&mut self, path: usize) {
        self.parked.insert(path);
    }

    /// Clear the suppression for a path (4.64): the park condition
    /// lifted (Wi-Fi lost, traffic burst, battery saver off). A
    /// missing path becomes due at once with its failure count
    /// reset — exactly as `note_added` does for a newly appeared
    /// path — so the supervisor re-dials it immediately instead of
    /// waiting out a backoff whose evidence predates the park. A
    /// present path just leaves the parked set.
    pub fn note_unparked(&mut self, path: usize, now: Instant) {
        self.parked.remove(&path);
        if let Some(PathStatus::Missing {
            failed_attempts,
            next_due,
            cooling_down,
        }) = self.paths.get_mut(&path)
        {
            *failed_attempts = 0;
            *next_due = now;
            *cooling_down = false;
        }
    }

    /// The server's pre-resolved dial address changed (4.116: the
    /// DNS record moved under a dead tunnel). Every missing path
    /// becomes due at once with its failure count reset — exactly
    /// as `note_added` does for a newly appeared path — so the
    /// supervisor re-dials it immediately against the new address
    /// instead of waiting out a backoff whose evidence predates the
    /// address change (a dial to the old IP proves nothing about
    /// the new one). Present paths are untouched: a healthy path
    /// needs no re-dial, and the address only matters at dial time.
    /// Parked paths keep their suppression — `due_paths` still
    /// skips them — and become due on unpark, as usual.
    pub fn note_server_address_changed(&mut self, now: Instant) {
        for status in self.paths.values_mut() {
            if let PathStatus::Missing {
                failed_attempts,
                next_due,
                cooling_down,
            } = status
            {
                *failed_attempts = 0;
                *next_due = now;
                *cooling_down = false;
            }
        }
    }

    /// Whether a path is currently suppressed (4.64).
    pub fn is_parked(&self, path: usize) -> bool {
        self.parked.contains(&path)
    }

    pub fn contains(&self, path: usize) -> bool {
        self.paths.contains_key(&path)
    }

    /// Record a failed re-dial attempt; returns the delay until the
    /// next one.
    pub fn note_attempt_failed(&mut self, path: usize, now: Instant) -> Duration {
        match self.paths.get_mut(&path) {
            Some(PathStatus::Missing {
                failed_attempts,
                next_due,
                cooling_down,
            }) => {
                *failed_attempts += 1;
                let delay = backoff_delay(*failed_attempts);
                *next_due = now + delay;
                *cooling_down = false;
                delay
            }
            _ => Duration::ZERO,
        }
    }

    /// Record a bind PONG timeout (the dial succeeded but the first
    /// session frame never arrived); returns the cooldown until the
    /// next attempt. Unlike the ordinary backoff this is 10 minutes
    /// (`BIND_TIMEOUT_COOLDOWN`): the failure is a property of the
    /// path, not of the moment, and re-dialing it promptly only
    /// repeats a handshake that dies the same way. The failure
    /// count still increments, so a later ordinary failure backs
    /// off from where the count stands.
    pub fn note_bind_timeout(&mut self, path: usize, now: Instant) -> Duration {
        match self.paths.get_mut(&path) {
            Some(PathStatus::Missing {
                failed_attempts,
                next_due,
                cooling_down,
            }) => {
                *failed_attempts += 1;
                *next_due = now + BIND_TIMEOUT_COOLDOWN;
                *cooling_down = true;
                BIND_TIMEOUT_COOLDOWN
            }
            _ => Duration::ZERO,
        }
    }

    /// A path-set change invalidates the evidence behind every
    /// bind-timeout cooldown: the network may have changed under a
    /// path that was cooling down, so each cooling path becomes due
    /// now with its failure count reset (exactly as `note_added`
    /// does for a newly appeared path). Paths in an ordinary
    /// backoff keep their schedule — only the cooldown resets.
    pub fn reset_cooldowns(&mut self, now: Instant) {
        for status in self.paths.values_mut() {
            if let PathStatus::Missing {
                failed_attempts,
                next_due,
                cooling_down,
            } = status
            {
                if *cooling_down {
                    *failed_attempts = 0;
                    *next_due = now;
                    *cooling_down = false;
                }
            }
        }
    }

    /// Paths whose re-dial is due at `now`, in path order. Parked
    /// paths (4.64) are never due, however long they have waited.
    pub fn due_paths(&self, now: Instant) -> Vec<usize> {
        self.paths
            .iter()
            .filter_map(|(&path, status)| match status {
                PathStatus::Missing { next_due, .. }
                    if *next_due <= now && !self.parked.contains(&path) =>
                {
                    Some(path)
                }
                _ => None,
            })
            .collect()
    }

    /// The earliest moment any missing path becomes due. Parked
    /// paths (4.64) contribute no wakeup: when every missing path
    /// is parked the supervisor sleeps instead of waking for a
    /// re-dial the saver already suppressed.
    pub fn next_wakeup(&self) -> Option<Instant> {
        self.paths
            .iter()
            .filter_map(|(&path, status)| match status {
                PathStatus::Missing { next_due, .. }
                    if !self.parked.contains(&path) =>
                {
                    Some(*next_due)
                }
                _ => None,
            })
            .min()
    }

    pub fn is_present(&self, path: usize) -> bool {
        matches!(self.paths.get(&path), Some(PathStatus::Present))
    }
}

/// Maps the worker's transport-vector indices to direct-path indices.
/// Vector indices shift on every insert/remove; path indices are the
/// durable identity the supervisor works in. Peer-relay transports
/// have no entry.
#[derive(Default)]
pub struct PathIndexMap {
    by_vec_index: HashMap<usize, usize>,
}

impl PathIndexMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, vec_index: usize, path_index: usize) {
        self.by_vec_index.insert(vec_index, path_index);
    }

    pub fn path_of(&self, vec_index: usize) -> Option<usize> {
        self.by_vec_index.get(&vec_index).copied()
    }

    /// Vector index currently holding a path, if present.
    pub fn vec_index_of(&self, path_index: usize) -> Option<usize> {
        self.by_vec_index
            .iter()
            .find(|(_, &path)| path == path_index)
            .map(|(&index, _)| index)
    }

    /// Every direct path index currently mapped, in no particular
    /// order (the durable identities of the live direct transports).
    pub fn path_indexes(&self) -> Vec<usize> {
        self.by_vec_index.values().copied().collect()
    }

    pub fn contains_path(&self, path_index: usize) -> bool {
        self.by_vec_index.values().any(|&p| p == path_index)
    }

    /// Adjust after the transport at `removed` was taken out of the
    /// vector: its entry drops and every later index shifts down one.
    pub fn on_remove(&mut self, removed: usize) {
        self.by_vec_index.remove(&removed);
        let shifted: Vec<(usize, usize)> = self
            .by_vec_index
            .drain()
            .map(|(index, path)| {
                (if index > removed { index - 1 } else { index }, path)
            })
            .collect();
        self.by_vec_index.extend(shifted);
    }
}

enum AttemptResult {
    Bound {
        transport: ClientTransport,
        bind_address: Option<String>,
    },
    Failed(String),
    /// The bind PONG timed out: the dial succeeded (the server
    /// authenticated us) but the first session frame never arrived.
    /// The supervisor cools this path down for
    /// `BIND_TIMEOUT_COOLDOWN` instead of the ordinary backoff.
    BindTimedOut(String),
    SessionDead(String),
}

enum BindFailure {
    /// The PONG named a different session: the server replaced the
    /// session wholesale.
    SessionReplaced(u32),
    /// The binding PONG never arrived within `BIND_TIMEOUT`: the
    /// dial succeeded but the first session frame never completed
    /// — the server logs this as "failed to receive initial
    /// session frame". Kept distinct from `Retryable` so the
    /// supervisor can cool the path down instead of re-dialing on
    /// the ordinary backoff.
    BindTimedOut,
    Retryable(String),
}

/// The session-binding exchange session start performs per path:
/// PING, expect a PONG carrying the authoritative session id.
async fn bind_redialed_transport(
    transport: &mut ClientTransport,
    session_id: u32,
) -> Result<(), BindFailure> {
    let ping = SessionFrame {
        header: SessionHeader {
            connection_id: 0,
            sequence: 0,
            flags: FLAG_PING | FLAG_MULTIPATH_RECV,
        },
        payload: Bytes::new(),
    };
    transport
        .send(ping)
        .await
        .map_err(|err| BindFailure::Retryable(format!("bind ping send failed: {err}")))?;
    match tokio::time::timeout(BIND_TIMEOUT, transport.recv()).await {
        Ok(Ok(frame)) if frame.header.flags & FLAG_PONG != 0 => {
            if frame.header.connection_id == session_id {
                Ok(())
            } else {
                Err(BindFailure::SessionReplaced(frame.header.connection_id))
            }
        }
        Ok(Ok(frame)) => Err(BindFailure::Retryable(format!(
            "bind expected a pong, got flags={}",
            frame.header.flags
        ))),
        Ok(Err(err)) => Err(BindFailure::Retryable(format!("bind recv failed: {err}"))),
        Err(_) => Err(BindFailure::BindTimedOut),
    }
}

async fn attempt_redial(
    config: &ClientConfig,
    path_index: usize,
    requested_paths: usize,
    session_id: u32,
    path_addresses: &Arc<std::sync::RwLock<HashMap<usize, String>>>,
    log: &Arc<dyn Fn(String) + Send + Sync>,
) -> AttemptResult {
    let mut observer = |message: String| log(message);
    // The bind address comes from the live path-set map, not the
    // frozen session-start config: after a path-set change the map
    // holds the current address for this path (or nothing, for an
    // unbound path, in which case the config fallback below applies
    // exactly as at session start).
    let bind_address = path_addresses
        .read()
        .expect("path address map lock poisoned")
        .get(&path_index)
        .cloned();
    let dial = establish_single_transport_path(
        config,
        path_index,
        requested_paths,
        bind_address.as_deref(),
        &mut observer,
    );
    let mut transport = match tokio::time::timeout(DIAL_TIMEOUT, dial).await {
        Err(_) => return AttemptResult::Failed("dial timed out".to_owned()),
        // establish_* returns Err only for a server-identity failure.
        Ok(Err(err)) => return AttemptResult::SessionDead(format!("{err:#}")),
        Ok(Ok(SinglePathResult::Failed(reason))) => {
            return AttemptResult::Failed(reason);
        }
        Ok(Ok(SinglePathResult::Connected(transport))) => transport,
    };
    match bind_redialed_transport(&mut transport, session_id).await {
        Ok(()) => AttemptResult::Bound {
            transport,
            bind_address,
        },
        Err(BindFailure::SessionReplaced(other)) => {
            let _ = transport.close().await;
            AttemptResult::SessionDead(format!(
                "re-dialed path {path_index} bound to session {other}, expected {session_id}; the server replaced the session"
            ))
        }
        Err(BindFailure::BindTimedOut) => {
            let _ = transport.close().await;
            AttemptResult::BindTimedOut("bind timed out".to_owned())
        }
        Err(BindFailure::Retryable(reason)) => {
            let _ = transport.close().await;
            AttemptResult::Failed(reason)
        }
    }
}

/// Spawn the supervisor task. It runs until the session's cancel
/// token fires, the worker drops its channels, or a fatal outcome is
/// reported. `initially_parked` is the battery-saver suppression set
/// at spawn time (4.64): empty at session start, the worker's
/// current set for a mid-session spawn.
pub fn spawn_path_supervisor(
    config: ClientConfig,
    requested_paths: usize,
    desired_paths: Vec<usize>,
    initially_present: Vec<usize>,
    initially_parked: Vec<usize>,
    session_id: u32,
    cancel_token: CancellationToken,
    mut lost_rx: mpsc::UnboundedReceiver<usize>,
    mut paths_update_rx: mpsc::UnboundedReceiver<PathsUpdate>,
    path_addresses: Arc<std::sync::RwLock<HashMap<usize, String>>>,
    outcome_tx: mpsc::UnboundedSender<RedialOutcome>,
    log: Arc<dyn Fn(String) + Send + Sync>,
    wakeup_stats: Arc<SessionWakeupStats>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // 4.116: the supervisor owns a clone of the session config
        // (see the spawn site) and dials from it, so a DNS refresh
        // must be able to rewrite its copy — hence `mut`.
        let mut config = config;
        let mut state = PathSupervisorState::new(
            &desired_paths,
            &initially_present,
            &initially_parked,
            Instant::now(),
        );
        if state.next_wakeup().is_some() {
            log(format!(
                "supervisor active: {} of {} direct paths present",
                initially_present.len(),
                desired_paths.len()
            ));
        }
        loop {
            let wakeup = state.next_wakeup();
            let sleep = match wakeup {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)),
                None => tokio::time::sleep(Duration::from_secs(3600)),
            };
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                lost = lost_rx.recv() => {
                    match lost {
                        Some(path) => {
                            if state.is_present(path) {
                                log(format!(
                                    "path {path} reported lost; scheduling re-dial"
                                ));
                            }
                            state.note_lost(path, Instant::now());
                        }
                        None => break,
                    }
                }
                update = paths_update_rx.recv() => {
                    match update {
                        Some(PathsUpdate {
                            added,
                            removed,
                            parked,
                            unparked,
                            server_resolved_address,
                        }) => {
                            let path_set_changed =
                                !added.is_empty() || !removed.is_empty();
                            for path in removed {
                                state.note_removed(path);
                            }
                            let now = Instant::now();
                            for path in added {
                                state.note_added(path, now);
                            }
                            // The set changed under paths that were
                            // not added or removed: a network change
                            // invalidates their bind-timeout
                            // cooldowns too (ordinary backoffs are
                            // untouched). A park-only update is not
                            // a network change, so it does not reset
                            // cooldowns (4.64).
                            if path_set_changed {
                                state.reset_cooldowns(now);
                            }
                            // Server address refresh (4.116): the
                            // DNS record moved under a dead tunnel.
                            // Swap the dial target in this task's
                            // config clone and make every missing
                            // path due at once, so the next wakeup
                            // re-dials against the new address
                            // instead of the stale one. An address
                            // identical to the current one is a
                            // no-op (the worker dedupes first; this
                            // is defense in depth). The wakeup is
                            // recomputed below, so a newly due path
                            // dials without waiting out a stale
                            // sleep — the loop-back comment for
                            // added/unparked paths applies here too.
                            if let Some(address) = server_resolved_address {
                                if address != config.client.server_resolved_address {
                                    log(format!(
                                        "supervisor: server address refreshed {} -> {}",
                                        config.client.server_resolved_address, address
                                    ));
                                    config.client.server_resolved_address = address;
                                    state.note_server_address_changed(now);
                                }
                            }
                            // Battery-saver suppression (4.64):
                            // parked paths stop being re-dialed;
                            // unparked ones are due at once (their
                            // backoff is reset by note_unparked).
                            for path in parked {
                                state.note_parked(path);
                            }
                            for path in unparked {
                                state.note_unparked(path, now);
                            }
                            // Loop back: wakeup is recomputed, so a
                            // newly added or unparked path (due now)
                            // dials without waiting out a stale sleep.
                        }
                        None => break,
                    }
                }
                _ = sleep => {
                    for path in state.due_paths(Instant::now()) {
                        if cancel_token.is_cancelled() {
                            return;
                        }
                        // Profiler (§5(b)): count every re-dial
                        // attempt, success or failure, so the
                        // hourly aggregates can attribute the
                        // re-dial loop's share of the wakeups.
                        wakeup_stats
                            .supervisor_redial_attempts
                            .fetch_add(1, Ordering::Relaxed);
                        match attempt_redial(
                            &config,
                            path,
                            requested_paths,
                            session_id,
                            &path_addresses,
                            &log,
                        )
                        .await
                        {
                            AttemptResult::Bound {
                                transport,
                                bind_address,
                            } => {
                                state.note_bound(path);
                                log(format!("path {path} re-dialed and bound"));
                                if outcome_tx
                                    .send(RedialOutcome::Bound {
                                        path_index: path,
                                        transport,
                                        bind_address,
                                    })
                                    .is_err()
                                {
                                    return;
                                }
                            }
                            AttemptResult::Failed(reason) => {
                                // A path removed while its dial was
                                // in flight is no longer in state;
                                // don't log a phantom "next attempt".
                                if state.contains(path) {
                                    let delay = state.note_attempt_failed(
                                        path,
                                        Instant::now(),
                                    );
                                    log(format!(
                                        "path {path} re-dial failed ({reason}); next attempt in {}s",
                                        delay.as_secs()
                                    ));
                                }
                            }
                            AttemptResult::BindTimedOut(reason) => {
                                // The dial succeeded but the first
                                // session frame never arrived: cool
                                // the path down for 10 minutes
                                // instead of the ordinary backoff.
                                // A path removed while its dial was
                                // in flight is no longer in state;
                                // don't log a phantom cooldown.
                                if state.contains(path) {
                                    let delay = state.note_bind_timeout(
                                        path,
                                        Instant::now(),
                                    );
                                    log(format!(
                                        "path {path} re-dial failed ({reason}); bind timeout, cooling down for {}s",
                                        delay.as_secs()
                                    ));
                                }
                            }
                            AttemptResult::SessionDead(reason) => {
                                let _ = outcome_tx.send(RedialOutcome::SessionDead {
                                    reason,
                                    path_index: Some(path),
                                });
                                return;
                            }
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn initially_missing_paths_become_due_after_initial_delay() {
        let now = t0();
        let state = PathSupervisorState::new(&[0, 1, 2], &[0], &[], now);
        assert!(state.is_present(0));
        assert!(!state.is_present(1));
        assert!(state.due_paths(now).is_empty());
        assert_eq!(
            state.due_paths(now + INITIAL_MISSING_DELAY),
            vec![1, 2]
        );
        assert_eq!(
            state.next_wakeup(),
            Some(now + INITIAL_MISSING_DELAY)
        );
    }

    #[test]
    fn lost_path_is_due_after_first_retry_delay() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0, 1], &[0, 1], &[], now);
        assert_eq!(state.next_wakeup(), None);
        state.note_lost(1, now);
        assert!(state.due_paths(now).is_empty());
        assert_eq!(state.due_paths(now + FIRST_RETRY_DELAY), vec![1]);
    }

    #[test]
    fn duplicate_loss_notice_does_not_reset_backoff() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0], &[0], &[], now);
        state.note_lost(0, now);
        let first_due = state.next_wakeup().expect("due after loss");
        state.note_attempt_failed(0, now + FIRST_RETRY_DELAY);
        let backed_off = state.next_wakeup().expect("due after failure");
        assert!(backed_off > first_due);
        // A second loss notice mid-backoff changes nothing.
        state.note_lost(0, now + FIRST_RETRY_DELAY);
        assert_eq!(state.next_wakeup(), Some(backed_off));
    }

    #[test]
    fn backoff_grows_and_caps() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0], &[], &[], now);
        let mut at = now + INITIAL_MISSING_DELAY;
        for expected in [10_u64, 20, 40, 60, 60] {
            let delay = state.note_attempt_failed(0, at);
            assert_eq!(delay, Duration::from_secs(expected));
            at += delay;
            assert_eq!(state.next_wakeup(), Some(at));
        }
    }

    #[test]
    fn bind_timeout_cools_down_for_ten_minutes() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0], &[], &[], now);
        let delay = state.note_bind_timeout(0, now + INITIAL_MISSING_DELAY);
        assert_eq!(delay, BIND_TIMEOUT_COOLDOWN);
        assert_eq!(delay, Duration::from_secs(600));
        // Not due at the ordinary 60 s backoff cap, nor at 599 s.
        assert!(state
            .due_paths(now + INITIAL_MISSING_DELAY + Duration::from_secs(60))
            .is_empty());
        assert!(state
            .due_paths(now + INITIAL_MISSING_DELAY + Duration::from_secs(599))
            .is_empty());
        assert_eq!(
            state.due_paths(now + INITIAL_MISSING_DELAY + BIND_TIMEOUT_COOLDOWN),
            vec![0]
        );
        assert_eq!(
            state.next_wakeup(),
            Some(now + INITIAL_MISSING_DELAY + BIND_TIMEOUT_COOLDOWN)
        );
    }

    #[test]
    fn path_set_change_resets_bind_cooldown_only() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0, 1], &[], &[], now);
        let at = now + INITIAL_MISSING_DELAY;
        // Path 0 cools down after a bind timeout; path 1 sits in an
        // ordinary backoff after a dial failure.
        state.note_bind_timeout(0, at);
        let backoff = state.note_attempt_failed(1, at);
        assert_eq!(backoff, Duration::from_secs(10));
        // A path-set change resets the cooldown to due now, and the
        // failure count with it (so the next ordinary failure backs
        // off from 10 s, not from the cooldown's count).
        state.reset_cooldowns(at);
        assert_eq!(state.due_paths(at), vec![0]);
        assert_eq!(state.next_wakeup(), Some(at));
        let next = state.note_attempt_failed(0, at);
        assert_eq!(next, Duration::from_secs(10));
        // The ordinary backoff on path 1 is untouched: still due
        // 10 s after the failure, not now.
        assert!(state.due_paths(at).is_empty());
        assert_eq!(state.next_wakeup(), Some(at + Duration::from_secs(10)));
    }

    #[test]
    fn added_path_resets_bind_cooldown() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0], &[], &[], now);
        state.note_bind_timeout(0, now + INITIAL_MISSING_DELAY);
        assert!(state.due_paths(now + Duration::from_secs(60)).is_empty());
        state.note_added(0, now + Duration::from_secs(60));
        assert_eq!(state.due_paths(now + Duration::from_secs(60)), vec![0]);
    }

    #[test]
    fn parked_path_is_never_due_and_contributes_no_wakeup() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0, 1], &[0], &[], now);
        // Path 1 is missing and due after the initial delay; path 0
        // is present. Parking path 1 suppresses it entirely: no due
        // path, no wakeup — the supervisor sleeps instead of waking
        // the modem for a path the saver already parked.
        let at = now + INITIAL_MISSING_DELAY;
        assert_eq!(state.due_paths(at), vec![1]);
        state.note_parked(1);
        assert!(state.is_parked(1));
        assert!(state.due_paths(at).is_empty());
        assert!(state.due_paths(at + Duration::from_secs(3600)).is_empty());
        assert_eq!(state.next_wakeup(), None);
        // Parking a present path is a no-op for the schedule.
        state.note_parked(0);
        assert_eq!(state.next_wakeup(), None);
    }

    #[test]
    fn unparked_path_is_due_at_once_with_count_reset() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0], &[], &[], now);
        let at = now + INITIAL_MISSING_DELAY;
        // Fail twice (10 s, then 20 s backoff) and park mid-backoff.
        state.note_attempt_failed(0, at);
        state.note_attempt_failed(0, at + Duration::from_secs(10));
        assert_eq!(state.next_wakeup(), Some(at + Duration::from_secs(30)));
        state.note_parked(0);
        assert_eq!(state.next_wakeup(), None);
        // Unparking makes it due now with the failure count reset,
        // so the next failure backs off from 10 s, not from the
        // pre-park count.
        let unpark_at = at + Duration::from_secs(100);
        state.note_unparked(0, unpark_at);
        assert!(!state.is_parked(0));
        assert_eq!(state.due_paths(unpark_at), vec![0]);
        let next = state.note_attempt_failed(0, unpark_at);
        assert_eq!(next, Duration::from_secs(10));
    }

    #[test]
    fn server_address_change_makes_backed_off_paths_due_at_once() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0, 1], &[0, 1], &[], now);
        let at = now + Duration::from_secs(60);
        // Both paths lost, then failed twice: after the second
        // failure (20 s backoff) neither is due until at+33 s.
        state.note_lost(0, at);
        state.note_lost(1, at);
        state.note_attempt_failed(0, at + FIRST_RETRY_DELAY);
        state.note_attempt_failed(1, at + FIRST_RETRY_DELAY);
        state.note_attempt_failed(0, at + Duration::from_secs(13));
        state.note_attempt_failed(1, at + Duration::from_secs(13));
        assert!(state.due_paths(at + Duration::from_secs(20)).is_empty());
        // The DNS record moved: both missing paths become due now
        // with their failure counts reset, so the next failure
        // backs off from 10 s — the old-IP dials prove nothing
        // about the new address.
        let refresh_at = at + Duration::from_secs(20);
        state.note_server_address_changed(refresh_at);
        assert_eq!(state.due_paths(refresh_at), vec![0, 1]);
        let next = state.note_attempt_failed(0, refresh_at);
        assert_eq!(next, Duration::from_secs(10));
    }

    #[test]
    fn server_address_change_also_resets_bind_cooldown() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0], &[], &[], now);
        let at = now + INITIAL_MISSING_DELAY;
        state.note_bind_timeout(0, at);
        assert!(state.due_paths(at + Duration::from_secs(60)).is_empty());
        state.note_server_address_changed(at + Duration::from_secs(60));
        assert_eq!(
            state.due_paths(at + Duration::from_secs(60)),
            vec![0]
        );
    }

    #[test]
    fn server_address_change_leaves_present_and_parked_paths_alone() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0, 1, 2], &[0], &[], now);
        let at = now + INITIAL_MISSING_DELAY;
        // Path 1 is missing and due; path 2 is missing, due, then parked.
        assert_eq!(state.due_paths(at), vec![1, 2]);
        state.note_parked(2);
        let refresh_at = at + Duration::from_secs(30);
        state.note_server_address_changed(refresh_at);
        // Present path 0 is untouched (still present, no wakeup
        // from it); missing path 1 is due now; parked path 2 stays
        // suppressed — the address change does not unpark it.
        assert!(state.is_present(0));
        assert_eq!(state.due_paths(refresh_at), vec![1]);
        assert_eq!(state.next_wakeup(), Some(refresh_at));
    }

    #[test]
    fn initially_parked_paths_start_suppressed() {
        let now = t0();
        let state = PathSupervisorState::new(&[0, 1], &[0], &[1], now);
        assert!(state.is_parked(1));
        assert!(state.due_paths(now + INITIAL_MISSING_DELAY).is_empty());
        assert_eq!(state.next_wakeup(), None);
    }

    #[test]
    fn parked_path_stays_parked_across_readd_and_removal_clears_it() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0, 1], &[0, 1], &[], now);
        state.note_lost(1, now);
        state.note_parked(1);
        // The interface vanishes and comes back while parked: the
        // path is due-now via note_added but still suppressed.
        state.note_removed(1);
        assert!(!state.is_parked(1));
        state.note_added(1, now);
        assert_eq!(state.due_paths(now), vec![1]);
        state.note_parked(1);
        assert!(state.due_paths(now).is_empty());
        // Only the unpark clears it.
        state.note_unparked(1, now);
        assert_eq!(state.due_paths(now), vec![1]);
    }

    #[test]
    fn non_parked_path_is_still_retried_on_schedule() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0, 1], &[0], &[1], now);
        // Path 1 is parked; path 0 is present. A second missing path
        // that is NOT parked keeps its ordinary backoff: parking
        // one path must not disturb the other's re-dial.
        let at = now + INITIAL_MISSING_DELAY;
        state.note_lost(0, at);
        assert!(state.due_paths(at).is_empty());
        assert_eq!(state.due_paths(at + FIRST_RETRY_DELAY), vec![0]);
        assert_eq!(state.next_wakeup(), Some(at + FIRST_RETRY_DELAY));
    }

    #[test]
    fn bound_path_leaves_the_schedule() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0, 1], &[0], &[], now);
        assert_eq!(state.next_wakeup(), Some(now + INITIAL_MISSING_DELAY));
        state.note_bound(1);
        assert_eq!(state.next_wakeup(), None);
        assert!(state.is_present(1));
    }

    #[test]
    fn added_path_is_due_immediately_and_removed_path_is_forgotten() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0, 1], &[0, 1], &[], now);
        assert_eq!(state.next_wakeup(), None);
        // A removed path leaves the schedule entirely: no wakeup,
        // and a later failure notice for it is a silent no-op.
        state.note_removed(1);
        assert!(!state.contains(1));
        assert_eq!(state.next_wakeup(), None);
        assert_eq!(state.note_attempt_failed(1, now), Duration::ZERO);
        // A newly added path dials at once, not after the
        // missing-at-start delay.
        state.note_added(2, now);
        assert_eq!(state.due_paths(now), vec![2]);
        assert_eq!(state.next_wakeup(), Some(now));
        // Adding a present path disturbs nothing.
        state.note_added(0, now);
        assert!(state.is_present(0));
        assert_eq!(state.due_paths(now), vec![2]);
    }

    #[test]
    fn index_map_tracks_removals() {
        let mut map = PathIndexMap::new();
        map.insert(0, 0);
        map.insert(1, 1);
        // index 2 is a peer relay: no entry.
        assert_eq!(map.path_of(0), Some(0));
        assert_eq!(map.path_of(1), Some(1));
        assert_eq!(map.path_of(2), None);
        assert!(map.contains_path(1));

        map.on_remove(0);
        assert_eq!(map.path_of(0), Some(1));
        assert_eq!(map.path_of(1), None);
        assert!(map.contains_path(1));
        assert!(!map.contains_path(0));

        map.insert(2, 0);
        assert_eq!(map.path_of(2), Some(0));
        map.on_remove(2);
        assert!(!map.contains_path(0));
        assert_eq!(map.path_of(0), Some(1));
    }
}
