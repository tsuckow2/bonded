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

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
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

/// What the supervisor hands back to the worker loop.
pub enum RedialOutcome {
    /// The path was re-dialed and bound to the live session; insert
    /// this transport as that path's standby.
    Bound {
        path_index: usize,
        transport: ClientTransport,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathStatus {
    Present,
    Missing {
        failed_attempts: u32,
        next_due: Instant,
    },
}

/// Pure bookkeeping for the supervisor: which direct paths exist,
/// which are missing, and when each missing path is next due a
/// re-dial attempt. Kept separate from the async runner so the
/// scheduling rules are unit-testable without sockets.
pub struct PathSupervisorState {
    paths: BTreeMap<usize, PathStatus>,
}

impl PathSupervisorState {
    /// `desired` is every direct path the session wants; `present` is
    /// the subset currently established. Missing paths become due
    /// after [`INITIAL_MISSING_DELAY`].
    pub fn new(desired: &[usize], present: &[usize], now: Instant) -> Self {
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
                    }
                },
            );
        }
        Self { paths }
    }

    /// Record that a path's transport is gone. Duplicate notices for
    /// an already-missing path do not reset its backoff.
    pub fn note_lost(&mut self, path: usize, now: Instant) {
        if let Some(status) = self.paths.get_mut(&path) {
            if *status == PathStatus::Present {
                *status = PathStatus::Missing {
                    failed_attempts: 0,
                    next_due: now + FIRST_RETRY_DELAY,
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

    /// Record a failed re-dial attempt; returns the delay until the
    /// next one.
    pub fn note_attempt_failed(&mut self, path: usize, now: Instant) -> Duration {
        match self.paths.get_mut(&path) {
            Some(PathStatus::Missing {
                failed_attempts,
                next_due,
            }) => {
                *failed_attempts += 1;
                let delay = backoff_delay(*failed_attempts);
                *next_due = now + delay;
                delay
            }
            _ => Duration::ZERO,
        }
    }

    /// Paths whose re-dial is due at `now`, in path order.
    pub fn due_paths(&self, now: Instant) -> Vec<usize> {
        self.paths
            .iter()
            .filter_map(|(&path, status)| match status {
                PathStatus::Missing { next_due, .. } if *next_due <= now => Some(path),
                _ => None,
            })
            .collect()
    }

    /// The earliest moment any missing path becomes due.
    pub fn next_wakeup(&self) -> Option<Instant> {
        self.paths
            .values()
            .filter_map(|status| match status {
                PathStatus::Missing { next_due, .. } => Some(*next_due),
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
    Bound(ClientTransport),
    Failed(String),
    SessionDead(String),
}

enum BindFailure {
    /// The PONG named a different session: the server replaced the
    /// session wholesale.
    SessionReplaced(u32),
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
        Err(_) => Err(BindFailure::Retryable("bind timed out".to_owned())),
    }
}

async fn attempt_redial(
    config: &ClientConfig,
    path_index: usize,
    requested_paths: usize,
    session_id: u32,
    log: &Arc<dyn Fn(String) + Send + Sync>,
) -> AttemptResult {
    let mut observer = |message: String| log(message);
    let dial = establish_single_transport_path(
        config,
        path_index,
        requested_paths,
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
        Ok(()) => AttemptResult::Bound(transport),
        Err(BindFailure::SessionReplaced(other)) => {
            let _ = transport.close().await;
            AttemptResult::SessionDead(format!(
                "re-dialed path {path_index} bound to session {other}, expected {session_id}; the server replaced the session"
            ))
        }
        Err(BindFailure::Retryable(reason)) => {
            let _ = transport.close().await;
            AttemptResult::Failed(reason)
        }
    }
}

/// Spawn the supervisor task. It runs until the session's cancel
/// token fires, the worker drops its channels, or a fatal outcome is
/// reported.
pub fn spawn_path_supervisor(
    config: ClientConfig,
    requested_paths: usize,
    initially_present: Vec<usize>,
    session_id: u32,
    cancel_token: CancellationToken,
    mut lost_rx: mpsc::UnboundedReceiver<usize>,
    outcome_tx: mpsc::UnboundedSender<RedialOutcome>,
    log: Arc<dyn Fn(String) + Send + Sync>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let desired: Vec<usize> = (0..requested_paths).collect();
        let mut state =
            PathSupervisorState::new(&desired, &initially_present, Instant::now());
        if state.next_wakeup().is_some() {
            log(format!(
                "supervisor active: {} of {} direct paths present",
                initially_present.len(),
                requested_paths
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
                _ = sleep => {
                    for path in state.due_paths(Instant::now()) {
                        if cancel_token.is_cancelled() {
                            return;
                        }
                        match attempt_redial(
                            &config,
                            path,
                            requested_paths,
                            session_id,
                            &log,
                        )
                        .await
                        {
                            AttemptResult::Bound(transport) => {
                                state.note_bound(path);
                                log(format!("path {path} re-dialed and bound"));
                                if outcome_tx
                                    .send(RedialOutcome::Bound {
                                        path_index: path,
                                        transport,
                                    })
                                    .is_err()
                                {
                                    return;
                                }
                            }
                            AttemptResult::Failed(reason) => {
                                let delay =
                                    state.note_attempt_failed(path, Instant::now());
                                log(format!(
                                    "path {path} re-dial failed ({reason}); next attempt in {}s",
                                    delay.as_secs()
                                ));
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
        let state = PathSupervisorState::new(&[0, 1, 2], &[0], now);
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
        let mut state = PathSupervisorState::new(&[0, 1], &[0, 1], now);
        assert_eq!(state.next_wakeup(), None);
        state.note_lost(1, now);
        assert!(state.due_paths(now).is_empty());
        assert_eq!(state.due_paths(now + FIRST_RETRY_DELAY), vec![1]);
    }

    #[test]
    fn duplicate_loss_notice_does_not_reset_backoff() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0], &[0], now);
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
        let mut state = PathSupervisorState::new(&[0], &[], now);
        let mut at = now + INITIAL_MISSING_DELAY;
        for expected in [10_u64, 20, 40, 60, 60] {
            let delay = state.note_attempt_failed(0, at);
            assert_eq!(delay, Duration::from_secs(expected));
            at += delay;
            assert_eq!(state.next_wakeup(), Some(at));
        }
    }

    #[test]
    fn bound_path_leaves_the_schedule() {
        let now = t0();
        let mut state = PathSupervisorState::new(&[0, 1], &[0], now);
        assert_eq!(state.next_wakeup(), Some(now + INITIAL_MISSING_DELAY));
        state.note_bound(1);
        assert_eq!(state.next_wakeup(), None);
        assert!(state.is_present(1));
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
