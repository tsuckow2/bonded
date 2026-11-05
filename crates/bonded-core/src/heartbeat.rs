//! Adaptive session-heartbeat policy (battery).
//!
//! A bonded session used to ping every path on a fixed short cadence
//! (5 s in the Linux CLI worker, 10 s in the Android worker) forever,
//! even with no user traffic. On cellular that never lets the radio
//! sleep: the modem stays in high-power mode for ~10-15 s after each
//! packet, so a 5-10 s heartbeat means it never drops to idle at all.
//!
//! The policy here is: keep the fast cadence while user traffic is
//! flowing or a path is suspect, and back off when the session has been
//! idle for [`IDLE_AFTER`]. While idle, only the active path is pinged,
//! at [`IDLE_INTERVAL`] — standby paths are not pinged until traffic
//! resumes.
//!
//! Detection-lag tradeoff, stated openly:
//! * The server closes any transport it receives no session frame on
//!   for 30 s (`bootstrap.rs`, transport recv timeout). An idle
//!   25 s ping on the active path leaves only 5 s of slack, so a
//!   Doze/scheduler stall past the deadline can kill even the active
//!   path; the session then has to re-establish. 25 s is the
//!   WireGuard-recommended keepalive for the same reason (just under
//!   the shortest common NAT timeout, ~30 s) — it is the longest
//!   cadence that still keeps the mapping and the server transport
//!   alive, not a comfortable one.
//! * Standby paths go silent while idle, so the server reaps them
//!   after 30 s. They stay in the client's transport list as
//!   unverified until traffic resumes, when the fast cadence restarts
//!   and the existing eviction logic (consecutive ping failures /
//!   pong silence) removes the dead ones and the path supervisor
//!   re-dials direct paths. A failover that happens while idle may
//!   briefly try a reaped standby; the send/recv failure paths
//!   already remove a failed candidate and try the next one, so this
//!   costs one failed attempt, not a blackhole. QUIC transport
//!   keepalives (also 25 s) keep the underlying QUIC connections
//!   themselves alive while idle, so a standby can be re-pinged on
//!   demand without a fresh handshake.

use std::time::{Duration, Instant};

/// No user traffic (and no transport churn) for this long => idle.
pub const IDLE_AFTER: Duration = Duration::from_secs(60);

/// Heartbeat interval while idle. Deliberately 25 s, not longer: see
/// the module docs — the server reaps a silent transport at 30 s.
pub const IDLE_INTERVAL: Duration = Duration::from_secs(25);

/// True when the session has been idle long enough to back off:
/// no user traffic since `last_traffic` and no transport added or
/// removed since `last_transport_change`.
pub fn is_idle(last_traffic: Instant, last_transport_change: Instant, now: Instant) -> bool {
    now.duration_since(last_traffic) >= IDLE_AFTER
        && now.duration_since(last_transport_change) >= IDLE_AFTER
}

/// Pong-silence threshold for a heartbeat interval: three missed
/// intervals means the path is blackholed (15 s at the 5 s cadence,
/// 75 s at the 25 s idle cadence).
pub fn pong_silence_timeout(interval: Duration) -> Duration {
    interval * 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_requires_sixty_seconds_of_quiet() {
        let now = Instant::now();
        let quiet = now - Duration::from_secs(61);
        assert!(is_idle(quiet, quiet, now));
        // Recent traffic keeps the fast cadence even if the transport
        // set has been stable for hours.
        assert!(!is_idle(now, quiet, now));
        // Recent transport churn keeps the fast cadence even with no
        // traffic: a just-added path has not proven itself yet.
        assert!(!is_idle(quiet, now, now));
        // Exactly at the boundary counts as idle.
        let boundary = now - IDLE_AFTER;
        assert!(is_idle(boundary, boundary, now));
    }

    #[test]
    fn pong_silence_timeout_is_three_intervals() {
        assert_eq!(
            pong_silence_timeout(Duration::from_secs(5)),
            Duration::from_secs(15)
        );
        assert_eq!(
            pong_silence_timeout(IDLE_INTERVAL),
            Duration::from_secs(75)
        );
    }
}
