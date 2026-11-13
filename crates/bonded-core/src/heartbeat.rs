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
//! While ACTIVE, standby paths are pinged at the slower
//! [`STANDBY_PING_INTERVAL`] (4.74), not on every 10 s tick: pinging
//! every path every tick multiplies the wakeup rate by the transport
//! count (overnight 2026-11-11/12: ~6 paths x 360 ticks/h = 2,128
//! pings/h). The standby cadence is 60 s, just under the 90 s server
//! reap, so a live standby is never reaped.
//!
//! The idle gate itself is traffic-based by default, but a session
//! whose screen is off AND battery saver is on goes idle regardless
//! of traffic (4.73): the 6a's own background traffic resets the
//! 180 s timer constantly, so the traffic gate alone never fired
//! overnight. Screen state is the honest idle signal; background
//! system traffic is not user traffic.
//!
//! Shared idle-cadence contract (4.72): the idle heartbeat, the QUIC
//! keepalive, and the WireGuard persistent keepalive all run at
//! [`IDLE_INTERVAL`] (60 s), and the server reaps a silent transport
//! at [`SERVER_TRANSPORT_RECV_TIMEOUT`] (90 s). The heartbeat stays
//! comfortably below the reap so a live session is never reaped:
//! 60 s vs 90 s leaves 30 s of slack for a Doze/scheduler stall (the
//! old 25 s vs 30 s left only 5 s). The QUIC keepalive must stay
//! below quinn's max idle timeout, so both endpoints set
//! [`QUIC_MAX_IDLE_TIMEOUT`] (120 s) — the effective timeout is the
//! minimum of the two, so one side alone is not enough. A single
//! missed keepalive therefore cannot kill a connection.
//!
//! Detection-lag tradeoff, stated openly:
//! * The server closes any transport it receives no session frame on
//!   for 90 s (`bootstrap.rs`, transport recv timeout). An idle
//!   60 s ping on the active path leaves 30 s of slack, so a
//!   Doze/scheduler stall past the deadline can still kill even the
//!   active path; the session then has to re-establish. 60 s exceeds
//!   the shortest common NAT UDP timeouts (~30 s), so a mapping may
//!   expire between heartbeats — but the client re-creates it on each
//!   heartbeat, and in idle mode the server sends nothing unsolicited
//!   (only PONG replies, which follow the heartbeat), so an expired
//!   mapping costs a re-created mapping, not a dead session. While
//!   active the cadence is 10 s, well under any NAT timeout.
//! * Standby paths go silent while idle, so the server reaps them
//!   after 90 s. They stay in the client's transport list as
//!   unverified until traffic resumes, when the fast cadence restarts
//!   and the existing eviction logic (consecutive ping failures /
//!   pong silence) removes the dead ones and the path supervisor
//!   re-dials direct paths. A failover that happens while idle may
//!   briefly try a reaped standby; the send/recv failure paths
//!   already remove a failed candidate and try the next one, so this
//!   costs one failed attempt, not a blackhole. QUIC transport
//!   keepalives (also 60 s) keep the underlying QUIC connections
//!   themselves alive while idle, so a standby can be re-pinged on
//!   demand without a fresh handshake.
//! * Dead sessions linger longer on the server: a dead transport is
//!   reaped after 90 s instead of 30 s, so the server holds
//!   per-session state up to 3x as long. Bounded and acceptable —
//!   the per-session state is small, and the dial-back push limiter
//!   (4.66) already caps the churn a flapping consumer can cause.

use std::time::{Duration, Instant};

/// No user traffic (and no transport churn) for this long => idle.
pub const IDLE_AFTER: Duration = Duration::from_secs(60);

/// No user traffic for this long => the heartbeat goes idle (4.65).
/// Longer than [`IDLE_AFTER`]: background app traffic (a packet
/// every few seconds) resets the 60 s gate constantly, so the
/// heartbeat flaps between the 10 s active and 25 s idle cadences
/// and averages ~16 s instead of 25 s. 180 s is long enough to ride
/// out a sync burst but short enough that a genuinely quiet session
/// backs off. Transport churn does NOT reset this threshold — churn
/// affects only the new path's probing, not the global cadence.
pub const HEARTBEAT_IDLE_AFTER: Duration = Duration::from_secs(180);

/// Consecutive heartbeat ticks with traffic observed required to
/// leave the idle cadence (4.65). A single background packet spans
/// one tick only, so it cannot re-arm the 10 s all-paths heartbeat;
/// sustained traffic spans two or more.
const HEARTBEAT_ACTIVE_TICKS: u32 = 2;

/// Heartbeat interval while idle (4.72). 60 s, not 25 s: the server
/// reaps a silent transport at [`SERVER_TRANSPORT_RECV_TIMEOUT`]
/// (90 s), so a 60 s ping leaves 30 s of slack for a
/// Doze/scheduler stall (the old 25 s vs 30 s left only 5 s).
/// The QUIC keepalive ([`QUIC_KEEPALIVE_INTERVAL`]) and the
/// WireGuard persistent keepalive ([`WG_KEEPALIVE_INTERVAL`]) run at
/// the same cadence, so no transport wakes the radio more often than
/// the heartbeat itself.
pub const IDLE_INTERVAL: Duration = Duration::from_secs(60);

/// Server-side transport reap (4.72): a transport the server
/// receives no session frame on for this long is closed. Raised from
/// 30 s to 90 s so the idle heartbeat ([`IDLE_INTERVAL`], 60 s)
/// keeps a 30 s margin. Dead sessions linger at most 90 s —
/// bounded, and the server's per-session state is small. Used by
/// `bootstrap.rs` (websocket session loop); QUIC transports are
/// reaped by quinn's max idle timeout ([`QUIC_MAX_IDLE_TIMEOUT`])
/// instead, and TCP/WireGuard loops have no recv timeout of their
/// own.
pub const SERVER_TRANSPORT_RECV_TIMEOUT: Duration = Duration::from_secs(90);

/// QUIC keepalive interval (4.72). Matched to [`IDLE_INTERVAL`]
/// (60 s) so a QUIC connection wakes the radio no more often than
/// the session heartbeat. Must stay below [`QUIC_MAX_IDLE_TIMEOUT`]
/// on BOTH endpoints — quinn takes the minimum, so one side alone
/// is not enough. Quinn applies this at connection setup and offers
/// no dynamic adjustment, so this is the idle cadence as well as
/// the active one.
pub const QUIC_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);

/// Quinn max idle timeout (4.72). 120 s — twice the keepalive, so a
/// single missed keepalive (or a scheduling stall up to 60 s) cannot
/// kill a connection. Set explicitly on every quinn TransportConfig
/// that carries a 60 s keepalive (client, server, peer-relay
/// listener): the default is 30 s (RFC 9308 § 3.2), which would kill
/// an idle connection before its first 60 s keepalive.
pub const QUIC_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// WireGuard persistent keepalive interval (4.72). Matched to
/// [`IDLE_INTERVAL`] (60 s) so a WireGuard transport wakes the radio
/// no more often than the session heartbeat. 60 s exceeds the
/// shortest NAT UDP timeouts (~30 s), so a mapping may expire
/// between heartbeats — but the client re-creates it on each
/// heartbeat, and in idle mode the server sends nothing unsolicited
/// (only PONG replies, which follow the heartbeat), so an expired
/// mapping costs a re-created mapping, not a dead session.
pub const WG_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);

/// True when the session has been idle long enough to back off:
/// no user traffic since `last_traffic` and no transport added or
/// removed since `last_transport_change`.
pub fn is_idle(last_traffic: Instant, last_transport_change: Instant, now: Instant) -> bool {
    now.duration_since(last_traffic) >= IDLE_AFTER
        && now.duration_since(last_transport_change) >= IDLE_AFTER
}

/// Standby-ping interval while active (4.74 / Fix B). 60 s — equal
/// to [`IDLE_INTERVAL`] and just under
/// [`SERVER_TRANSPORT_RECV_TIMEOUT`] (90 s), so a standby pinged at
/// this cadence is never reaped by the server. While the session is
/// active the active path is pinged every 10 s but each standby only
/// every 60 s: with N transports the ping rate drops from 360*N/h
/// to 360 + 60*(N-1)/h (N=6: 2,160/h → 660/h). The 30 s of slack
/// covers a Doze/scheduler stall, exactly as the idle heartbeat does.
pub const STANDBY_PING_INTERVAL: Duration = Duration::from_secs(60);

/// True when a standby path is due its (slower) ping: at least
/// [`STANDBY_PING_INTERVAL`] since its last ping. Pure, so the
/// workers' standby-ping decision is unit-testable without a
/// session. The workers reset the timer whenever standbys are
/// pinged, and also when the transport set changes, so a newly
/// added standby is pinged on the next tick instead of waiting out
/// a full 60 s before proving itself.
pub fn standby_ping_due(last_standby_ping: Instant, now: Instant) -> bool {
    now.duration_since(last_standby_ping) >= STANDBY_PING_INTERVAL
}

/// Next heartbeat-idle state, with hysteresis (4.65). Pure, so the
/// worker's cadence flip is unit-testable without a session. This is
/// the heartbeat cadence's own idle gate — traffic-only, decoupled
/// from transport churn. Parking and peer pacing keep the 60 s
/// churn-aware [`is_idle`]; only the heartbeat cadence uses this.
///
/// - Go idle after [`HEARTBEAT_IDLE_AFTER`] of no user traffic.
///   The active cadence (10 s) and idle cadence (60 s) are
///   unchanged; only WHEN the mode switches changes.
/// - Go active only after sustained traffic: `traffic_ticks`
///   consecutive ticks with traffic observed (the worker counts a
///   tick when `last_traffic` advanced since the previous tick).
///   A lone background packet does not re-arm the 10 s heartbeat.
/// - Screen-off + battery saver (4.73 / Fix A) forces idle
///   regardless of traffic, and keeps the heartbeat idle while it
///   holds: `screen_off_and_saver` true => idle, full stop. The
///   180 s traffic rule above is the fallback for the screen-on
///   (or saver-off) case. When the screen turns back on (or saver
///   goes off) the traffic rule resumes, and background traffic —
///   which keeps `traffic_ticks` high — returns the heartbeat to
///   the active cadence on the next tick.
pub fn next_heartbeat_idle(
    currently_idle: bool,
    last_traffic: Instant,
    traffic_ticks: u32,
    now: Instant,
    screen_off_and_saver: bool,
) -> bool {
    // 4.73: screen off + battery saver is the honest idle signal —
    // background traffic must not keep the 10 s cadence alive.
    if screen_off_and_saver {
        return true;
    }
    if currently_idle {
        traffic_ticks < HEARTBEAT_ACTIVE_TICKS
    } else {
        now.duration_since(last_traffic) >= HEARTBEAT_IDLE_AFTER
    }
}

/// Pong-silence threshold for a heartbeat interval: three missed
/// intervals means the path is blackholed (15 s at the 5 s cadence,
/// 180 s at the 60 s idle cadence).
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
            Duration::from_secs(180)
        );
    }

    #[test]
    fn idle_cadence_contract_is_consistent() {
        // 4.72: the idle heartbeat must stay comfortably below the
        // server reap, and the QUIC keepalive below the max idle
        // timeout, so a live session is never reaped and a single
        // missed keepalive cannot kill a QUIC connection. The
        // WireGuard keepalive matches the heartbeat so no transport
        // wakes the radio more often than the heartbeat itself.
        // Exact values are pinned: changing any of them is a
        // protocol decision, not a tune-up.
        assert_eq!(IDLE_INTERVAL, Duration::from_secs(60));
        assert_eq!(SERVER_TRANSPORT_RECV_TIMEOUT, Duration::from_secs(90));
        assert_eq!(QUIC_KEEPALIVE_INTERVAL, Duration::from_secs(60));
        assert_eq!(QUIC_MAX_IDLE_TIMEOUT, Duration::from_secs(120));
        assert_eq!(WG_KEEPALIVE_INTERVAL, Duration::from_secs(60));
        // 4.74: the standby ping cadence matches the idle heartbeat
        // and stays below the server reap with the same 30 s slack.
        assert_eq!(STANDBY_PING_INTERVAL, IDLE_INTERVAL);
        assert!(STANDBY_PING_INTERVAL < SERVER_TRANSPORT_RECV_TIMEOUT);
        assert!(
            SERVER_TRANSPORT_RECV_TIMEOUT - STANDBY_PING_INTERVAL >= Duration::from_secs(30),
            "30 s of slack for a Doze/scheduler stall"
        );
        assert!(IDLE_INTERVAL < SERVER_TRANSPORT_RECV_TIMEOUT);
        assert!(
            SERVER_TRANSPORT_RECV_TIMEOUT - IDLE_INTERVAL >= Duration::from_secs(30),
            "30 s of slack for a Doze/scheduler stall"
        );
        assert_eq!(QUIC_KEEPALIVE_INTERVAL, IDLE_INTERVAL);
        assert!(QUIC_KEEPALIVE_INTERVAL < QUIC_MAX_IDLE_TIMEOUT);
        assert!(QUIC_MAX_IDLE_TIMEOUT >= QUIC_KEEPALIVE_INTERVAL * 2);
        assert_eq!(WG_KEEPALIVE_INTERVAL, IDLE_INTERVAL);
    }

    #[test]
    fn heartbeat_idle_uses_traffic_only_with_hysteresis() {
        let now = Instant::now();
        // Active -> idle needs 180 s of no traffic, not 60 s.
        let quiet_60 = now - Duration::from_secs(61);
        assert!(
            !next_heartbeat_idle(false, quiet_60, 0, now, false),
            "60 s quiet is not idle for the heartbeat"
        );
        let quiet_180 = now - HEARTBEAT_IDLE_AFTER;
        assert!(next_heartbeat_idle(false, quiet_180, 0, now, false));
        // A single tick with traffic does not re-arm the heartbeat.
        assert!(
            next_heartbeat_idle(true, now, 1, now, false),
            "one traffic tick keeps the heartbeat idle"
        );
        // Sustained traffic (two consecutive ticks) goes active.
        assert!(!next_heartbeat_idle(true, now, 2, now, false));
        assert!(!next_heartbeat_idle(true, now, 5, now, false));
        // Idle with no traffic stays idle regardless of the count.
        assert!(next_heartbeat_idle(true, quiet_180, 0, now, false));
    }

    #[test]
    fn screen_off_and_saver_forces_idle_despite_traffic() {
        // 4.73: the overnight failure — background traffic flows
        // constantly, so the 180 s traffic gate never fires. Screen
        // off + battery saver must force idle even with fresh
        // traffic on every tick.
        let now = Instant::now();
        // Active with traffic this very tick: forced idle.
        assert!(next_heartbeat_idle(false, now, 5, now, true));
        // Idle with sustained traffic: stays idle while the
        // screen-off+saver condition holds.
        assert!(next_heartbeat_idle(true, now, 5, now, true));
        // Same inputs without the condition: traffic keeps it active.
        assert!(!next_heartbeat_idle(false, now, 5, now, false));
        assert!(!next_heartbeat_idle(true, now, 5, now, false));
        // Screen on again (or saver off): the traffic gate resumes —
        // an idle session with sustained traffic goes active on the
        // next tick, which is how the heartbeat recovers when the
        // user picks the phone up.
        assert!(!next_heartbeat_idle(true, now, 2, now, false));
    }

    #[test]
    fn standby_ping_due_at_sixty_second_cadence() {
        // 4.74: standbys are pinged every 60 s while active, not
        // every 10 s tick.
        let now = Instant::now();
        let pinged_59s_ago = now - Duration::from_secs(59);
        assert!(!standby_ping_due(pinged_59s_ago, now));
        let pinged_60s_ago = now - Duration::from_secs(60);
        assert!(standby_ping_due(pinged_60s_ago, now));
        let pinged_61s_ago = now - Duration::from_secs(61);
        assert!(standby_ping_due(pinged_61s_ago, now));
        // Just pinged: not due.
        assert!(!standby_ping_due(now, now));
    }
}
