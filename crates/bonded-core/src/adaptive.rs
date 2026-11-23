//! Adaptive traffic mode (4.99, proof of concept).
//!
//! Adaptive is a per-flow policy that composes the existing modes
//! ([`TrafficMode`]) — it does NOT replace them, and it does NOT
//! classify traffic by content. There is no DPI, no DNS snooping, no
//! content inspection: the policy reads only flow shape (bytes, age,
//! rate) and the per-transport signals the engine already carries
//! ([`PathSignal`]: grade, RTT, loss). What it does is decide, per
//! flow and over time, which of the existing placements the flow
//! should have.
//!
//! # The state machine
//!
//! A flow starts on a single leg — the best-graded transport
//! (lowest latency in practice), picked by the engine's
//! BestTransport ranking. As the flow reveals itself it is
//! classified:
//!
//! * **Bulk** (sustained high throughput, long-lived): promoted to
//!   [`TrafficMode::BandwidthBoost`] — spread across the top two
//!   graded transports. The promotion thresholds are
//!   [`BULK_BYTES`], [`BULK_MIN_AGE_MS`], and
//!   [`BULK_MIN_RATE_BYTES_PER_SEC`].
//! * **Interactive** (small, bursty, short): stays on the single
//!   lowest-latency leg. "Interactive" is the complement of bulk —
//!   a flow that never reaches the bulk thresholds never spreads.
//!
//! If the leg a flow is on degrades mid-flow (its grade drops by
//! [`DEGRADE_GRADE_DROP`] points from the grade recorded at the
//! last decision, or its loss rate reaches [`DEGRADE_LOSS_RATE`]
//! having been below it), the flow moves to the next-best leg — or
//! is briefly duplicated ([`TrafficMode::Redundant`]) through the
//! handover for [`DUPLICATE_WINDOW_MS`], so there is no gap, and
//! settles on the new leg when the window expires. A spread flow
//! does not duplicate: it already covers two legs, so a degraded
//! leg is replaced by re-ranking the spread set.
//!
//! Per-domain/IP rules still win: if a rule pins a flow to a mode,
//! [`AdaptiveFlow::decide`] returns [`AdaptiveDecision::Pinned`]
//! and the policy makes no decision — the caller uses the rule's
//! mode. Adaptive is the default policy for flows with no explicit
//! rule.
//!
//! # Hysteresis (first-class)
//!
//! A flow must not be re-classified or moved more often than
//! [`MIN_DECISION_INTERVAL_MS`] — so grade flapping does not cause
//! flow flapping — and a move requires the best alternative to beat
//! the current leg by [`MOVE_GRADE_GAP`] grade points, so a move
//! that gains nothing never happens. The stability weight and the
//! 99 exploration prior already damp grade movement; the policy
//! adds its own damping on top. Settling a duplication window is
//! not a new decision (it completes the previous one), so it is not
//! gated by the interval.
//!
//! The interval gates changes *since the last change*: the first
//! change a flow ever makes is gated only by the classification
//! criteria themselves (bulk already needs [`BULK_MIN_AGE_MS`] of
//! age; degradation needs a real drop), not by the interval. That
//! is what [`AdaptiveFlow::last_change_ms`] being `None` means.
//!
//! # What this is NOT
//!
//! This module is the policy + its simulation tests, and (since
//! 4.100) the per-flow table the pin points consult. It is still
//! data-only: it knows nothing about transports, sessions, or the
//! UI — only flow placement, observations, and the signals the
//! caller hands it. The caller is responsible for feeding the
//! policy: [`AdaptiveFlowTable::pin_for_packet`] takes one packet,
//! resolves its mode through the engine, and — only when the mode
//! is [`TrafficMode::Adaptive`] — consults one [`AdaptiveFlow`]
//! for that flow (created at the same point the mode is resolved
//! today) with the flow's cumulative bytes and the current
//! per-transport signals (built the same way the FFI's
//! `path_signals` builds them — grades from
//! `path_grades_snapshot`, RTT from the last heartbeat pong, loss
//! from the QUIC counters), and applies the returned
//! [`AdaptiveDecision`]. Times are milliseconds on a monotonic
//! clock supplied by the caller, so the policy is testable without
//! wall time. `decide` runs on every packet of an adaptive flow,
//! not just on a poll tick: the hysteresis interval makes that
//! cheap and stable (a packet inside the window returns
//! [`AdaptiveDecision::Stay`]), and it is what lets a bulk
//! promotion or a handover land on the packet that crosses the
//! threshold instead of waiting for the next tick.
//!
//! Decision logging (4.101): [`AdaptiveFlowTable::pin_for_packet`]
//! logs every decision change — a promotion, a move, a handover —
//! at INFO through `tracing`, so it reaches logcat on Android (the
//! FFI's `LogcatSubscriber` passes INFO and above) and the CLI's
//! stdout logger. One line per change, never per packet:
//! [`AdaptiveDecision::Stay`] is never logged. The line is
//! `adaptive decision flow=0x… decision=… bytes_total=… age_ms=…`;
//! the flow key is the direction-independent key below, so one
//! flow's lines correlate across its lifetime.
//!
//! Inbound bytes (4.101): a flow's cumulative bytes count both
//! directions — the pin points feed outbound lengths through
//! [`AdaptiveFlowTable::pin_for_packet`] and inbound lengths
//! through [`AdaptiveFlowTable::note_inbound`]. The table is keyed
//! by the direction-independent [`flow_key`] (canonical endpoint
//! order), so a reply matches the entry its outbound packets
//! created; a packet whose tuple cannot be parsed falls back to
//! [`flow_hash`].
//!
//! # Open questions (for the real implementation, not this POC)
//!
//! * **Demotion (4.101, resolved):** a spread flow that moves no
//!   bytes for [`DEMOTE_IDLE_MS`] (30 s) demotes back to a single
//!   leg — the best leg by the current ranking — as an
//!   [`AdaptiveDecision::MoveTo`]. The quiet period is measured
//!   from the last `decide` that saw the byte total grow, so the
//!   packet that ends a quiet period still sees the quiet that
//!   preceded it. A demotion is a decision change, so it is gated
//!   by the same [`MIN_DECISION_INTERVAL_MS`] hysteresis as every
//!   other change; in practice the 30 s threshold (6x the
//!   interval) is what damps it — any change implies recent
//!   activity, so the interval never binds a demotion. A demoted
//!   flow must re-clear the bulk floors to promote again.
//! * **Cold start:** a flow created before any signals exist starts
//!   on leg 0. When signals first arrive and another leg is clearly
//!   ahead (by [`MOVE_GRADE_GAP`]), the policy (re)places it — see
//!   the `first_signals` arm in [`AdaptiveFlow::decide`].
//! * **Mid-handover degradation:** a leg degrading *during* a
//!   500 ms duplication window is not re-evaluated until the window
//!   settles. The window is short enough that this is acceptable
//!   for the POC; the real implementation may want to re-check.

use std::collections::HashMap;

use crate::flow::{flow_hash, flow_key};
use crate::traffic_mode::{PathSignal, TrafficMode, TrafficModeEngine};

/// A flow is bulk once it has moved at least this many bytes
/// (1 MiB). A 1 MiB download is small by modern standards, but the
/// threshold is about *sustained* movement, not size alone — the
/// age and rate floors below are what keep a short burst from
/// promoting. Tunable.
pub const BULK_BYTES: u64 = 1_048_576;

/// ... and is at least this old (2 s). A 1 MiB burst in 100 ms is
/// a spike, not a bulk flow — the flow must sustain itself long
/// enough to prove it is bulk before it is spread.
pub const BULK_MIN_AGE_MS: u64 = 2_000;

/// ... and sustains at least this rate (128 KiB/s, ≈ 1 Mbit/s). A
/// flow that moves 1 MiB over 10 s (100 KiB/s) is a slow trickle,
/// not a bulk download — spreading it gains nothing and costs
/// reordering. Tunable.
pub const BULK_MIN_RATE_BYTES_PER_SEC: u64 = 131_072;

/// At most one strategy change per flow per this interval (5 s).
/// Grade flapping faster than this cannot move the flow: the
/// second, third, and fourth "move" in the window all return
/// [`AdaptiveDecision::Stay`].
pub const MIN_DECISION_INTERVAL_MS: u64 = 5_000;

/// A leg is degraded when its grade falls this many points (20)
/// from the grade recorded at the last decision. A slow drift and
/// a sharp drop are both caught — the baseline is only re-set when
/// a decision is made, so a cumulative 20-point fall from the last
/// placement counts even if it arrived in small steps.
pub const DEGRADE_GRADE_DROP: u8 = 20;

/// ... or its loss rate reaches this level (10%), having been
/// below it when the baseline was recorded. A leg that was already
/// lossy at placement does not re-trigger on the same loss.
pub const DEGRADE_LOSS_RATE: f64 = 0.10;

/// A move requires the best alternative to beat the current leg by
/// at least this many grade points (10). A degraded leg whose best
/// alternative is only 5 points better is not worth moving from —
/// the move gains nothing and costs a handover.
pub const MOVE_GRADE_GAP: u8 = 10;

/// A loss-driven move is allowed when the best alternative's loss
/// rate is at or below this level (2%) while the current leg is at
/// or above [`DEGRADE_LOSS_RATE`] (10%). The grade gap does not
/// apply to a loss-driven move: the grade has not caught up with
/// the loss yet (the Dart layer recomputes grades once a second,
/// so a fresh loss spike is visible in the loss counters before it
/// is visible in the grade), and comparing grades would block a
/// move the loss data already justifies.
pub const MOVE_LOSS_OK_RATE: f64 = 0.02;

/// How long a degradation handover duplicates the flow
/// ([`TrafficMode::Redundant`]) before settling on the new leg
/// (500 ms). Brief by design: duplication is 2x traffic, so it
/// covers the gap and then stops.
pub const DUPLICATE_WINDOW_MS: u64 = 500;

/// How long a spread flow must move no bytes before it demotes
/// back to a single leg (30 s, 4.101). A bulk flow silent that
/// long is done or stalled, not bursty — a download that pauses
/// 30 s is not coming back as the same burst — so demoting costs
/// nothing while it is quiet and saves the reordering cost when it
/// resumes. 30 s is 15x the [`BULK_MIN_AGE_MS`] promotion floor
/// and half the session idle interval (60 s, `heartbeat`
/// `IDLE_INTERVAL`): long enough that TCP think time, a slow
/// server, or a user reading never trips it, short enough that a
/// finished download demotes promptly. A demoted flow must
/// re-clear the bulk floors to promote again, so the quiet period
/// itself — not the hysteresis interval — is what prevents
/// flapping.
pub const DEMOTE_IDLE_MS: u64 = 30_000;

/// The placement a flow currently has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Strategy {
    /// On one transport (index into the transport set). The initial
    /// placement for every flow, and the settled placement after a
    /// handover.
    Single(usize),
    /// Spread across these transports (top two by BestTransport
    /// ranking) — the [`TrafficMode::BandwidthBoost`] placement for
    /// a bulk flow.
    Spread(Vec<usize>),
    /// Duplicating on `from` and `to` until `until_ms`, then the
    /// caller re-asks and the policy settles on `to`. The
    /// [`TrafficMode::Redundant`] placement, used briefly through a
    /// handover.
    Duplicating {
        from: usize,
        to: usize,
        until_ms: u64,
    },
}

/// What the policy tells the caller to do with one flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdaptiveDecision {
    /// No change: keep the current placement.
    Stay,
    /// The flow is pinned by an explicit per-domain/IP rule; the
    /// policy makes no decision — the caller uses the rule's mode.
    Pinned,
    /// Move the flow's single leg to this transport. Returned when
    /// a duplication window expires and the handover settles on the
    /// new leg.
    MoveTo(usize),
    /// A bulk flow: spread it across these transports (top two by
    /// BestTransport ranking) — the
    /// [`TrafficMode::BandwidthBoost`] placement.
    PromoteToSpread(Vec<usize>),
    /// Duplicate the flow on these transports until `until_ms`, then
    /// re-ask: the policy settles the handover on the next decide
    /// after the window. The [`TrafficMode::Redundant`] placement,
    /// used briefly through a degradation handover.
    DuplicateThrough { legs: Vec<usize>, until_ms: u64 },
}

/// One flow's observed shape, as the caller reports it each tick.
/// Cumulative: the policy only needs the total, not a delta.
#[derive(Clone, Copy, Debug, Default)]
pub struct FlowObservation {
    /// Cumulative bytes observed on this flow so far (both
    /// directions, as the caller counts them).
    pub bytes_total: u64,
}

/// One flow's adaptive state. Data-only, like
/// [`TrafficModeEngine`]: it knows nothing about transports,
/// sessions, or the UI — only the flow's placement, its
/// observations, and the signals the caller hands it.
#[derive(Clone, Debug)]
pub struct AdaptiveFlow {
    /// The placement the flow currently has.
    pub strategy: Strategy,
    /// When the flow was created (ms, caller-supplied clock).
    pub started_ms: u64,
    /// When the strategy last changed. `None` until the first
    /// change — the first change is gated only by the
    /// classification criteria, not by the hysteresis interval.
    pub last_change_ms: Option<u64>,
    /// The current single leg's grade at the last decision (the
    /// baseline the degradation check measures against). `None`
    /// while the flow is spread (the spread set is re-ranked, not
    /// baselined) or while no grade has been observed.
    pub recorded_grade: Option<u8>,
    /// The current single leg's loss rate at the last decision.
    pub recorded_loss: Option<f64>,
    /// The explicit per-domain/IP rule mode governing this flow, if
    /// any. Set at creation; when present, [`AdaptiveFlow::decide`]
    /// always returns [`AdaptiveDecision::Pinned`].
    pub pinned_mode: Option<TrafficMode>,
    /// Whether this flow has ever seen a non-empty signal set. A
    /// flow created before any signals exist starts on leg 0; the
    /// first call that brings signals (re)places it if another leg
    /// is clearly ahead.
    seen_signals: bool,
    /// The byte total `decide` last saw, and when it last grew —
    /// the activity clock for spread demotion (4.101). A flow that
    /// keeps moving bytes advances `last_activity_ms` on every
    /// decide; a flow that goes quiet keeps its old timestamp, so
    /// the Spread arm can demote it after [`DEMOTE_IDLE_MS`].
    /// Initialized to the creation time: a flow that never moves
    /// any bytes is quiet from birth, but it also never promotes,
    /// so demotion never applies to it.
    last_bytes_total: u64,
    last_activity_ms: u64,
}

impl AdaptiveFlow {
    /// Create a flow's adaptive state. The initial leg is the best
    /// transport by the engine's BestTransport ranking (grade, then
    /// RTT, then loss); with no signals yet it is leg 0. The
    /// recorded baseline is the initial leg's signals, so a later
    /// drop is measured from the placement the flow started on.
    /// `pinned_mode` is the explicit rule mode for this flow, if
    /// any — pass `None` for a flow governed by the default policy.
    pub fn new(signals: &[PathSignal], now_ms: u64, pinned_mode: Option<TrafficMode>) -> Self {
        let first_leg = best_transport_ranking(signals)
            .into_iter()
            .next()
            .unwrap_or(0);
        let mut flow = AdaptiveFlow {
            strategy: Strategy::Single(first_leg),
            started_ms: now_ms,
            last_change_ms: None,
            recorded_grade: None,
            recorded_loss: None,
            pinned_mode,
            seen_signals: !signals.is_empty(),
            last_bytes_total: 0,
            last_activity_ms: now_ms,
        };
        flow.set_baseline(signals, first_leg);
        flow
    }

    /// The transport index the flow is currently on, when it has a
    /// single placement. `None` while spread (it is on several) or
    /// while duplicating (it is on both `from` and `to`).
    pub fn current_leg(&self) -> Option<usize> {
        match self.strategy {
            Strategy::Single(leg) => Some(leg),
            _ => None,
        }
    }

    /// Decide what to do with this flow, given its cumulative
    /// observations and the current per-transport signals. Updates
    /// the flow's state to match the returned decision, so repeated
    /// calls are consistent. See the module docs for the order the
    /// checks run in: pinned → settle a duplication window →
    /// hysteresis → degradation → bulk promotion → spread re-rank
    /// or demotion when quiet.
    pub fn decide(
        &mut self,
        obs: &FlowObservation,
        signals: &[PathSignal],
        now_ms: u64,
    ) -> AdaptiveDecision {
        // 1. Pinned: an explicit rule governs this flow. The policy
        // makes no decision at all — it does not even look at the
        // signals.
        if self.pinned_mode.is_some() {
            return AdaptiveDecision::Pinned;
        }

        // Activity clock (4.101): whether this flow has gone quiet
        // is measured from the last decide that saw its byte total
        // grow — computed BEFORE this call's total is recorded, so
        // the packet that ends a quiet period still sees the quiet
        // that preceded it. The update runs here, before every
        // early return below, so a flow whose packets keep arriving
        // inside a hysteresis window still counts as active: only
        // a flow with no byte growth at all goes quiet.
        let quiet = now_ms.saturating_sub(self.last_activity_ms) >= DEMOTE_IDLE_MS;
        if obs.bytes_total > self.last_bytes_total {
            self.last_bytes_total = obs.bytes_total;
            self.last_activity_ms = now_ms;
        }

        // 2. Duplicating: inside the window, keep duplicating; past
        // it, settle on the new leg. Settling completes the
        // handover, so it is not gated by the hysteresis interval
        // and does not reset the interval clock.
        if let Strategy::Duplicating { from, to, until_ms } = self.strategy {
            if now_ms < until_ms {
                return AdaptiveDecision::DuplicateThrough {
                    legs: vec![from, to],
                    until_ms,
                };
            }
            self.strategy = Strategy::Single(to);
            self.set_baseline(signals, to);
            return AdaptiveDecision::MoveTo(to);
        }

        // 3. Hysteresis: at most one strategy change per
        // MIN_DECISION_INTERVAL_MS. The first change a flow ever
        // makes is exempt (last_change_ms is None) — it is gated
        // only by the classification criteria themselves.
        if let Some(last) = self.last_change_ms {
            if now_ms.saturating_sub(last) < MIN_DECISION_INTERVAL_MS {
                return AdaptiveDecision::Stay;
            }
        }

        // 4. Single leg: degradation, then bulk promotion.
        if let Strategy::Single(leg) = self.strategy {
            // Cold start: the flow was placed before any signals
            // existed. The first call that brings signals (re)places
            // it if another leg is clearly ahead — the initial leg
            // was a guess, not a measurement.
            let first_signals = !self.seen_signals && !signals.is_empty();
            if !signals.is_empty() {
                self.seen_signals = true;
            }
            if first_signals {
                if let Some(best) = self.best_alternative(leg, signals) {
                    if self.move_gap_ok(leg, best, signals) {
                        return self.start_handover(leg, best, signals, now_ms);
                    }
                }
            }

            if self.leg_degraded(leg, signals) {
                if let Some(best) = self.best_alternative(leg, signals) {
                    if self.move_gap_ok(leg, best, signals) {
                        return self.start_handover(leg, best, signals, now_ms);
                    }
                }
                // Degraded but no better leg (or the gap is too
                // small): stay, and re-baseline so the same drop
                // does not re-trigger on the next tick.
                self.set_baseline(signals, leg);
                return AdaptiveDecision::Stay;
            }

            if self.is_bulk(obs, now_ms) {
                let top_two = top_two_legs(signals);
                if top_two.len() >= 2 {
                    self.strategy = Strategy::Spread(top_two.clone());
                    self.last_change_ms = Some(now_ms);
                    self.recorded_grade = None;
                    self.recorded_loss = None;
                    return AdaptiveDecision::PromoteToSpread(top_two);
                }
            }
            return AdaptiveDecision::Stay;
        }

        // 5. Spread: demote when quiet, else re-rank the spread
        // set. A degraded leg is replaced by the new top two — no
        // duplication is needed, the flow already covers two legs
        // and the good one keeps carrying it.
        if let Strategy::Spread(legs) = &self.strategy {
            // Demotion (4.101): a spread flow that has moved no
            // bytes for DEMOTE_IDLE_MS goes back to a single leg —
            // the best one by the current ranking. A quiet flow
            // sends nothing to spread, so demoting saves the
            // reordering cost when it resumes. This is a decision
            // change, so the hysteresis gate above already applied;
            // in practice the 30 s quiet period (6x the interval)
            // is the damping, since any change implies recent
            // activity. A demoted flow must re-clear the bulk
            // floors to promote again.
            if quiet {
                let best = best_transport_ranking(signals)
                    .into_iter()
                    .next()
                    .unwrap_or(0);
                self.strategy = Strategy::Single(best);
                self.last_change_ms = Some(now_ms);
                self.set_baseline(signals, best);
                return AdaptiveDecision::MoveTo(best);
            }
            let top_two = top_two_legs(signals);
            if top_two.len() >= 2 && top_two != *legs {
                self.strategy = Strategy::Spread(top_two.clone());
                self.last_change_ms = Some(now_ms);
                return AdaptiveDecision::PromoteToSpread(top_two);
            }
            return AdaptiveDecision::Stay;
        }

        AdaptiveDecision::Stay
    }

    /// Is this flow bulk? Bytes, age, and rate must all clear their
    /// floors — a short burst is not bulk, and a slow trickle is not
    /// bulk either.
    fn is_bulk(&self, obs: &FlowObservation, now_ms: u64) -> bool {
        let age_ms = now_ms.saturating_sub(self.started_ms);
        if age_ms < BULK_MIN_AGE_MS || obs.bytes_total < BULK_BYTES {
            return false;
        }
        let age_secs = (age_ms / 1000).max(1);
        let rate = obs.bytes_total / age_secs;
        rate >= BULK_MIN_RATE_BYTES_PER_SEC
    }

    /// Has the current leg degraded since the baseline was recorded?
    /// A grade drop of [`DEGRADE_GRADE_DROP`] points, a loss rate
    /// reaching [`DEGRADE_LOSS_RATE`] having been below it, or the
    /// leg no longer existing in the signal set. An unknown grade
    /// is not a degradation — missing is unknown, never a
    /// fabricated 0 (the 4.49 discipline).
    fn leg_degraded(&self, leg: usize, signals: &[PathSignal]) -> bool {
        if signals.is_empty() {
            return false;
        }
        if leg >= signals.len() {
            return true;
        }
        let sig = signals[leg];
        let grade_drop = match (self.recorded_grade, sig.grade) {
            (Some(recorded), Some(current)) => {
                recorded.saturating_sub(current) >= DEGRADE_GRADE_DROP
            }
            _ => false,
        };
        let loss_spike = match sig.loss_rate {
            Some(loss) if loss.is_finite() => {
                loss >= DEGRADE_LOSS_RATE
                    && self.recorded_loss.map_or(true, |r| r < DEGRADE_LOSS_RATE)
            }
            _ => false,
        };
        grade_drop || loss_spike
    }

    /// The best transport other than `leg`, by the engine's
    /// BestTransport ranking. `None` when there is no other
    /// transport to move to.
    fn best_alternative(&self, leg: usize, signals: &[PathSignal]) -> Option<usize> {
        best_transport_ranking(signals)
            .into_iter()
            .find(|&i| i != leg)
    }

    /// Does moving to `best` gain anything over staying on `leg`?
    /// The best alternative must beat the current leg by
    /// [`MOVE_GRADE_GAP`] grade points, or — when the degradation
    /// is a loss spike the grade has not caught up with yet — the
    /// current leg must be lossy (at or above [`DEGRADE_LOSS_RATE`])
    /// while the candidate is clean (at or below
    /// [`MOVE_LOSS_OK_RATE`]). A leg that no longer exists always
    /// loses, and unknown grades defer to the ranking — the ranking
    /// already put `best` ahead on RTT/loss, so the move is
    /// trusted.
    fn move_gap_ok(&self, leg: usize, best: usize, signals: &[PathSignal]) -> bool {
        if leg >= signals.len() {
            return true;
        }
        let current = signals[leg];
        let candidate = signals[best];
        let grade_ok = match (current.grade, candidate.grade) {
            (Some(c), Some(b)) => b.saturating_sub(c) >= MOVE_GRADE_GAP,
            _ => true,
        };
        if grade_ok {
            return true;
        }
        match (current.loss_rate, candidate.loss_rate) {
            (Some(c), Some(b)) if c.is_finite() && b.is_finite() => {
                c >= DEGRADE_LOSS_RATE && b <= MOVE_LOSS_OK_RATE
            }
            _ => false,
        }
    }

    /// Begin a degradation handover: duplicate on the old and new
    /// legs until the window expires, then the caller re-asks and
    /// the policy settles. Records the new leg as the baseline (the
    /// flow is heading there) and starts the hysteresis clock.
    fn start_handover(
        &mut self,
        leg: usize,
        best: usize,
        signals: &[PathSignal],
        now_ms: u64,
    ) -> AdaptiveDecision {
        let until_ms = now_ms + DUPLICATE_WINDOW_MS;
        self.strategy = Strategy::Duplicating {
            from: leg,
            to: best,
            until_ms,
        };
        self.last_change_ms = Some(now_ms);
        self.set_baseline(signals, best);
        AdaptiveDecision::DuplicateThrough {
            legs: vec![leg, best],
            until_ms,
        }
    }

    /// Record a leg's current signals as the baseline the
    /// degradation check measures against.
    fn set_baseline(&mut self, signals: &[PathSignal], leg: usize) {
        match signals.get(leg) {
            Some(sig) => {
                self.recorded_grade = sig.grade;
                self.recorded_loss = sig.loss_rate;
            }
            None => {
                self.recorded_grade = None;
                self.recorded_loss = None;
            }
        }
    }
}

/// The engine's BestTransport ranking for the signal set: grade
/// first (higher wins), then RTT, then loss — the same ranking the
/// pin points use, so adaptive composes the existing modes rather
/// than re-implementing their order. An empty signal set ranks
/// nothing (there are no transports to rank); the engine's
/// `order_candidates` would return the active transport as a
/// fallback, which is not a real leg. The flow hash is 0 — the
/// ranking ignores it.
fn best_transport_ranking(signals: &[PathSignal]) -> Vec<usize> {
    if signals.is_empty() {
        return Vec::new();
    }
    TrafficModeEngine::default().order_candidates(
        TrafficMode::BestTransport,
        0,
        signals.len(),
        0,
        signals,
    )
}

/// The top two legs by BestTransport ranking — the spread set for a
/// bulk flow. Fewer than two legs means the flow cannot spread.
fn top_two_legs(signals: &[PathSignal]) -> Vec<usize> {
    best_transport_ranking(signals)
        .into_iter()
        .take(2)
        .collect()
}

/// What the pin points do with one packet.
///
/// `candidates` is the ordered try-list (first entry tried first;
/// on send failure the caller tries the next, the existing failover
/// discipline). `duplicate` says the packet is fanned out to the
/// candidate set instead of tried in turn — the redundant
/// discipline — and the caller flags the frame
/// `FLAG_REDUNDANT` so the server fans the return traffic out the
/// same way. It is true for a flow in [`TrafficMode::Redundant`]
/// and for an adaptive flow inside a degradation handover
/// ([`AdaptiveDecision::DuplicateThrough`]); every other adaptive
/// placement is a try-list, not a fan-out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptivePin {
    pub candidates: Vec<usize>,
    pub duplicate: bool,
}

/// One flow's entry in the table: its adaptive state, its
/// cumulative observed bytes (both directions — the uplink packet
/// lengths the pin point sees plus the return-path lengths fed
/// through [`AdaptiveFlowTable::note_inbound`]), and when it was
/// last seen (for eviction).
struct AdaptiveFlowEntry {
    flow: AdaptiveFlow,
    bytes_total: u64,
    last_seen_ms: u64,
}

/// The table key for a packet: the direction-independent
/// [`flow_key`] when the tuple parses, so an uplink packet and its
/// reply share one entry — that is what lets
/// [`AdaptiveFlowTable::note_inbound`] count a download's inbound
/// bytes toward the flow its outbound packets created. A packet
/// whose tuple cannot be parsed (truncated, non-IP) has no
/// canonical key and falls back to [`flow_hash`]; its two
/// directions key separately, so its inbound bytes are not
/// counted — an accepted corner, since the bulk thresholds are
/// about IP flows.
fn table_key(packet: &[u8]) -> u64 {
    flow_key(packet).unwrap_or_else(|| flow_hash(packet))
}

/// Maximum flows tracked per session (4.100). A phone VPN sees
/// hundreds of flows in a session; 4096 is headroom, not a target.
/// Past it the least-recently-seen flow is evicted — its next
/// packet just creates a fresh flow (a cold start on the best
/// leg), it is never dropped.
pub const ADAPTIVE_MAX_FLOWS: usize = 4096;

/// One [`AdaptiveFlow`] per flow, keyed by flow hash — the table
/// the two pin points share (4.100). The Linux client loop and the
/// Android worker both call [`AdaptiveFlowTable::pin_for_packet`]
/// for every packet, so the same adaptive application logic runs
/// in both places and the pin points cannot drift.
///
/// A flow's table entry is created on its first packet (on the
/// best-graded leg, or leg 0 with no signals yet) and fed on every
/// packet after that: the packet's length joins its cumulative
/// bytes and [`AdaptiveFlow::decide`] runs with the current
/// signals and the caller's monotonic clock. Flows whose resolved
/// mode is not adaptive never get an entry — a rule pinning a flow
/// to another mode is never touched by the policy, because the
/// table is never consulted for it.
#[derive(Default)]
pub struct AdaptiveFlowTable {
    flows: HashMap<u64, AdaptiveFlowEntry>,
}

impl AdaptiveFlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Flows currently tracked.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Pin one packet: the single entry point both pin points use.
    ///
    /// The engine resolves the packet's mode from its destination
    /// IP. When the mode is not [`TrafficMode::Adaptive`] the
    /// engine's own order stands untouched — `duplicate` is true
    /// exactly when the mode is [`TrafficMode::Redundant`] — so a
    /// per-domain/IP rule pinning a flow to another mode, or a
    /// non-adaptive default mode, is never overridden by the
    /// policy. When the mode IS adaptive, the flow's entry decides
    /// and the decision is applied: `Stay` keeps the current
    /// placement (first candidate is the current leg, the rest are
    /// the best-transport ranking as failover); `MoveTo(leg)`
    /// re-pins the flow to that leg; `PromoteToSpread(legs)` orders
    /// the spread legs first (the bandwidth-boost ordering over
    /// those legs), then the remaining transports as failover;
    /// `DuplicateThrough` fans the packet out to the handover legs
    /// (`duplicate` true) until the window settles, when the next
    /// decide returns `MoveTo` on the new leg.
    ///
    /// Every decision change is logged at INFO (4.101) — one line
    /// per change, never per packet — so a promotion or handover is
    /// directly observable in logcat/diagnostics:
    /// `adaptive decision flow=0x… decision=… bytes_total=… age_ms=…`.
    /// `Stay` is never logged.
    pub fn pin_for_packet(
        &mut self,
        engine: &TrafficModeEngine,
        packet: &[u8],
        count: usize,
        active_index: usize,
        signals: &[PathSignal],
        now_ms: u64,
    ) -> AdaptivePin {
        let mode = engine.mode_for_packet(packet);
        if mode != TrafficMode::Adaptive {
            return AdaptivePin {
                candidates: engine.order_for_packet(packet, count, active_index, signals),
                duplicate: mode == TrafficMode::Redundant,
            };
        }
        let key = table_key(packet);
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= ADAPTIVE_MAX_FLOWS {
                if let Some(oldest) = self
                    .flows
                    .iter()
                    .min_by_key(|(_, entry)| entry.last_seen_ms)
                    .map(|(key, _)| *key)
                {
                    self.flows.remove(&oldest);
                }
            }
            self.flows.insert(
                key,
                AdaptiveFlowEntry {
                    flow: AdaptiveFlow::new(signals, now_ms, None),
                    bytes_total: 0,
                    last_seen_ms: now_ms,
                },
            );
        }
        let entry = self.flows.get_mut(&key).expect("flow just inserted");
        entry.bytes_total = entry
            .bytes_total
            .saturating_add(packet.len() as u64);
        entry.last_seen_ms = now_ms;
        let obs = FlowObservation {
            bytes_total: entry.bytes_total,
        };
        // The returned decision is already reflected in the flow's
        // strategy — decide updates state to match — so the
        // placement below reads the strategy, not the decision.
        // The decision itself is logged here (4.101): one line per
        // decision change, at INFO so it reaches logcat on Android
        // and the CLI's stdout logger. Stay is never logged — a
        // line per packet would spam diagnostics. The flow key is
        // the direction-independent table key, so one flow's lines
        // correlate across its lifetime.
        let decision = entry.flow.decide(&obs, signals, now_ms);
        if decision != AdaptiveDecision::Stay {
            tracing::info!(
                flow = format!("{key:#018x}"),
                decision = ?decision,
                bytes_total = entry.bytes_total,
                age_ms = now_ms.saturating_sub(entry.flow.started_ms),
                "adaptive decision"
            );
        }
        let strategy = entry.flow.strategy.clone();
        adaptive_candidates(&strategy, count, active_index, signals)
    }

    /// Count an inbound (return-path) packet toward its flow's
    /// cumulative bytes (4.101). Only a flow the table already
    /// tracks — created by its outbound packets — is counted: an
    /// inbound packet for an unknown flow has no adaptive state
    /// and must not create one (the client never sent on it, so
    /// there is no placement to decide). The direction-independent
    /// key is what matches the reply to the flow its outbound
    /// packets created. The next outbound packet (typically an
    /// ACK) runs `decide` with the new total, so a bulk download
    /// promotes on its ACKs even though its outbound stream is a
    /// trickle. Also refreshes the entry's last-seen time, so an
    /// active download is not evicted as idle while its inbound
    /// traffic flows.
    pub fn note_inbound(&mut self, packet: &[u8], now_ms: u64) {
        if let Some(entry) = self.flows.get_mut(&table_key(packet)) {
            entry.bytes_total = entry.bytes_total.saturating_add(packet.len() as u64);
            entry.last_seen_ms = now_ms;
        }
    }
}

/// Turn a flow's current strategy into the pin point's try-list
/// (and fan-out flag). The best-transport ranking over the full
/// transport set supplies the failover order behind the current
/// placement and the remaining legs behind a spread set, so a
/// send failure still fails over instead of dropping the packet.
/// Legs that no longer exist in the transport set (it shrank
/// since the flow was placed) are filtered out; with no
/// transports at all the active transport is the only candidate,
/// the same empty-set shape as the engine's orders.
fn adaptive_candidates(
    strategy: &Strategy,
    count: usize,
    active_index: usize,
    signals: &[PathSignal],
) -> AdaptivePin {
    if count == 0 {
        return AdaptivePin {
            candidates: vec![active_index],
            duplicate: false,
        };
    }
    let ranked = TrafficModeEngine::default().order_candidates(
        TrafficMode::BestTransport,
        0,
        count,
        active_index,
        signals,
    );
    match strategy {
        Strategy::Single(leg) => {
            let mut candidates = Vec::new();
            if *leg < count {
                candidates.push(*leg);
            }
            for index in ranked {
                if !candidates.contains(&index) {
                    candidates.push(index);
                }
            }
            if !candidates.contains(&active_index) {
                candidates.push(active_index);
            }
            AdaptivePin {
                candidates,
                duplicate: false,
            }
        }
        Strategy::Spread(legs) => {
            let mut candidates: Vec<usize> =
                legs.iter().copied().filter(|leg| *leg < count).collect();
            for index in ranked {
                if !candidates.contains(&index) {
                    candidates.push(index);
                }
            }
            if !candidates.contains(&active_index) {
                candidates.push(active_index);
            }
            AdaptivePin {
                candidates,
                duplicate: false,
            }
        }
        Strategy::Duplicating { from, to, .. } => {
            let legs: Vec<usize> = [*from, *to]
                .into_iter()
                .filter(|leg| *leg < count)
                .collect();
            if legs.is_empty() {
                // Both handover legs vanished: fall back to the
                // ranking as a single send, not a fan-out to
                // nothing.
                return AdaptivePin {
                    candidates: ranked,
                    duplicate: false,
                };
            }
            AdaptivePin {
                candidates: legs,
                duplicate: true,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic_mode::{PathSignal, TrafficRule};

    fn signal(grade: Option<u8>, rtt_ms: Option<u64>, loss_rate: Option<f64>) -> PathSignal {
        PathSignal {
            grade,
            rtt_ms,
            loss_rate,
        }
    }

    /// Three transports: a fast good one, a slower good one, and a
    /// poor one. Leg 0 leads on grade and RTT; leg 1 is the natural
    /// second; leg 2 trails on everything.
    fn three_good_signals() -> Vec<PathSignal> {
        vec![
            signal(Some(90), Some(20), Some(0.01)),
            signal(Some(80), Some(40), Some(0.02)),
            signal(Some(50), Some(120), Some(0.05)),
        ]
    }

    /// Drive one flow through a script of (now_ms, bytes_total,
    /// signals) ticks and collect the decisions. The signals are
    /// the same every tick unless the caller swaps them in.
    fn run_ticks(
        flow: &mut AdaptiveFlow,
        ticks: &[(u64, u64, Vec<PathSignal>)],
    ) -> Vec<AdaptiveDecision> {
        ticks
            .iter()
            .map(|(now_ms, bytes, signals)| {
                flow.decide(
                    &FlowObservation {
                        bytes_total: *bytes,
                    },
                    signals,
                    *now_ms,
                )
            })
            .collect()
    }

    #[test]
    fn new_flow_starts_on_the_best_leg() {
        let signals = three_good_signals();
        let flow = AdaptiveFlow::new(&signals, 0, None);
        assert_eq!(flow.strategy, Strategy::Single(0));
        assert_eq!(flow.current_leg(), Some(0));
        assert_eq!(flow.recorded_grade, Some(90));
        assert_eq!(flow.recorded_loss, Some(0.01));

        // Lowest RTT wins when grades tie: leg 1 (20 ms) leads leg 0
        // (30 ms) at equal grades.
        let signals = vec![
            signal(Some(80), Some(30), Some(0.01)),
            signal(Some(80), Some(20), Some(0.01)),
        ];
        let flow = AdaptiveFlow::new(&signals, 0, None);
        assert_eq!(flow.strategy, Strategy::Single(1));

        // No signals yet: leg 0, no baseline — the cold-start case.
        let flow = AdaptiveFlow::new(&[], 0, None);
        assert_eq!(flow.strategy, Strategy::Single(0));
        assert_eq!(flow.recorded_grade, None);
    }

    #[test]
    fn short_interactive_flow_stays_on_its_single_leg_and_never_spreads() {
        // A DNS-like flow: a few KB over ~1 s, ten 100 ms ticks.
        let signals = three_good_signals();
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        let mut bytes = 0u64;
        let mut ticks = Vec::new();
        for i in 0..10u64 {
            bytes += 4_096; // 4 KiB per tick
            ticks.push((i * 100, bytes, signals.clone()));
        }
        let decisions = run_ticks(&mut flow, &ticks);
        assert!(
            decisions.iter().all(|d| *d == AdaptiveDecision::Stay),
            "a 40 KiB / 1 s flow must never move or spread, got {decisions:?}"
        );
        assert_eq!(flow.strategy, Strategy::Single(0));
        assert_eq!(flow.current_leg(), Some(0));

        // Even a chatty interactive flow (200 KiB over 5 s, well
        // under the 1 MiB bulk floor) stays single.
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        let mut bytes = 0u64;
        let mut ticks = Vec::new();
        for i in 0..10u64 {
            bytes += 20_480; // 20 KiB per 500 ms tick
            ticks.push((i * 500, bytes, signals.clone()));
        }
        let decisions = run_ticks(&mut flow, &ticks);
        assert!(
            decisions.iter().all(|d| *d == AdaptiveDecision::Stay),
            "a 200 KiB / 5 s flow must stay single, got {decisions:?}"
        );
        assert_eq!(flow.strategy, Strategy::Single(0));
    }

    #[test]
    fn sustained_bulk_flow_is_promoted_to_spread_across_the_top_two() {
        // A download: ~2.1 MiB over 2.5 s (≈ 7 Mbit/s), 500 ms ticks
        // adding 350 KiB each.
        let signals = three_good_signals();
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        let mut bytes = 0u64;
        let mut ticks = Vec::new();
        for i in 0..6u64 {
            bytes += 350_000;
            ticks.push((i * 500, bytes, signals.clone()));
        }
        let decisions = run_ticks(&mut flow, &ticks);
        // The first four ticks are under the 2 s age floor (t = 0,
        // 500, 1000, 1500 ms); the promotion lands on the tick where
        // bytes, age, and rate all clear their floors (t = 2000 ms,
        // 1.75 MiB, 875 KiB/s).
        assert_eq!(decisions[0], AdaptiveDecision::Stay);
        assert_eq!(decisions[1], AdaptiveDecision::Stay);
        assert_eq!(decisions[2], AdaptiveDecision::Stay);
        assert_eq!(decisions[3], AdaptiveDecision::Stay);
        assert_eq!(
            decisions[4],
            AdaptiveDecision::PromoteToSpread(vec![0, 1]),
            "the bulk flow must spread across the top two legs, got {decisions:?}"
        );
        assert_eq!(flow.strategy, Strategy::Spread(vec![0, 1]));
        // Once spread it stays spread while the signals are stable.
        assert_eq!(decisions[5], AdaptiveDecision::Stay);
    }

    #[test]
    fn bulk_thresholds_are_all_required() {
        let signals = three_good_signals();
        // Bytes without age: 1 MiB in 100 ms is a burst, not bulk.
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 2 * BULK_BYTES,
            },
            &signals,
            100,
        );
        assert_eq!(d, AdaptiveDecision::Stay, "a 100 ms burst must not promote");

        // Age without bytes: 10 s old but only 100 KiB is not bulk.
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 100_000,
            },
            &signals,
            10_000,
        );
        assert_eq!(
            d,
            AdaptiveDecision::Stay,
            "a 100 KiB / 10 s flow must not promote"
        );

        // Bytes and age but a slow rate: 1 MiB over 10 s is
        // 100 KiB/s, under the 128 KiB/s rate floor.
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        let d = flow.decide(
            &FlowObservation {
                bytes_total: BULK_BYTES,
            },
            &signals,
            10_000,
        );
        assert_eq!(
            d,
            AdaptiveDecision::Stay,
            "a 1 MiB / 10 s trickle (100 KiB/s) must not promote"
        );

        // Just over all three floors: 1 MiB at 2 s is 512 KiB/s.
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        let d = flow.decide(
            &FlowObservation {
                bytes_total: BULK_BYTES,
            },
            &signals,
            2_000,
        );
        assert_eq!(
            d,
            AdaptiveDecision::PromoteToSpread(vec![0, 1]),
            "1 MiB at 2 s (512 KiB/s) clears every floor and must promote"
        );
    }

    #[test]
    fn single_transport_cannot_spread() {
        // One transport: a bulk flow has nowhere to spread to.
        let signals = vec![signal(Some(90), Some(20), Some(0.01))];
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 4 * BULK_BYTES,
            },
            &signals,
            5_000,
        );
        assert_eq!(d, AdaptiveDecision::Stay);
        assert_eq!(flow.strategy, Strategy::Single(0));
    }

    #[test]
    fn degrading_leg_duplicates_through_the_handover_then_settles() {
        let mut signals = three_good_signals();
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        assert_eq!(flow.strategy, Strategy::Single(0));

        // t = 1000 ms, still healthy: nothing to do.
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 10_000,
            },
            &signals,
            1_000,
        );
        assert_eq!(d, AdaptiveDecision::Stay);

        // t = 2000 ms: leg 0's grade collapses 90 -> 60 (a
        // 30-point drop, past the 20-point trigger) while leg 1
        // holds at 80 — a 20-point gap to the best alternative,
        // past the 10-point move threshold.
        signals[0] = signal(Some(60), Some(200), Some(0.05));
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 20_000,
            },
            &signals,
            2_000,
        );
        assert_eq!(
            d,
            AdaptiveDecision::DuplicateThrough {
                legs: vec![0, 1],
                until_ms: 2_000 + DUPLICATE_WINDOW_MS,
            },
            "a 30-point grade collapse must duplicate through the handover"
        );
        assert_eq!(
            flow.strategy,
            Strategy::Duplicating {
                from: 0,
                to: 1,
                until_ms: 2_500
            }
        );

        // Inside the window the flow keeps duplicating.
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 30_000,
            },
            &signals,
            2_200,
        );
        assert_eq!(
            d,
            AdaptiveDecision::DuplicateThrough {
                legs: vec![0, 1],
                until_ms: 2_500
            }
        );

        // Past the window it settles on the new leg.
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 40_000,
            },
            &signals,
            2_500,
        );
        assert_eq!(d, AdaptiveDecision::MoveTo(1));
        assert_eq!(flow.strategy, Strategy::Single(1));
        assert_eq!(flow.recorded_grade, Some(80));
    }

    #[test]
    fn loss_spike_degrades_a_leg_even_when_its_grade_holds() {
        // Grade stays 90, but the loss rate jumps 1% -> 20%: the
        // loss trigger fires on its own.
        let mut signals = three_good_signals();
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        signals[0] = signal(Some(90), Some(20), Some(0.20));
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 10_000,
            },
            &signals,
            1_000,
        );
        assert_eq!(
            d,
            AdaptiveDecision::DuplicateThrough {
                legs: vec![0, 1],
                until_ms: 1_000 + DUPLICATE_WINDOW_MS,
            },
            "a 1% -> 20% loss spike must degrade the leg even at grade 90"
        );
    }

    #[test]
    fn degraded_leg_with_no_better_alternative_stays_and_rebaselines() {
        // Every leg degrades together: leg 0 falls 90 -> 60, leg 1
        // falls 80 -> 55, leg 2 falls 50 -> 30. Leg 0 is degraded
        // (30-point drop) but the best alternative (leg 1, 55) is
        // only 5 points above the current 60 — under the 10-point
        // move gap, so moving gains nothing.
        let mut signals = three_good_signals();
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        signals[0] = signal(Some(60), Some(200), Some(0.05));
        signals[1] = signal(Some(55), Some(220), Some(0.06));
        signals[2] = signal(Some(30), Some(300), Some(0.09));
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 10_000,
            },
            &signals,
            1_000,
        );
        assert_eq!(
            d,
            AdaptiveDecision::Stay,
            "a 5-point gap must not move the flow"
        );
        // The baseline re-set to the degraded 60, so the same drop
        // does not re-trigger on the next tick.
        assert_eq!(flow.recorded_grade, Some(60));
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 20_000,
            },
            &signals,
            6_000,
        );
        assert_eq!(
            d,
            AdaptiveDecision::Stay,
            "the re-baselined drop must not re-fire"
        );
    }

    #[test]
    fn rapidly_flapping_grades_do_not_flap_the_flow() {
        // The grades flip the lead every few seconds: leg 0 leads,
        // then collapses and leg 1 leads, then leg 1 collapses and
        // leg 0 leads again. Each collapse is a 30-point drop with a
        // 20+ point gap to the other leg, so the grade-gap threshold
        // never blocks a move — only the hysteresis interval can.
        // The flow must move at most once per MIN_DECISION_INTERVAL_MS
        // (5 s): at t = 1000, 6000, and 11000 ms — three moves in
        // 11.5 s of flapping, not one per flip — and every tick
        // inside each 5 s window after a move must be Stay even
        // though the grades are screaming "move".
        let good0 = three_good_signals();
        // Leg 0 collapsed (60), leg 1 leading (80).
        let leg0_down = vec![
            signal(Some(60), Some(200), Some(0.05)),
            signal(Some(80), Some(40), Some(0.02)),
            signal(Some(50), Some(120), Some(0.05)),
        ];
        // Leg 1 collapsed (50), leg 0 leading (90).
        let leg1_down = vec![
            signal(Some(90), Some(20), Some(0.01)),
            signal(Some(50), Some(200), Some(0.05)),
            signal(Some(50), Some(120), Some(0.05)),
        ];
        let mut flow = AdaptiveFlow::new(&good0, 0, None);
        let ticks: Vec<(u64, Vec<PathSignal>)> = vec![
            (0, good0.clone()),
            (1_000, leg0_down.clone()),
            (1_500, leg0_down.clone()),
            (2_000, leg1_down.clone()),
            (3_000, leg1_down.clone()),
            (4_000, leg1_down.clone()),
            (5_000, leg1_down.clone()),
            (6_000, leg1_down.clone()),
            (6_500, leg1_down.clone()),
            (7_000, leg0_down.clone()),
            (11_000, leg0_down.clone()),
            (11_500, leg0_down.clone()),
        ];
        let mut decisions = Vec::new();
        for (now_ms, signals) in &ticks {
            let d = flow.decide(
                &FlowObservation {
                    bytes_total: 10_000,
                },
                signals,
                *now_ms,
            );
            decisions.push((*now_ms, d));
        }
        let expected = vec![
            (0, AdaptiveDecision::Stay),
            (
                1_000,
                AdaptiveDecision::DuplicateThrough {
                    legs: vec![0, 1],
                    until_ms: 1_500,
                },
            ),
            (1_500, AdaptiveDecision::MoveTo(1)),
            (2_000, AdaptiveDecision::Stay),
            (3_000, AdaptiveDecision::Stay),
            (4_000, AdaptiveDecision::Stay),
            (5_000, AdaptiveDecision::Stay),
            (
                6_000,
                AdaptiveDecision::DuplicateThrough {
                    legs: vec![1, 0],
                    until_ms: 6_500,
                },
            ),
            (6_500, AdaptiveDecision::MoveTo(0)),
            (7_000, AdaptiveDecision::Stay),
            (
                11_000,
                AdaptiveDecision::DuplicateThrough {
                    legs: vec![0, 1],
                    until_ms: 11_500,
                },
            ),
            (11_500, AdaptiveDecision::MoveTo(1)),
        ];
        assert_eq!(
            decisions, expected,
            "hysteresis must hold the flow to one move per 5 s"
        );
        // And the move times are exactly 5 s apart — the interval,
        // not the grade flips, sets the pace.
        let move_times: Vec<u64> = decisions
            .iter()
            .filter(|(_, d)| matches!(d, AdaptiveDecision::DuplicateThrough { .. }))
            .map(|(t, _)| *t)
            .collect();
        assert_eq!(move_times, vec![1_000, 6_000, 11_000]);
    }

    #[test]
    fn small_grade_gap_never_moves_the_flow() {
        // Leg 0 degrades 90 -> 75 (a 15-point drop, under the
        // 20-point trigger): no degradation at all, so no move even
        // though leg 1 (80) is 5 points ahead.
        let mut signals = three_good_signals();
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        signals[0] = signal(Some(75), Some(60), Some(0.02));
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 10_000,
            },
            &signals,
            1_000,
        );
        assert_eq!(
            d,
            AdaptiveDecision::Stay,
            "a 15-point drop is under the 20-point degradation trigger"
        );

        // Leg 0 degrades 90 -> 65 (a 25-point drop, past the
        // trigger) but leg 1 is only 70 — a 5-point gap, under the
        // 10-point move threshold.
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        signals[0] = signal(Some(65), Some(200), Some(0.05));
        signals[1] = signal(Some(70), Some(40), Some(0.02));
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 10_000,
            },
            &signals,
            1_000,
        );
        assert_eq!(
            d,
            AdaptiveDecision::Stay,
            "a 5-point gap to the best alternative must not move the flow"
        );
    }

    #[test]
    fn pinned_flow_is_left_alone_no_matter_what_happens() {
        // The flow is pinned to Redundant by an explicit rule. Feed
        // it bulk-level bytes (which would promote it) and collapse
        // its leg (which would move it): the policy must not touch it.
        let signals = three_good_signals();
        let mut flow = AdaptiveFlow::new(&signals, 0, Some(TrafficMode::Redundant));
        assert_eq!(flow.strategy, Strategy::Single(0));

        let mut degraded = three_good_signals();
        degraded[0] = signal(Some(40), Some(500), Some(0.30));
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 10 * BULK_BYTES,
            },
            &degraded,
            10_000,
        );
        assert_eq!(d, AdaptiveDecision::Pinned);
        assert_eq!(flow.strategy, Strategy::Single(0));

        // And again, later, still pinned.
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 20 * BULK_BYTES,
            },
            &degraded,
            20_000,
        );
        assert_eq!(d, AdaptiveDecision::Pinned);
        assert_eq!(flow.strategy, Strategy::Single(0));

        // A pinned flow is also pinned when it would otherwise stay.
        let mut flow = AdaptiveFlow::new(&signals, 0, Some(TrafficMode::LowestLatency));
        let d = flow.decide(&FlowObservation { bytes_total: 100 }, &signals, 100);
        assert_eq!(d, AdaptiveDecision::Pinned);
    }

    #[test]
    fn cold_start_replaces_the_guessed_leg_when_signals_first_arrive() {
        // The flow was created before any signals existed (leg 0,
        // a guess). The first tick with signals shows leg 1 clearly
        // ahead (grade 90 vs 60 — a 30-point gap): the policy
        // (re)places the flow on leg 1.
        let mut flow = AdaptiveFlow::new(&[], 0, None);
        assert_eq!(flow.strategy, Strategy::Single(0));
        let signals = vec![
            signal(Some(60), Some(200), Some(0.05)),
            signal(Some(90), Some(20), Some(0.01)),
        ];
        let d = flow.decide(&FlowObservation { bytes_total: 1_000 }, &signals, 1_000);
        assert_eq!(
            d,
            AdaptiveDecision::DuplicateThrough {
                legs: vec![0, 1],
                until_ms: 1_000 + DUPLICATE_WINDOW_MS,
            },
            "a cold-started flow must be (re)placed when signals first arrive"
        );

        // But if the guessed leg turns out to be the best one, the
        // flow stays put.
        let mut flow = AdaptiveFlow::new(&[], 0, None);
        let signals = three_good_signals();
        let d = flow.decide(&FlowObservation { bytes_total: 1_000 }, &signals, 1_000);
        assert_eq!(d, AdaptiveDecision::Stay);
        assert_eq!(flow.strategy, Strategy::Single(0));
    }

    #[test]
    fn spread_flow_re_ranks_instead_of_duplicating() {
        // Promote to spread first.
        let signals = three_good_signals();
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 2 * BULK_BYTES,
            },
            &signals,
            3_000,
        );
        assert_eq!(d, AdaptiveDecision::PromoteToSpread(vec![0, 1]));
        assert_eq!(flow.strategy, Strategy::Spread(vec![0, 1]));

        // At t = 8000 ms (past the 5 s interval) leg 0 collapses
        // 90 -> 40. The spread set re-ranks to [1, 2] — no
        // duplication, because the flow already covers two legs and
        // leg 1 keeps carrying it.
        let mut degraded = three_good_signals();
        degraded[0] = signal(Some(40), Some(500), Some(0.20));
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 10 * BULK_BYTES,
            },
            &degraded,
            8_000,
        );
        assert_eq!(
            d,
            AdaptiveDecision::PromoteToSpread(vec![1, 2]),
            "a spread flow must re-rank its legs, not duplicate"
        );
        assert_eq!(flow.strategy, Strategy::Spread(vec![1, 2]));

        // And a spread set that does not change stays put.
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 20 * BULK_BYTES,
            },
            &degraded,
            14_000,
        );
        assert_eq!(d, AdaptiveDecision::Stay);
    }

    #[test]
    fn vanished_leg_moves_the_flow() {
        // The transport set shrinks: the flow's leg 2 is gone.
        let signals = three_good_signals();
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        // Force the flow onto leg 2 first (a bulk spread would do it,
        // but simpler: construct the state directly).
        flow.strategy = Strategy::Single(2);
        flow.set_baseline(&signals, 2);
        let shrunk = vec![
            signal(Some(90), Some(20), Some(0.01)),
            signal(Some(80), Some(40), Some(0.02)),
        ];
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 10_000,
            },
            &shrunk,
            1_000,
        );
        assert_eq!(
            d,
            AdaptiveDecision::DuplicateThrough {
                legs: vec![2, 0],
                until_ms: 1_000 + DUPLICATE_WINDOW_MS,
            },
            "a leg that no longer exists must move the flow to the best remaining leg"
        );
    }

    #[test]
    fn no_signals_at_all_never_moves_or_promotes() {
        let mut flow = AdaptiveFlow::new(&[], 0, None);
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 10 * BULK_BYTES,
            },
            &[],
            10_000,
        );
        assert_eq!(d, AdaptiveDecision::Stay);
        assert_eq!(flow.strategy, Strategy::Single(0));
    }

    /// Build an IPv4 UDP packet to `dst` from `src_port`, padded
    /// to `len` bytes total. The pin point counts the packet's
    /// length as the flow's observed bytes, so the padding is what
    /// drives the bulk thresholds in the table tests.
    fn udp_packet(dst: [u8; 4], src_port: u16, len: usize) -> Vec<u8> {
        udp_packet_between([192, 0, 2, 1], src_port, dst, 443, len)
    }

    /// Build an IPv4 UDP packet from `src:src_port` to
    /// `dst:dst_port`, padded to `len` bytes total.
    fn udp_packet_between(
        src: [u8; 4],
        src_port: u16,
        dst: [u8; 4],
        dst_port: u16,
        len: usize,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; len.max(28)];
        packet[0] = 0x45; // version 4, IHL 20
        packet[9] = 17; // UDP
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    /// Build the reply to [`udp_packet`]: the same 5-tuple in the
    /// reverse direction (server `dst:443` back to the client
    /// `192.0.2.1:src_port`). The direction-independent table key
    /// matches it to the flow the outbound packet created, so
    /// [`AdaptiveFlowTable::note_inbound`] counts it toward that
    /// flow's bytes.
    fn udp_reply_packet(dst: [u8; 4], src_port: u16, len: usize) -> Vec<u8> {
        udp_packet_between(dst, 443, [192, 0, 2, 1], src_port, len)
    }

    fn adaptive_engine() -> TrafficModeEngine {
        TrafficModeEngine {
            default_mode: TrafficMode::Adaptive,
            rules: vec![],
        }
    }

    /// A minimal `tracing` subscriber that captures formatted
    /// events into a shared vec, so the decision-logging test can
    /// assert a decision produces a log record without a log
    /// backend. No new dependency: the test implements the
    /// `Subscriber` trait by hand.
    struct CapturingSubscriber {
        events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl tracing::Subscriber for CapturingSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            struct Visitor {
                text: String,
            }
            impl tracing::field::Visit for Visitor {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.text.push_str(&format!(" {}={value:?}", field.name()));
                }

                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    self.text.push_str(&format!(" {}={value}", field.name()));
                }

                fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                    self.text.push_str(&format!(" {}={value}", field.name()));
                }

                fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
                    self.text.push_str(&format!(" {}={value}", field.name()));
                }

                fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
                    self.text.push_str(&format!(" {}={value}", field.name()));
                }
            }
            let mut visitor = Visitor {
                text: String::new(),
            };
            event.record(&mut visitor);
            self.events
                .lock()
                .expect("captured events lock poisoned")
                .push(visitor.text);
        }
    }

    #[test]
    fn table_pins_interactive_flow_to_best_leg() {
        // A short flow under the adaptive default: every packet
        // stays on the best-graded leg (0), with the other legs
        // behind it as failover — never a fan-out.
        let engine = adaptive_engine();
        let signals = three_good_signals();
        let mut table = AdaptiveFlowTable::new();
        let packet = udp_packet([93, 184, 216, 34], 51000, 1_000);
        for now_ms in [0u64, 100, 200, 500, 1_000] {
            let pin = table.pin_for_packet(&engine, &packet, 3, 0, &signals, now_ms);
            assert_eq!(pin.candidates, vec![0, 1, 2]);
            assert!(!pin.duplicate);
        }
        assert_eq!(table.len(), 1);
        // Empty transport set: the active transport is the only
        // candidate, the same empty-set shape as the engine.
        let pin = table.pin_for_packet(&engine, &packet, 0, 3, &signals, 2_000);
        assert_eq!(pin.candidates, vec![3]);
        assert!(!pin.duplicate);
    }

    #[test]
    fn table_promotes_bulk_flow_to_spread() {
        // The same download as the policy test, driven through the
        // table with real packet lengths: 350 KiB per 500 ms tick.
        let engine = adaptive_engine();
        let signals = three_good_signals();
        let mut table = AdaptiveFlowTable::new();
        let packet = udp_packet([93, 184, 216, 34], 51000, 350_000);
        let mut pins = Vec::new();
        for now_ms in [0u64, 500, 1_000, 1_500, 2_000, 2_500] {
            pins.push(table.pin_for_packet(&engine, &packet, 3, 0, &signals, now_ms));
        }
        // Under the 2 s age floor the flow stays single on leg 0.
        for pin in &pins[0..4] {
            assert_eq!(pin.candidates, vec![0, 1, 2]);
            assert!(!pin.duplicate);
        }
        // At t = 2000 ms (1.75 MiB, 875 KiB/s) it promotes: the
        // spread legs [0, 1] lead, leg 2 follows as failover.
        assert_eq!(pins[4].candidates, vec![0, 1, 2]);
        assert!(!pins[4].duplicate);
        // ... and it stays spread while the signals are stable.
        assert_eq!(pins[5].candidates, vec![0, 1, 2]);
        assert!(!pins[5].duplicate);
    }

    #[test]
    fn table_duplicates_through_degradation_then_settles() {
        let engine = adaptive_engine();
        let mut signals = three_good_signals();
        let mut table = AdaptiveFlowTable::new();
        let packet = udp_packet([93, 184, 216, 34], 51000, 10_000);
        // Healthy first: single leg, no fan-out.
        let pin = table.pin_for_packet(&engine, &packet, 3, 0, &signals, 1_000);
        assert_eq!(pin.candidates, vec![0, 1, 2]);
        assert!(!pin.duplicate);
        // Leg 0 collapses 90 -> 60 at t = 2000 ms: duplicate
        // through the handover on [0, 1].
        signals[0] = signal(Some(60), Some(200), Some(0.05));
        let pin = table.pin_for_packet(&engine, &packet, 3, 0, &signals, 2_000);
        assert_eq!(pin.candidates, vec![0, 1]);
        assert!(pin.duplicate, "the handover must fan out, got {pin:?}");
        // Inside the window it keeps duplicating.
        let pin = table.pin_for_packet(&engine, &packet, 3, 0, &signals, 2_200);
        assert_eq!(pin.candidates, vec![0, 1]);
        assert!(pin.duplicate);
        // Past the window it settles on leg 1 — single send again.
        let pin = table.pin_for_packet(&engine, &packet, 3, 0, &signals, 2_500);
        assert_eq!(pin.candidates, vec![1, 0, 2]);
        assert!(!pin.duplicate);
    }

    fn subnet_rule(id: &str, target: &str, mode: TrafficMode) -> TrafficRule {
        use crate::traffic_mode::TrafficRuleKind;
        TrafficRule {
            id: id.to_string(),
            kind: TrafficRuleKind::Subnet,
            target: target.to_string(),
            resolved_ips: vec![],
            mode,
        }
    }

    #[test]
    fn table_pin_for_packet_never_overrides_a_pinned_rule() {
        // Default adaptive, but 10.0.0.0/8 is pinned to Redundant:
        // a packet to 10.1.2.3 fans out on all transports (the
        // rule's mode), and the adaptive policy never sees it — no
        // table entry is created for that flow.
        let engine = TrafficModeEngine {
            default_mode: TrafficMode::Adaptive,
            rules: vec![subnet_rule("s", "10.0.0.0/8", TrafficMode::Redundant)],
        };
        let signals = three_good_signals();
        let mut table = AdaptiveFlowTable::new();
        let pinned = udp_packet([10, 1, 2, 3], 51000, 10_000);
        let pin = table.pin_for_packet(&engine, &pinned, 3, 0, &signals, 1_000);
        assert_eq!(pin.candidates, vec![0, 1, 2]);
        assert!(pin.duplicate, "a redundant rule must fan out");
        assert_eq!(table.len(), 0, "a pinned flow must not get an adaptive entry");
        // The same engine, an unmatched destination: adaptive
        // applies — best leg first, no fan-out.
        let free = udp_packet([203, 0, 113, 1], 51000, 10_000);
        let pin = table.pin_for_packet(&engine, &free, 3, 0, &signals, 1_000);
        assert_eq!(pin.candidates, vec![0, 1, 2]);
        assert!(!pin.duplicate);
        assert_eq!(table.len(), 1);

        // The mirror: default Redundant, but 10.0.0.0/8 is pinned
        // to Adaptive — the rule's flow is adaptive (best leg, no
        // fan-out) while every other flow fans out.
        let engine = TrafficModeEngine {
            default_mode: TrafficMode::Redundant,
            rules: vec![subnet_rule("s", "10.0.0.0/8", TrafficMode::Adaptive)],
        };
        let mut table = AdaptiveFlowTable::new();
        let pin = table.pin_for_packet(&engine, &pinned, 3, 0, &signals, 1_000);
        assert_eq!(pin.candidates, vec![0, 1, 2]);
        assert!(!pin.duplicate, "an adaptive rule must not fan out");
        assert_eq!(table.len(), 1);
        let pin = table.pin_for_packet(&engine, &free, 3, 0, &signals, 1_000);
        assert_eq!(pin.candidates, vec![0, 1, 2]);
        assert!(pin.duplicate, "the redundant default must fan out");
        assert_eq!(table.len(), 1, "a redundant flow must not get an adaptive entry");
    }

    #[test]
    fn table_evicts_least_recently_seen_flow_when_full() {
        let engine = adaptive_engine();
        let signals = three_good_signals();
        let mut table = AdaptiveFlowTable::new();
        // One more flow than the cap, each on its own port, seen in
        // order: the first flow is the least recently seen and must
        // be the one evicted.
        for i in 0..=ADAPTIVE_MAX_FLOWS {
            let packet = udp_packet([93, 184, 216, 34], i as u16, 100);
            table.pin_for_packet(&engine, &packet, 3, 0, &signals, i as u64);
        }
        assert_eq!(table.len(), ADAPTIVE_MAX_FLOWS);
    }

    #[test]
    fn table_logs_a_decision_change_and_not_a_stay() {
        // The decision log is the only way a promotion or handover
        // is directly observable: drive the same download as the
        // promotion test through the table under a capturing
        // subscriber and assert exactly one line, on the promotion
        // tick — none on the Stay ticks before it.
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = CapturingSubscriber {
            events: events.clone(),
        };
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("probe");
            assert!(
                events.lock().expect("events lock").iter().any(|e| e.contains("probe")),
                "the capturing subscriber must see a direct probe event"
            );
            events.lock().expect("events lock").clear();
            let engine = adaptive_engine();
            let signals = three_good_signals();
            let mut table = AdaptiveFlowTable::new();
            let packet = udp_packet([93, 184, 216, 34], 51000, 350_000);
            for now_ms in [0u64, 500, 1_000, 1_500] {
                table.pin_for_packet(&engine, &packet, 3, 0, &signals, now_ms);
            }
            assert!(
                events.lock().expect("events lock").is_empty(),
                "Stay must not log: a line per packet would spam diagnostics"
            );
            // Rebuild the callsite interest cache HERE, after the
            // Stay ticks — not at the top of the closure. The
            // `pin_for_packet` callsite's interest is cached
            // globally the first time any test thread hits it
            // (NEVER under the no-op dispatcher), and installing a
            // thread-local subscriber does not rebuild it. A
            // rebuild before the first pin call is a no-op when the
            // callsite is still unregistered, and another thread's
            // first hit after it caches NEVER again — the test
            // flaked exactly this way (3/6 full-suite runs). By
            // this point the callsite is certainly registered (the
            // Stay ticks above hit it), so this rebuild
            // deterministically re-evaluates it against this
            // subscriber; nothing re-registers or rebuilds after
            // it, so the promotion line below is captured every run.
            tracing::callsite::rebuild_interest_cache();
            // At t = 2000 ms (1.75 MiB, 875 KiB/s) the flow
            // promotes: exactly one line.
            table.pin_for_packet(&engine, &packet, 3, 0, &signals, 2_000);
            let events = events.lock().expect("events lock");
            assert_eq!(
                events.len(),
                1,
                "one decision change must log exactly one line, got {events:?}"
            );
            assert!(
                events[0].contains("adaptive decision"),
                "the line must name the event: {}",
                events[0]
            );
            assert!(
                events[0].contains("PromoteToSpread"),
                "the line must name the decision: {}",
                events[0]
            );
            assert!(
                events[0].contains("flow=0x"),
                "the line must carry the flow key: {}",
                events[0]
            );
            assert!(
                events[0].contains("bytes_total=1750000"),
                "the line must carry the cumulative bytes: {}",
                events[0]
            );
            assert!(
                events[0].contains("age_ms=2000"),
                "the line must carry the flow age: {}",
                events[0]
            );
        });
    }

    #[test]
    fn table_counts_inbound_bytes_toward_bulk() {
        // The bench case (4.100): a download's outbound stream is
        // ACKs — here 1 KiB per 500 ms tick, 5 KiB over 2.5 s,
        // far under every bulk floor — while its inbound stream
        // carries 350 KiB per tick. With outbound bytes only the
        // flow never promotes; with both directions it promotes at
        // t = 2000 ms (1.75 MiB, 875 KiB/s), exactly like the
        // outbound-only download in table_promotes_bulk_flow_to_spread.
        let engine = adaptive_engine();
        let signals = three_good_signals();
        let outbound = udp_packet([93, 184, 216, 34], 51000, 1_000);
        let inbound = udp_reply_packet([93, 184, 216, 34], 51000, 350_000);

        // Control: the ACK-only flow never promotes.
        let mut table = AdaptiveFlowTable::new();
        let mut pins = Vec::new();
        for now_ms in [0u64, 500, 1_000, 1_500, 2_000, 2_500] {
            pins.push(table.pin_for_packet(&engine, &outbound, 3, 0, &signals, now_ms));
        }
        assert!(
            pins.iter().all(|pin| !pin.duplicate),
            "an ACK-only flow must never spread or duplicate"
        );
        assert_eq!(table.len(), 1);

        // The same ACK stream with the download's inbound bytes
        // counted: promotes at t = 2000 ms.
        let mut table = AdaptiveFlowTable::new();
        let mut pins = Vec::new();
        for now_ms in [0u64, 500, 1_000, 1_500, 2_000, 2_500] {
            table.note_inbound(&inbound, now_ms);
            pins.push(table.pin_for_packet(&engine, &outbound, 3, 0, &signals, now_ms));
        }
        for pin in &pins[0..4] {
            assert_eq!(pin.candidates, vec![0, 1, 2]);
            assert!(!pin.duplicate);
        }
        assert_eq!(pins[4].candidates, vec![0, 1, 2]);
        assert!(!pins[4].duplicate);
        assert_eq!(pins[5].candidates, vec![0, 1, 2]);
        assert!(!pins[5].duplicate);
    }

    #[test]
    fn note_inbound_ignores_unknown_flows() {
        // An inbound packet for a flow the table never saw
        // outbound must not create an entry: the client never
        // sent on it, so there is no placement to decide.
        let mut table = AdaptiveFlowTable::new();
        let inbound = udp_reply_packet([93, 184, 216, 34], 51000, 350_000);
        table.note_inbound(&inbound, 1_000);
        assert_eq!(table.len(), 0);
        table.note_inbound(&inbound, 2_000);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn quiet_spread_flow_demotes_to_a_single_leg_after_the_idle_threshold() {
        // Promote first: 2 MiB over 3 s.
        let signals = three_good_signals();
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 2 * BULK_BYTES,
            },
            &signals,
            3_000,
        );
        assert_eq!(d, AdaptiveDecision::PromoteToSpread(vec![0, 1]));
        assert_eq!(flow.strategy, Strategy::Spread(vec![0, 1]));

        // Still active at t = 8000 ms (bytes grew to 10 MiB):
        // stays spread.
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 10 * BULK_BYTES,
            },
            &signals,
            8_000,
        );
        assert_eq!(d, AdaptiveDecision::Stay);
        assert_eq!(flow.strategy, Strategy::Spread(vec![0, 1]));

        // Quiet for exactly DEMOTE_IDLE_MS (no byte growth since
        // t = 8000): the next decide demotes to the best leg.
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 10 * BULK_BYTES,
            },
            &signals,
            8_000 + DEMOTE_IDLE_MS,
        );
        assert_eq!(
            d,
            AdaptiveDecision::MoveTo(0),
            "a flow quiet for 30 s must demote to a single leg"
        );
        assert_eq!(flow.strategy, Strategy::Single(0));
        assert_eq!(flow.recorded_grade, Some(90));

        // And the demotion respects the hysteresis interval: 1 s
        // later the flow must not instantly re-promote, even
        // though its byte total still clears the bulk floors — a
        // resumed bulk flow re-promotes only after the interval,
        // on fresh byte growth.
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 10 * BULK_BYTES,
            },
            &signals,
            8_000 + DEMOTE_IDLE_MS + 1_000,
        );
        assert_eq!(
            d,
            AdaptiveDecision::Stay,
            "a flow demoted 1 s ago must not instantly re-promote"
        );
        assert_eq!(flow.strategy, Strategy::Single(0));
    }

    #[test]
    fn brief_quiet_does_not_demote_a_spread_flow() {
        // Promote first: 2 MiB over 3 s.
        let signals = three_good_signals();
        let mut flow = AdaptiveFlow::new(&signals, 0, None);
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 2 * BULK_BYTES,
            },
            &signals,
            3_000,
        );
        assert_eq!(d, AdaptiveDecision::PromoteToSpread(vec![0, 1]));

        // 10 s of quiet (no byte growth since t = 3000): under
        // the 30 s threshold, stays spread.
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 2 * BULK_BYTES,
            },
            &signals,
            13_000,
        );
        assert_eq!(
            d,
            AdaptiveDecision::Stay,
            "10 s of quiet must not demote a spread flow"
        );
        assert_eq!(flow.strategy, Strategy::Spread(vec![0, 1]));

        // When it resumes it is still spread — the brief quiet
        // did not demote it, so no re-promotion is due.
        let d = flow.decide(
            &FlowObservation {
                bytes_total: 3 * BULK_BYTES,
            },
            &signals,
            14_000,
        );
        assert_eq!(d, AdaptiveDecision::Stay);
        assert_eq!(flow.strategy, Strategy::Spread(vec![0, 1]));
    }
}
