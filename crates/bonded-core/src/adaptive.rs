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
//! This is the policy module + its simulation tests, nothing else.
//! There is no `TrafficMode::Adaptive` variant, no change to
//! [`TrafficModeEngine`], no wiring into the flow-pin points (the
//! Linux client loop / the Android worker), the FFI, the Android
//! app, or the server. The caller is responsible for feeding the
//! policy: create one [`AdaptiveFlow`] per flow (at the same point
//! it would resolve the flow's mode), call
//! [`AdaptiveFlow::decide`] on its poll tick with the flow's
//! cumulative bytes and the current per-transport signals (built
//! the same way the FFI's `path_signals` builds them — grades from
//! `path_grades_snapshot`, RTT from the last heartbeat pong, loss
//! from the QUIC counters), and apply the returned
//! [`AdaptiveDecision`]. Times are milliseconds on a monotonic
//! clock supplied by the caller, so the policy is testable without
//! wall time.
//!
//! # Open questions (for the real implementation, not this POC)
//!
//! * **Demotion:** a bulk flow that goes quiet stays spread for the
//!   rest of its life. Demoting it back to a single leg would save
//!   nothing (a quiet flow sends little) and risks flapping between
//!   spread and single; the POC does not demote. Whether the real
//!   implementation should demote after a long idle period is open.
//! * **Cold start:** a flow created before any signals exist starts
//!   on leg 0. When signals first arrive and another leg is clearly
//!   ahead (by [`MOVE_GRADE_GAP`]), the policy (re)places it — see
//!   the `first_signals` arm in [`AdaptiveFlow::decide`].
//! * **Mid-handover degradation:** a leg degrading *during* a
//!   500 ms duplication window is not re-evaluated until the window
//!   settles. The window is short enough that this is acceptable
//!   for the POC; the real implementation may want to re-check.

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
    /// hysteresis → degradation → bulk promotion → spread re-rank.
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

        // 5. Spread: re-rank the spread set. A degraded leg is
        // replaced by the new top two — no duplication is needed,
        // the flow already covers two legs and the good one keeps
        // carrying it.
        if let Strategy::Spread(legs) = &self.strategy {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic_mode::PathSignal;

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
}
