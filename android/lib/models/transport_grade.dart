import 'grade_scoring.dart';
import 'session_status.dart';

/// Per-transport grading (plan 4.50).
///
/// The user corrected 4.47: grades belong on the TRANSPORTS
/// (per path), not the session. The session-grade card was removed
/// (2026-11-17); each path gets its own grade from its OWN
/// metrics, accumulated from the same snapshot stream the home
/// screen already polls — no new timers, wakeups, permissions,
/// or server changes, and no Rust/Kotlin changes: every input
/// (RTT, QUIC loss, PING counters, byte counters) already arrives
/// per path in the snapshot.
///
/// Rubric (weights sum to 100):
///
/// * Latency (30): this path's median RTT. 100 at ≤ 50 ms,
///   0 at ≥ 500 ms, linear — the shared scoring function, reused.
/// * Stability (30): this path's flaps per hour — its QUIC PING
///   counter dropping (a re-dial restarts it from zero) or the
///   path rejoining after being inactive. Max 1 event per sample.
///   100 at 0/h, 0 at ≥ 12/h, linear — the shared scoring
///   function, reused.
///   Only scored after ≥ 60 s of sampled time for that path.
/// * Loss (20): this path's QUIC loss rate (lost / sent, from
///   the 4.49 counters). 100 at ≤ 0.1%, 0 at ≥ 10%, linear.
///   Only scored after ≥ 100 packets sent: a smaller denominator
///   is not a measurement. Non-QUIC paths never observe loss and
///   never get a loss score — never a fabricated 0.
/// * Bandwidth (20): 100 UNLESS saturation is observed — the
///   user-directed rule. Absolute throughput is NOT scored: a
///   lightly-used path is not a slow path. A window counts as
///   active when bytes moved in it; it counts as saturated when,
///   under that load, RTT inflates against the path's own
///   low-water mark (≥ 1.5× and ≥ +100 ms) or the interval loss
///   rate spikes (≥ 5% over ≥ 20 packets sent). Score =
///   100 × (1 − saturated / active). Only scored after ≥ 10
///   active windows: before that there is nothing to judge, so
///   the component is excluded (not assumed 100 with no data).
///   NOT implemented: throughput plateauing while demand exists —
///   there is no demand signal in the snapshot (no per-path queue
///   depth), so a plateau cannot be distinguished from light use.
///   RTT inflation and loss spikes under load are the observable
///   saturation signals we have.
///
/// Every component is optional at runtime: no data yet →
/// excluded, total rebalances proportionally over the components
/// that do have data (total = Σ w·s / Σ w). The detail view shows
/// each sub-score and its measurement, so the grade is explainable.
/// Letters: 90+ A, 80+ B, 70+ C, 60+ D, below 60 F, no
/// plus/minus — reused from the shared scoring primitives.
///
/// Exploration prior (4.86): a transport with insufficient data
/// — not enough traffic to measure loss or bandwidth — grades 99,
/// not its thin measured total. An idle leg would otherwise grade
/// low on RTT alone (a peer relay at 300 ms scores ~44) and never
/// win traffic in BestTransport, so it never gathers the data
/// that would raise it: the feedback loop. 99 is just below a
/// known-perfect 100 and above most known-worse, so the leg gets
/// tried, gathers data, and then earns a real grade. The prior is
/// marked on the grade ([TransportGrade.isPrior]) and explained
/// in the detail view; it ends as soon as the transport meets
/// either traffic threshold (≥ 100 packets sent for loss, or
/// ≥ 10 active windows for bandwidth).
///
/// Sampling limits: the grade only sees what the snapshot stream
/// backgrounded, home screen left) are skipped as unknown time;
/// flaps and saturation between samples are missed at that
/// cadence. Medians come from the shared RTT histogram buckets;
/// the detail view shows the band, never a fake-precise number.
class TransportGrade {
  /// Rounded 0–100 total over the components that have data.
  final int total;

  /// A, B, C, D, or F: 90+ A, 80+ B, 70+ C, 60+ D, below 60 F.
  final String letter;

  /// Sub-scores 0–100, null when the component has no data yet.
  final double? latencyScore;
  final double? stabilityScore;
  final double? lossScore;
  final double? bandwidthScore;

  /// The measurement behind each sub-score, for the detail view.
  /// Null alongside a null score.
  final String? latencyDetail;
  final String? stabilityDetail;
  final String? lossDetail;
  final String? bandwidthDetail;

  /// Sampled time the grade covers for this path, and how many
  /// snapshot intervals contributed.
  final Duration sampledFor;
  final int sampleCount;

  /// True when the total is the 99 exploration prior (plan 4.86),
  /// not a measured grade: the transport has not yet carried
  /// enough traffic to measure loss or bandwidth, so it is graded
  /// 99 — just below a known-perfect 100, above most known-worse —
  /// so BestTransport tries it and it gathers data. The sub-scores
  /// are still the honest measurements (they may show what little
  /// data exists); only the total is the prior. Once the transport
  /// carries enough traffic the grade becomes measured.
  final bool isPrior;

  const TransportGrade({
    required this.total,
    required this.letter,
    required this.latencyScore,
    required this.stabilityScore,
    required this.lossScore,
    required this.bandwidthScore,
    required this.latencyDetail,
    required this.stabilityDetail,
    required this.lossDetail,
    required this.bandwidthDetail,
    required this.sampledFor,
    required this.sampleCount,
    this.isPrior = false,
  });
}

/// Pure scoring functions, one per component new to this slice.
/// Latency, stability, letters, and the rebalanced total are
/// reused from `grade_scoring.dart`.

/// QUIC loss rate, 0–1: 100 at ≤ 0.1%, 0 at ≥ 10%, linear.
double lossScoreFromRate(double rate) =>
    ((0.10 - rate) / 0.099).clamp(0.0, 1.0).toDouble() * 100;

/// Share of active windows that were saturated, 0–1: 100 when
/// none saturated, 0 when all were.
double bandwidthScoreFromSaturatedShare(double share) =>
    (1 - share.clamp(0.0, 1.0)) * 100;

/// Accumulation state for one path, keyed by [PathStat.gradeKey].
class _PathGradeState {
  final List<int> rttBuckets = List.filled(6, 0);
  int rttSamples = 0;

  /// Lowest RTT seen on this path so far (ms); the baseline the
  /// saturation check inflates against. Null until the first
  /// RTT sample.
  int? lowWaterRttMs;

  int flapEvents = 0;
  int sampledMs = 0;
  int samples = 0;

  /// Accumulated QUIC loss deltas since tracking began.
  int lostTotal = 0;
  int sentTotal = 0;

  /// Active windows (bytes moved) and how many of them showed
  /// a saturation signal.
  int activeIntervals = 0;
  int saturatedIntervals = 0;

  bool? prevActive;
  int? prevPingFrames;
  int? prevInBytes;
  int? prevOutBytes;
  int? prevLostPackets;
  int? prevSentPackets;
  bool hasBaseline = false;
}

/// Accumulates one grade per transport from the snapshot stream.
/// Fed by the home screen on its existing poll tick — the tracker
/// itself adds no timers or sampling of its own.
///
/// A flap is one event per sample at most: this path's QUIC PING
/// counter dropping (a re-dial restarts it from zero) or the path
/// rejoining after being inactive. WS paths report no PING
/// counter and cannot contribute re-dial detection.
class TransportGradeTracker {
  static const weights = {
    'latency': 30.0,
    'stability': 30.0,
    'loss': 20.0,
    'bandwidth': 20.0,
  };

  /// Stability needs this much sampled time before it scores.
  static const minStabilityMs = 60000;

  /// Loss needs this many packets sent before it scores.
  static const minLossSentPackets = 100;

  /// Bandwidth needs this many active windows before it scores.
  static const minBandwidthActiveIntervals = 10;

  /// Intervals longer than this are unknown time (app
  /// backgrounded, home screen left): skipped, not counted up
  /// or down. 35 s admits the 30 s background cadence.
  static const maxIntervalMs = 35000;

  /// Flaps/h at which Stability hits zero.
  static const maxFlapsPerHour = 12.0;

  /// Saturation signals (see the file doc comment): RTT
  /// inflation vs the path's low-water mark, and an interval
  /// loss spike under load.
  static const minRttInflationMs = 100;
  static const minRttInflationFactor = 1.5;
  static const minLossSpikePackets = 20;
  static const lossSpikeRate = 0.05;

  /// Exploration prior (plan 4.86): a transport with insufficient
  /// data grades this, not its thin measured total. 99 is just
  /// below a known-perfect 100 and above most known-worse
  /// transports, so BestTransport tries it and it gathers data.
  /// Insufficient data means it has not yet carried enough traffic
  /// to measure loss (fewer than [minLossSentPackets] sent) AND
  /// has not yet had enough active windows to measure bandwidth
  /// (fewer than [minBandwidthActiveIntervals]): essentially
  /// unmeasured. Once either threshold is met the grade becomes
  /// the measured total. A bad leg is bounded by this: it gets one
  /// flow's worth of traffic, then a real grade (and send-failure
  /// eviction if it cannot carry it).
  static const priorGradeTotal = 99;

  int _sessionId = 0;
  DateTime? _lastSampleAt;
  final Map<String, _PathGradeState> _paths = {};

  /// The grade for one path by its [PathStat.gradeKey], or null
  /// when the path has no data yet.
  TransportGrade? gradeFor(String key) {
    final state = _paths[key];
    if (state == null) return null;
    return _grade(state);
  }

  /// Grades for every path with data, keyed by [PathStat.gradeKey].
  Map<String, TransportGrade> get grades {
    final out = <String, TransportGrade>{};
    for (final entry in _paths.entries) {
      final grade = _grade(entry.value);
      if (grade != null) out[entry.key] = grade;
    }
    return out;
  }

  TransportGrade? _grade(_PathGradeState state) {
    double? latencyScore;
    String? latencyDetail;
    if (state.rttSamples > 0) {
      final bucket = medianBucketIndex(state.rttBuckets);
      latencyScore = latencyScoreFromMedianRtt(rttMidpoints[bucket]);
      latencyDetail = rttBandLabel(bucket);
    }

    double? stabilityScore;
    String? stabilityDetail;
    if (state.sampledMs >= minStabilityMs) {
      final hours = state.sampledMs / 3600000;
      final rate = state.flapEvents / hours;
      stabilityScore = stabilityScoreFromFlapsPerHour(rate);
      stabilityDetail =
          '${state.flapEvents} flap${state.flapEvents == 1 ? '' : 's'} · '
          '${rate.toStringAsFixed(1)}/h';
    }

    double? lossScore;
    String? lossDetail;
    if (state.sentTotal >= minLossSentPackets) {
      final rate = state.lostTotal / state.sentTotal;
      lossScore = lossScoreFromRate(rate);
      lossDetail =
          '${(rate * 100).toStringAsFixed(1)}% lost · '
          '${state.lostTotal}/${state.sentTotal} packets';
    }

    double? bandwidthScore;
    String? bandwidthDetail;
    if (state.activeIntervals >= minBandwidthActiveIntervals) {
      final share = state.saturatedIntervals / state.activeIntervals;
      bandwidthScore = bandwidthScoreFromSaturatedShare(share);
      bandwidthDetail = state.saturatedIntervals > 0
          ? '${state.saturatedIntervals} of ${state.activeIntervals} '
              'active windows saturated'
          : 'no saturation in ${state.activeIntervals} active windows';
    }

    // Exploration prior (4.86): insufficient data — not enough
    // traffic to measure loss or bandwidth — grades 99 so this
    // transport gets tried and gathers data. The sub-scores stay
    // the honest measurements (they may show what little data
    // exists); only the total is the prior.
    final insufficientData = state.sentTotal < minLossSentPackets &&
        state.activeIntervals < minBandwidthActiveIntervals;
    if (insufficientData) {
      return TransportGrade(
        total: priorGradeTotal,
        letter: letterForScore(priorGradeTotal),
        latencyScore: latencyScore,
        stabilityScore: stabilityScore,
        lossScore: lossScore,
        bandwidthScore: bandwidthScore,
        latencyDetail: latencyDetail,
        stabilityDetail: stabilityDetail,
        lossDetail: lossDetail,
        bandwidthDetail: bandwidthDetail,
        sampledFor: Duration(milliseconds: state.sampledMs),
        sampleCount: state.samples,
        isPrior: true,
      );
    }

    final total = totalScore([
      WeightedComponent(weights['latency']!, latencyScore),
      WeightedComponent(weights['stability']!, stabilityScore),
      WeightedComponent(weights['loss']!, lossScore),
      WeightedComponent(weights['bandwidth']!, bandwidthScore),
    ]);
    if (total == null) return null;
    return TransportGrade(
      total: total,
      letter: letterForScore(total),
      latencyScore: latencyScore,
      stabilityScore: stabilityScore,
      lossScore: lossScore,
      bandwidthScore: bandwidthScore,
      latencyDetail: latencyDetail,
      stabilityDetail: stabilityDetail,
      lossDetail: lossDetail,
      bandwidthDetail: bandwidthDetail,
      sampledFor: Duration(milliseconds: state.sampledMs),
      sampleCount: state.samples,
      isPrior: false,
    );
  }

  /// Starts a new session (connectedAtMs as the id). Resets all
  /// per-path accumulation: path keys and counters do not carry
  /// across sessions.
  void beginSession(int connectedAtMs) {
    _reset();
    _sessionId = connectedAtMs;
  }

  /// One snapshot sample. Call on the existing poll tick while
  /// connected; samples outside a session are ignored. A session
  /// id change re-baselines without counting (the home screen
  /// normally calls [beginSession] first).
  void record(SessionStatus status, DateTime now) {
    if (!status.isConnected) return;
    if (status.connectedAtMs != _sessionId) {
      _reset();
      _sessionId = status.connectedAtMs;
    }
    final prevAt = _lastSampleAt;
    final dtMs = prevAt == null
        ? 0
        : now.difference(prevAt).inMilliseconds;
    // Keys are computed once per sample so a peer's legs share one
    // numbering with the display (4.108): the ordinal is part of the
    // key, so two legs to the same peer accumulate separately.
    final keys = gradeKeysForPaths(status.paths);
    if (prevAt == null || dtMs <= 0 || dtMs > maxIntervalMs) {
      // First sample, clock oddity, or a gap the stream did not
      // observe (backgrounded): re-baseline every path present,
      // count nothing. Paths absent from this sample lose their
      // baseline too, so their deltas never span the gap when
      // they return.
      _lastSampleAt = now;
      for (final state in _paths.values) {
        state.hasBaseline = false;
      }
      for (var i = 0; i < status.paths.length; i++) {
        final state = _paths.putIfAbsent(
          keys[i],
          () => _PathGradeState(),
        );
        _rebaseline(state, status.paths[i]);
      }
      return;
    }

    for (var i = 0; i < status.paths.length; i++) {
      final path = status.paths[i];
      final state = _paths.putIfAbsent(
        keys[i],
        () => _PathGradeState(),
      );
      if (!state.hasBaseline) {
        _rebaseline(state, path);
        continue;
      }
      state.sampledMs += dtMs;
      state.samples++;

      final rtt = path.lastRttMs;
      if (rtt > 0) {
        state.rttBuckets[bucketIndex(rtt, rttBounds)]++;
        state.rttSamples++;
      }

      // Stability: a re-dial (PING counter restarts from zero)
      // or a rejoin after being inactive. At most one flap per
      // sample per path.
      var flapped = false;
      final prevPing = state.prevPingFrames;
      final ping = path.quicPingFrames;
      if (prevPing != null && ping != null && ping < prevPing) {
        flapped = true;
      }
      if (state.prevActive == false && path.active) {
        flapped = true;
      }
      if (flapped) state.flapEvents++;

      // Loss deltas from the cumulative counters. A negative
      // delta is a counter reset (re-dial), not negative loss.
      final lostDelta = _delta(path.quicLostPackets, state.prevLostPackets);
      final sentDelta = _delta(path.quicSentPackets, state.prevSentPackets);
      if (lostDelta != null && sentDelta != null) {
        state.lostTotal += lostDelta;
        state.sentTotal += sentDelta;
      }

      // Bandwidth: an active window moved bytes. It is saturated
      // when RTT inflates against this path's low-water mark
      // under that load, or the interval loss rate spikes.
      // The low-water mark is from earlier samples only — the
      // current sample cannot inflate against itself.
      final inDelta = _delta(path.inboundBytes, state.prevInBytes) ?? 0;
      final outDelta = _delta(path.outboundBytes, state.prevOutBytes) ?? 0;
      final moved = inDelta + outDelta;
      if (moved > 0) {
        state.activeIntervals++;
        final lowWater = state.lowWaterRttMs;
        final rttInflated = lowWater != null &&
            rtt > 0 &&
            rtt >= lowWater * minRttInflationFactor &&
            rtt - lowWater >= minRttInflationMs;
        final lossSpike = sentDelta != null &&
            sentDelta >= minLossSpikePackets &&
            lostDelta != null &&
            lostDelta / sentDelta >= lossSpikeRate;
        if (rttInflated || lossSpike) state.saturatedIntervals++;
      }

      if (rtt > 0) {
        final lowWater = state.lowWaterRttMs;
        state.lowWaterRttMs =
            lowWater == null || rtt < lowWater ? rtt : lowWater;
      }

      state.prevActive = path.active;
      state.prevPingFrames = path.quicPingFrames;
      state.prevInBytes = path.inboundBytes;
      state.prevOutBytes = path.outboundBytes;
      state.prevLostPackets = path.quicLostPackets;
      state.prevSentPackets = path.quicSentPackets;
      state.hasBaseline = true;
    }
    _lastSampleAt = now;
  }

  /// Non-negative delta between cumulative counters, or null when
  /// either side is unmeasured. A drop (counter reset) counts as
  /// zero and re-baselines on the next sample via the stored prev.
  int? _delta(int? current, int? prev) {
    if (current == null || prev == null) return null;
    final d = current - prev;
    return d < 0 ? 0 : d;
  }

  void _rebaseline(_PathGradeState state, PathStat path) {
    state.prevActive = path.active;
    state.prevPingFrames = path.quicPingFrames;
    state.prevInBytes = path.inboundBytes;
    state.prevOutBytes = path.outboundBytes;
    state.prevLostPackets = path.quicLostPackets;
    state.prevSentPackets = path.quicSentPackets;
    state.hasBaseline = true;
  }

  void _reset() {
    _sessionId = 0;
    _lastSampleAt = null;
    _paths.clear();
  }
}
