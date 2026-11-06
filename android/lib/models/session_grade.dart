import 'session_status.dart';

/// Session grading (plan 4.47).
///
/// One VPN session, connect → disconnect, graded live on the home
/// screen from the snapshot stream the app already has (the 1 s
/// UI-active / 30 s background ticks). No new timers, no new
/// wakeups, no new permissions, no server changes, and no battery
/// data in the score: battery was deliberately excluded from the
/// grade by the user (2026-11-06) — the 4.46 profiler and Battery
/// card are untouched, battery just isn't scored.
///
/// Rubric (weights sum to 100):
///
/// * Latency (30): session median RTT of the active path.
///   100 at ≤ 50 ms, 0 at ≥ 500 ms, linear between.
/// * Stability (30): path flaps per hour — the active-path set
///   changing, or a path's QUIC PING counter dropping (a re-dial
///   restarts it from zero). 100 at 0 flaps/h, 0 at ≥ 12 flaps/h,
///   linear between. Only scored after ≥ 60 s of sampled time: a
///   shorter session cannot be judged for stability.
/// * Availability (20): share of sampled session time with at least
///   one active path. Only scored after ≥ 10 s of sampled time.
/// * Bandwidth (20): median combined (up + down) throughput over
///   ACTIVE windows only — a window counts only when bytes moved
///   in it, so idle windows (no traffic expected) never drag the
///   score down. This is the per-window form of the existing idle
///   definition (no traffic for 60 s): a window with no bytes moved
///   is an idle window. 100 at ≥ 10 Mbps, 0 at ≤ 0.1 Mbps, linear
///   between. The bands are a coarse, network-independent scale
///   chosen for explainability, not a calibrated baseline: a tunnel
///   that only manages ~1 Mbps while active is a poor session on
///   any network.
///
/// Every component is optional at runtime: a component with no
/// data yet scores nothing and the total rebalances proportionally
/// over the components that do have data (total = Σ w·s / Σ w).
/// The card shows each sub-score and its measurement, so the grade
/// is explainable — never a black-box number.
///
/// Sampling limits, stated on the card: the grade only sees what
/// the snapshot stream sees. Flaps between samples are missed
/// (1 s cadence while the home screen is visible, 30 s otherwise);
/// intervals longer than 35 s (app backgrounded, home screen left)
/// are skipped as unknown time rather than counted up or down;
/// medians are estimated from histogram bands, so the card shows
/// the band, not an exact value.
class SessionGrade {
  /// Rounded 0–100 total over the components that have data.
  final int total;

  /// A, B, C, D, or F: 90+ A, 80+ B, 70+ C, 60+ D, below 60 F.
  final String letter;

  /// Sub-scores 0–100, null when the component has no data yet.
  final double? latencyScore;
  final double? stabilityScore;
  final double? availabilityScore;
  final double? bandwidthScore;

  /// The measurement behind each sub-score, for the card.
  /// Null alongside a null score.
  final String? latencyDetail;
  final String? stabilityDetail;
  final String? availabilityDetail;
  final String? bandwidthDetail;

  /// Sampled session time the grade covers, and how many snapshot
  /// intervals contributed.
  final Duration sampledFor;
  final int sampleCount;

  const SessionGrade({
    required this.total,
    required this.letter,
    required this.latencyScore,
    required this.stabilityScore,
    required this.availabilityScore,
    required this.bandwidthScore,
    required this.latencyDetail,
    required this.stabilityDetail,
    required this.availabilityDetail,
    required this.bandwidthDetail,
    required this.sampledFor,
    required this.sampleCount,
  });
}

/// One graded component's weight and score, for the rebalancing
/// total. A null score means the component has no data yet and is
/// excluded (weights rebalance over the rest).
class WeightedComponent {
  final double weight;
  final double? score;
  const WeightedComponent(this.weight, this.score);
}

/// Pure scoring functions, one per component. Each maps its
/// measurement to 0–100 and is unit-tested directly.

/// Median active-path RTT in ms: 100 at ≤ 50 ms, 0 at ≥ 500 ms.
double latencyScoreFromMedianRtt(double medianMs) =>
    _clamp01((500 - medianMs) / 450) * 100;

/// Flaps per hour: 100 at 0, 0 at ≥ 12.
double stabilityScoreFromFlapsPerHour(double flapsPerHour) =>
    _clamp01((12 - flapsPerHour) / 12) * 100;

/// Share of sampled time with a live path, 0–1.
double availabilityScoreFromShare(double share) => _clamp01(share) * 100;

/// Median combined throughput over active windows, in Mbps:
/// 100 at ≥ 10 Mbps, 0 at ≤ 0.1 Mbps.
double bandwidthScoreFromMbps(double mbps) =>
    _clamp01((mbps - 0.1) / 9.9) * 100;

/// Letter bands: 90+ A, 80+ B, 70+ C, 60+ D, below 60 F.
String letterForScore(int total) {
  if (total >= 90) return 'A';
  if (total >= 80) return 'B';
  if (total >= 70) return 'C';
  if (total >= 60) return 'D';
  return 'F';
}

/// Weighted total over the components that have data, rebalanced
/// proportionally. Null when no component has data yet.
int? totalScore(List<WeightedComponent> components) {
  double weightSum = 0;
  double scoreSum = 0;
  for (final c in components) {
    if (c.score == null) continue;
    weightSum += c.weight;
    scoreSum += c.weight * c.score!;
  }
  if (weightSum == 0) return null;
  return (scoreSum / weightSum).round();
}

double _clamp01(double value) => value.clamp(0.0, 1.0).toDouble();

/// Median bucket of a histogram: the bucket holding the 50th
/// percentile. Bounded memory (one counter per bucket) at the
/// cost of an approximate median — the bands are the point, not
/// the exact value, so the card shows the band ("median 50–100
/// ms"), never a fake-precise number. Scores interpolate from
/// the bucket midpoint (a documented convention).
int _medianBucketIndex(List<int> counts) {
  final total = counts.fold(0, (a, b) => a + b);
  if (total == 0) return 0;
  var seen = 0;
  final target = (total + 1) ~/ 2;
  for (var i = 0; i < counts.length; i++) {
    seen += counts[i];
    if (seen >= target) return i;
  }
  return counts.length - 1;
}

/// RTT histogram buckets (ms). Upper bounds [50, 100, 200, 350,
/// 500, ∞]; midpoints used for the score interpolation (the open
/// top bucket counts as 750 ms).
const _rttBounds = [50, 100, 200, 350, 500];
const _rttMidpoints = [25.0, 75.0, 150.0, 275.0, 425.0, 750.0];

String _rttBandLabel(int bucket) {
  if (bucket == 0) return 'median ≤ 50 ms';
  if (bucket >= _rttBounds.length) return 'median > 500 ms';
  return 'median ${_rttBounds[bucket - 1]}–${_rttBounds[bucket]} ms';
}

/// Throughput histogram buckets (bytes/s). Upper bounds at 0.1,
/// 1, 5, 10 Mbps; midpoints in Mbps used for the score
/// interpolation (the open top bucket counts as 15 Mbps).
const _bwBounds = [12500, 125000, 625000, 1250000];
const _bwBoundsMbps = [0.1, 1.0, 5.0, 10.0];
const _bwMidpoints = [0.05, 0.55, 3.0, 7.5, 15.0];

String _bwBandLabel(int bucket) {
  if (bucket == 0) return 'median ≤ 0.1 Mbps';
  if (bucket >= _bwBoundsMbps.length) return 'median > 10 Mbps';
  return 'median ${_bwBoundsMbps[bucket - 1]}–${_bwBoundsMbps[bucket]} Mbps';
}

int _bucketIndex(int value, List<int> bounds) {
  for (var i = 0; i < bounds.length; i++) {
    if (value <= bounds[i]) return i;
  }
  return bounds.length;
}

/// Accumulates one session's grade from the snapshot stream.
/// Fed by the home screen on its existing poll tick — the tracker
/// itself adds no timers or sampling of its own.
///
/// A flap is one event per sample at most: the active-path set
/// changing, or any path's QUIC PING counter dropping (a re-dial
/// restarts it from zero). WS paths report no PING counter and
/// cannot contribute re-dial detection.
class SessionGradeTracker {
  static const weights = {
    'latency': 30.0,
    'stability': 30.0,
    'availability': 20.0,
    'bandwidth': 20.0,
  };

  /// Stability needs this much sampled time before it scores;
  /// availability needs [minAvailabilityMs].
  static const minStabilityMs = 60000;
  static const minAvailabilityMs = 10000;

  /// Intervals longer than this are unknown time (app
  /// backgrounded, home screen left): skipped, not counted up
  /// or down. 35 s admits the 30 s background cadence.
  static const maxIntervalMs = 35000;

  /// Flaps/h at which Stability hits zero.
  static const maxFlapsPerHour = 12.0;

  int _sessionId = 0;
  DateTime? _lastSampleAt;
  int? _lastInBytes;
  int? _lastOutBytes;
  Set<String> _prevActiveKeys = {};
  Map<String, int?> _prevPingFrames = {};
  bool _hasBaseline = false;

  final List<int> _rttBuckets = List.filled(6, 0);
  int _rttSamples = 0;
  int _flapEvents = 0;
  int _sampledMs = 0;
  int _upMs = 0;
  final List<int> _bwBuckets = List.filled(5, 0);
  int _bwSamples = 0;
  int _samples = 0;

  bool get hasData => _samples > 0;

  /// Starts a new session (connectedAtMs as the id), returning
  /// the previous session's grade if it had one. Resets all
  /// accumulation.
  SessionGrade? beginSession(int connectedAtMs) {
    final prev = grade;
    _reset();
    _sessionId = connectedAtMs;
    return prev;
  }

  /// The current session's grade so far, or null when no
  /// component has data yet. Call when the session ends to keep
  /// the final grade; the tracker keeps its state until the next
  /// [beginSession].
  SessionGrade? get grade {
    double? latencyScore;
    String? latencyDetail;
    if (_rttSamples > 0) {
      final bucket = _medianBucketIndex(_rttBuckets);
      latencyScore = latencyScoreFromMedianRtt(_rttMidpoints[bucket]);
      latencyDetail = _rttBandLabel(bucket);
    }

    double? stabilityScore;
    String? stabilityDetail;
    if (_sampledMs >= minStabilityMs) {
      final hours = _sampledMs / 3600000;
      final rate = _flapEvents / hours;
      stabilityScore = stabilityScoreFromFlapsPerHour(rate);
      stabilityDetail =
          '$_flapEvents flap${_flapEvents == 1 ? '' : 's'} · '
          '${rate.toStringAsFixed(1)}/h';
    }

    double? availabilityScore;
    String? availabilityDetail;
    if (_sampledMs >= minAvailabilityMs) {
      final share = _upMs / _sampledMs;
      availabilityScore = availabilityScoreFromShare(share);
      availabilityDetail = '${(share * 100).toStringAsFixed(0)}% up';
    }

    double? bandwidthScore;
    String? bandwidthDetail;
    if (_bwSamples > 0) {
      final bucket = _medianBucketIndex(_bwBuckets);
      bandwidthScore = bandwidthScoreFromMbps(_bwMidpoints[bucket]);
      bandwidthDetail = '${_bwBandLabel(bucket)} (active windows)';
    }

    final total = totalScore([
      WeightedComponent(weights['latency']!, latencyScore),
      WeightedComponent(weights['stability']!, stabilityScore),
      WeightedComponent(weights['availability']!, availabilityScore),
      WeightedComponent(weights['bandwidth']!, bandwidthScore),
    ]);
    if (total == null) return null;
    return SessionGrade(
      total: total,
      letter: letterForScore(total),
      latencyScore: latencyScore,
      stabilityScore: stabilityScore,
      availabilityScore: availabilityScore,
      bandwidthScore: bandwidthScore,
      latencyDetail: latencyDetail,
      stabilityDetail: stabilityDetail,
      availabilityDetail: availabilityDetail,
      bandwidthDetail: bandwidthDetail,
      sampledFor: Duration(milliseconds: _sampledMs),
      sampleCount: _samples,
    );
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
    final activeKeys = _activeKeys(status);
    final pingFrames = _pingFrames(status);
    if (prevAt == null || dtMs <= 0 || dtMs > maxIntervalMs) {
      // First sample, clock oddity, or a gap the stream did not
      // observe (backgrounded): re-baseline, count nothing.
      _lastSampleAt = now;
      _lastInBytes = status.inboundBytes;
      _lastOutBytes = status.outboundBytes;
      _prevActiveKeys = activeKeys;
      _prevPingFrames = pingFrames;
      _hasBaseline = true;
      return;
    }
    _sampledMs += dtMs;
    _samples++;
    if (status.activePath != null) _upMs += dtMs;

    final rtt = status.activePath?.lastRttMs ?? 0;
    if (rtt > 0) {
      _rttBuckets[_bucketIndex(rtt, _rttBounds)]++;
      _rttSamples++;
    }

    if (_hasBaseline) {
      final setChanged =
          activeKeys.length != _prevActiveKeys.length ||
          !activeKeys.containsAll(_prevActiveKeys);
      var pingDropped = false;
      for (final entry in pingFrames.entries) {
        final prev = _prevPingFrames[entry.key];
        final current = entry.value;
        if (prev != null && current != null && current < prev) {
          pingDropped = true;
          break;
        }
      }
      if (setChanged || pingDropped) _flapEvents++;
    }

    final inDelta = status.inboundBytes - (_lastInBytes ?? 0);
    final outDelta = status.outboundBytes - (_lastOutBytes ?? 0);
    // Cumulative counters only move forward; a negative delta is
    // a counter reset, not negative throughput.
    final moved = (inDelta < 0 ? 0 : inDelta) + (outDelta < 0 ? 0 : outDelta);
    if (moved > 0) {
      final rateBps = moved / (dtMs / 1000);
      _bwBuckets[_bucketIndex(rateBps.round(), _bwBounds)]++;
      _bwSamples++;
    }

    _lastSampleAt = now;
    _lastInBytes = status.inboundBytes;
    _lastOutBytes = status.outboundBytes;
    _prevActiveKeys = activeKeys;
    _prevPingFrames = pingFrames;
    _hasBaseline = true;
  }

  Set<String> _activeKeys(SessionStatus status) {
    final keys = <String>{};
    for (final path in status.paths) {
      if (!path.active) continue;
      if (path.isDirect) {
        keys.add('d${path.pathIndex}');
      } else {
        keys.add('r${path.peerId ?? '?'}:${path.kind}');
      }
    }
    return keys;
  }

  Map<String, int?> _pingFrames(SessionStatus status) {
    final out = <String, int?>{};
    for (final path in status.paths) {
      final key = path.isDirect
          ? 'd${path.pathIndex}'
          : 'r${path.peerId ?? '?'}:${path.kind}';
      out[key] = path.quicPingFrames;
    }
    return out;
  }

  void _reset() {
    _sessionId = 0;
    _lastSampleAt = null;
    _lastInBytes = null;
    _lastOutBytes = null;
    _prevActiveKeys = {};
    _prevPingFrames = {};
    _hasBaseline = false;
    _rttBuckets.fillRange(0, _rttBuckets.length, 0);
    _rttSamples = 0;
    _flapEvents = 0;
    _sampledMs = 0;
    _upMs = 0;
    _bwBuckets.fillRange(0, _bwBuckets.length, 0);
    _bwSamples = 0;
    _samples = 0;
  }
}

/// "3m 12s" style duration for the card's sample line.
String formatSampledFor(Duration duration) {
  final totalSeconds = duration.inSeconds;
  final hours = totalSeconds ~/ 3600;
  final minutes = (totalSeconds % 3600) ~/ 60;
  final seconds = totalSeconds % 60;
  if (hours > 0) return '${hours}h ${minutes}m';
  if (minutes > 0) return '${minutes}m ${seconds}s';
  return '${seconds}s';
}
