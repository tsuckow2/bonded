/// Shared grading primitives, used by the per-transport grader
/// (plan 4.50).
///
/// These were originally written for the 4.47 session-grade card,
/// which Tom removed (2026-11-17): grades belong on the transports,
/// not the session. The session-only code (SessionGrade,
/// SessionGradeTracker, availability and absolute-bandwidth
/// scoring) is gone; what remains here is what the per-transport
/// grader reuses: the weighted-total rebalancing, the RTT
/// histogram buckets and median convention, the latency/stability
/// scoring functions, the letter bands, and the duration format.
///
/// Every component is optional at runtime: a component with no
/// data yet scores nothing and the total rebalances proportionally
/// over the components that do have data (total = Σ w·s / Σ w).
/// The grade is explainable — never a black-box number.
///
/// Medians are estimated from histogram bands, so the grade shows
/// the band, not an exact value. Scores interpolate from the
/// bucket midpoint (a documented convention).
library;

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
/// the exact value, so the grade shows the band ("median 50–100
/// ms"), never a fake-precise number. Scores interpolate from
/// the bucket midpoint (a documented convention).
///
/// Public so the per-transport grader (4.50) shares the same
/// buckets and median convention instead of duplicating them.
int medianBucketIndex(List<int> counts) {
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
/// top bucket counts as 750 ms). Shared with the per-transport
/// grader (4.50).
const rttBounds = [50, 100, 200, 350, 500];
const rttMidpoints = [25.0, 75.0, 150.0, 275.0, 425.0, 750.0];

String rttBandLabel(int bucket) {
  if (bucket == 0) return 'median ≤ 50 ms';
  if (bucket >= rttBounds.length) return 'median > 500 ms';
  return 'median ${rttBounds[bucket - 1]}–${rttBounds[bucket]} ms';
}

/// Bucket index for [value] against ascending [bounds]; the
/// open top bucket is `bounds.length`. Shared with the
/// per-transport grader (4.50).
int bucketIndex(int value, List<int> bounds) {
  for (var i = 0; i < bounds.length; i++) {
    if (value <= bounds[i]) return i;
  }
  return bounds.length;
}

/// "3m 12s" style duration for the grade's sample line.
String formatSampledFor(Duration duration) {
  final totalSeconds = duration.inSeconds;
  final hours = totalSeconds ~/ 3600;
  final minutes = (totalSeconds % 3600) ~/ 60;
  final seconds = totalSeconds % 60;
  if (hours > 0) return '${hours}h ${minutes}m';
  if (minutes > 0) return '${minutes}m ${seconds}s';
  return '${seconds}s';
}
