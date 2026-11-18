import 'package:bonded_app/models/grade_scoring.dart';
import 'package:flutter_test/flutter_test.dart';

/// Shared grading primitives (plan 4.50), salvaged from the
/// removed 4.47 session-grade tests: the latency/stability/letter
/// scoring functions, the rebalanced total, and the duration
/// formatter. The session-only tests (availability, absolute
/// bandwidth, SessionGradeTracker) are gone with the session
/// grade card (2026-11-17).
void main() {
  group('scoring functions', () {
    test('latency: full marks at 50 ms, zero at 500 ms, linear between', () {
      expect(latencyScoreFromMedianRtt(50), 100);
      expect(latencyScoreFromMedianRtt(20), 100);
      expect(latencyScoreFromMedianRtt(500), 0);
      expect(latencyScoreFromMedianRtt(900), 0);
      expect(latencyScoreFromMedianRtt(275), closeTo(50, 0.001));
    });

    test('stability: full marks at 0 flaps/h, zero at 12/h', () {
      expect(stabilityScoreFromFlapsPerHour(0), 100);
      expect(stabilityScoreFromFlapsPerHour(6), closeTo(50, 0.001));
      expect(stabilityScoreFromFlapsPerHour(12), 0);
      expect(stabilityScoreFromFlapsPerHour(100), 0);
    });

    test('letter bands: 90+ A, 80+ B, 70+ C, 60+ D, below 60 F', () {
      expect(letterForScore(100), 'A');
      expect(letterForScore(90), 'A');
      expect(letterForScore(89), 'B');
      expect(letterForScore(80), 'B');
      expect(letterForScore(79), 'C');
      expect(letterForScore(70), 'C');
      expect(letterForScore(69), 'D');
      expect(letterForScore(60), 'D');
      expect(letterForScore(59), 'F');
      expect(letterForScore(0), 'F');
    });
  });

  group('totalScore rebalancing', () {
    test('all components present: plain weighted total', () {
      // (30*100 + 30*100 + 20*100 + 20*100) / 100 = 100.
      final total = totalScore([
        const WeightedComponent(30, 100),
        const WeightedComponent(30, 100),
        const WeightedComponent(20, 100),
        const WeightedComponent(20, 100),
      ]);
      expect(total, 100);
    });

    test('missing component rebalances over the rest', () {
      // Bandwidth missing: (30*100 + 30*50 + 20*100) / 80 = 81.25 → 81.
      final total = totalScore([
        const WeightedComponent(30, 100),
        const WeightedComponent(30, 50),
        const WeightedComponent(20, 100),
        const WeightedComponent(20, null),
      ]);
      expect(total, 81);
    });

    test('no components: null total', () {
      final total = totalScore([
        const WeightedComponent(30, null),
        const WeightedComponent(30, null),
        const WeightedComponent(20, null),
        const WeightedComponent(20, null),
      ]);
      expect(total, isNull);
    });
  });

  group('formatters', () {
    test('formatSampledFor', () {
      expect(formatSampledFor(const Duration(seconds: 5)), '5s');
      expect(formatSampledFor(const Duration(minutes: 3, seconds: 12)), '3m 12s');
      expect(formatSampledFor(const Duration(hours: 2, minutes: 5)), '2h 5m');
    });
  });
}
