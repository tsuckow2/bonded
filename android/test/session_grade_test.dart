import 'package:bonded_app/models/session_grade.dart';
import 'package:bonded_app/models/session_status.dart';
import 'package:flutter_test/flutter_test.dart';

PathStat path({
  int? index = 0,
  String kind = 'h3',
  bool active = true,
  int rtt = 40,
  int? ping,
  int out = 0,
  int inb = 0,
  String? peerId,
}) => PathStat(
  pathIndex: index,
  kind: kind,
  active: active,
  outboundBytes: out,
  inboundBytes: inb,
  lastRttMs: rtt,
  serverSeenAddress: null,
  peerId: peerId,
  quicPingFrames: ping,
);

SessionStatus statusWith({
  int connectedAtMs = 1000,
  List<PathStat> paths = const [],
  int inBytes = 0,
  int outBytes = 0,
  String state = 'connected',
}) => SessionStatus(
  state: state,
  serverAddress: 'example.invalid:443',
  activeTransport: 'h3',
  transportCount: paths.length,
  peerRelayCount: 0,
  outboundBytes: outBytes,
  inboundBytes: inBytes,
  relayedUpBytes: 0,
  relayedDownBytes: 0,
  heartbeatPingsSent: 0,
  relayTasksStarted: 0,
  relayTasksEnded: 0,
  connectedAtMs: connectedAtMs,
  lastError: null,
  peerShareError: null,
  networkPathCount: paths.length,
  networkBindAddresses: const [],
  networkPathSummaries: const [],
  paths: paths,
  interception: null,
);

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

    test('availability: share maps straight to score', () {
      expect(availabilityScoreFromShare(1.0), 100);
      expect(availabilityScoreFromShare(0.5), 50);
      expect(availabilityScoreFromShare(0), 0);
    });

    test('bandwidth: full marks at 10 Mbps, zero at 0.1 Mbps', () {
      expect(bandwidthScoreFromMbps(10), 100);
      expect(bandwidthScoreFromMbps(50), 100);
      expect(bandwidthScoreFromMbps(0.1), closeTo(0, 0.001));
      expect(bandwidthScoreFromMbps(0), 0);
      expect(bandwidthScoreFromMbps(5.05), closeTo(50, 0.01));
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

  group('SessionGradeTracker', () {
    final t0 = DateTime(2026, 1, 1, 12, 0, 0);

    test('no samples: no grade', () {
      expect(SessionGradeTracker().grade, isNull);
    });

    test('non-connected snapshots are ignored', () {
      final tracker = SessionGradeTracker();
      tracker.record(
        statusWith(state: 'connecting', paths: [path()]),
        t0,
      );
      expect(tracker.grade, isNull);
      expect(tracker.hasData, isFalse);
    });

    test('latency grades the active path median RTT', () {
      final tracker = SessionGradeTracker();
      // 12 samples 1 s apart, RTT 40 ms throughout.
      for (var i = 0; i < 12; i++) {
        tracker.record(
          statusWith(paths: [path(rtt: 40)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.grade!;
      // Median lands in the ≤50 ms bucket (midpoint 25 ms) → 100.
      expect(grade.latencyScore, 100);
      expect(grade.latencyDetail, contains('ms'));
      // Availability also scores (11 s sampled ≥ 10 s): 100% up.
      expect(grade.availabilityScore, 100);
      // Stability needs 60 s: not scored yet.
      expect(grade.stabilityScore, isNull);
      // No bytes moved: bandwidth not scored.
      expect(grade.bandwidthScore, isNull);
      // Total rebalances over latency + availability only:
      // (30*100 + 20*100) / 50 = 100 → A.
      expect(grade.total, 100);
      expect(grade.letter, 'A');
    });

    test('slow RTT drags the grade down', () {
      final tracker = SessionGradeTracker();
      for (var i = 0; i < 12; i++) {
        tracker.record(
          statusWith(paths: [path(rtt: 400)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.grade!;
      // Median in the ≤500 bucket (midpoint 425 ms):
      // (500-425)/450*100 ≈ 16.7.
      expect(grade.latencyScore, closeTo(16.7, 0.1));
      // (30*16.7 + 20*100) / 50 ≈ 50 → F.
      expect(grade.total, 50);
      expect(grade.letter, 'F');
    });

    test('availability counts time with no active path as down', () {
      final tracker = SessionGradeTracker();
      for (var i = 0; i < 12; i++) {
        // Active for the first 6 samples, down for the rest.
        final active = i < 6;
        tracker.record(
          statusWith(paths: [path(active: active, rtt: 40)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.grade!;
      // 11 one-second intervals, attributed by the later sample's
      // state: samples 1–5 up (5 intervals), 6–11 down (6) →
      // 5000/11000 = 45.5% up. Total rebalances over latency +
      // availability: (30*100 + 20*45.5)/50 ≈ 78.
      expect(grade.availabilityScore, closeTo(45.5, 0.1));
      expect(grade.availabilityDetail, contains('45% up'));
      expect(grade.total, 78);
    });

    test('stability: quiet session scores 100 after 60 s', () {
      final tracker = SessionGradeTracker();
      for (var i = 0; i < 62; i++) {
        tracker.record(
          statusWith(paths: [path(rtt: 40)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.grade!;
      expect(grade.stabilityScore, 100);
      expect(grade.stabilityDetail, contains('0 flaps'));
    });

    test('stability: an active-path change counts one flap', () {
      final tracker = SessionGradeTracker();
      for (var i = 0; i < 62; i++) {
        // Switch from path 0 to path 1 halfway through.
        final paths = i < 31
            ? [path(index: 0, rtt: 40), path(index: 1, active: false, rtt: 0)]
            : [path(index: 0, active: false, rtt: 0), path(index: 1, rtt: 40)];
        tracker.record(statusWith(paths: paths), t0.add(Duration(seconds: i)));
      }
      final grade = tracker.grade!;
      // 1 flap in ~61 s ≈ 59 flaps/h → 0.
      expect(grade.stabilityScore, 0);
      expect(grade.stabilityDetail, contains('1 flap'));
    });

    test('stability: a QUIC PING counter drop counts one flap', () {
      final tracker = SessionGradeTracker();
      for (var i = 0; i < 62; i++) {
        // Re-dial at sample 31: the PING counter restarts at 0.
        final ping = i < 31 ? 100 + i : i - 31;
        tracker.record(
          statusWith(paths: [path(rtt: 40, ping: ping)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.grade!;
      expect(grade.stabilityScore, 0);
      expect(grade.stabilityDetail, contains('1 flap'));
    });

    test('stability: set change + ping drop in one sample is one flap', () {
      final tracker = SessionGradeTracker();
      for (var i = 0; i < 62; i++) {
        // At sample 31 path 1 joins while path 0's PING counter
        // restarts: both flap signals fire in the same sample.
        final paths = i < 31
            ? [path(index: 0, rtt: 40, ping: 100 + i)]
            : [
                path(index: 0, rtt: 40, ping: 0),
                path(index: 1, rtt: 40, ping: 0),
              ];
        tracker.record(statusWith(paths: paths), t0.add(Duration(seconds: i)));
      }
      final grade = tracker.grade!;
      expect(grade.stabilityDetail, contains('1 flap'));
    });

    test('bandwidth: median over active windows only', () {
      final tracker = SessionGradeTracker();
      var inBytes = 0;
      for (var i = 0; i < 12; i++) {
        // Alternate: traffic flows on even intervals, nothing on odd.
        if (i.isEven) inBytes += 2500000; // 20 Mbps over a 1 s window.
        tracker.record(
          statusWith(paths: [path(rtt: 40)], inBytes: inBytes),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.grade!;
      // 5 active windows at 20 Mbps → top bucket (> 10 Mbps) → 100.
      expect(grade.bandwidthScore, 100);
      expect(grade.bandwidthDetail, contains('> 10 Mbps'));
    });

    test('bandwidth: no traffic at all means no bandwidth score', () {
      final tracker = SessionGradeTracker();
      for (var i = 0; i < 12; i++) {
        tracker.record(
          statusWith(paths: [path(rtt: 40)]),
          t0.add(Duration(seconds: i)),
        );
      }
      expect(tracker.grade!.bandwidthScore, isNull);
    });

    test('bandwidth: a counter reset is not negative throughput', () {
      final tracker = SessionGradeTracker();
      tracker.record(
        statusWith(paths: [path(rtt: 40)], inBytes: 1000000),
        t0,
      );
      // Counter resets to 0: the delta must not crash or count.
      tracker.record(
        statusWith(paths: [path(rtt: 40)], inBytes: 0),
        t0.add(const Duration(seconds: 1)),
      );
      expect(tracker.grade!.bandwidthScore, isNull);
    });

    test('gaps over 35 s are skipped as unknown time', () {
      final tracker = SessionGradeTracker();
      tracker.record(statusWith(paths: [path(rtt: 40)]), t0);
      // 10-minute gap (app backgrounded): re-baselines, counts nothing.
      tracker.record(
        statusWith(paths: [path(rtt: 40)]),
        t0.add(const Duration(minutes: 10)),
      );
      tracker.record(
        statusWith(paths: [path(rtt: 40)]),
        t0.add(const Duration(minutes: 10, seconds: 1)),
      );
      final grade = tracker.grade!;
      // Only the last 1 s interval counted: availability needs
      // 10 s, so it is not scored; latency has 1 sample.
      expect(grade.availabilityScore, isNull);
      expect(grade.latencyScore, 100);
      expect(grade.sampledFor, const Duration(seconds: 1));
    });

    test('beginSession returns the previous grade and resets', () {
      final tracker = SessionGradeTracker();
      for (var i = 0; i < 12; i++) {
        tracker.record(
          statusWith(connectedAtMs: 1000, paths: [path(rtt: 40)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final prev = tracker.beginSession(2000);
      expect(prev, isNotNull);
      expect(prev!.total, 100);
      expect(tracker.grade, isNull);
      expect(tracker.hasData, isFalse);
    });

    test('beginSession with no previous session returns null', () {
      expect(SessionGradeTracker().beginSession(1000), isNull);
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
