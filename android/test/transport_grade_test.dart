import 'package:bonded_app/models/session_status.dart';
import 'package:bonded_app/models/transport_grade.dart';
import 'package:flutter_test/flutter_test.dart';

PathStat tpath({
  int? index = 0,
  String kind = 'h3',
  bool active = true,
  int rtt = 40,
  int? ping,
  int? lost,
  int? sent,
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
  quicLostPackets: lost,
  quicSentPackets: sent,
);

SessionStatus tstatusWith({
  int connectedAtMs = 1000,
  List<PathStat> paths = const [],
  String state = 'connected',
}) => SessionStatus(
  state: state,
  serverAddress: 'example.invalid:443',
  activeTransport: 'h3',
  transportCount: paths.length,
  peerRelayCount: 0,
  outboundBytes: 0,
  inboundBytes: 0,
  relayedUpBytes: 0,
  relayedDownBytes: 0,
  relayedPeers: const [],
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
  group('gradeKey', () {
    test('direct paths key by supervisor index', () {
      expect(tpath(index: 0).gradeKey(), 'd0');
      expect(tpath(index: 3).gradeKey(), 'd3');
    });

    test('peer-relay legs key by peer id + kind + leg number', () {
      expect(
        tpath(index: null, peerId: 'abcdef12', kind: 'h3').gradeKey(),
        'rabcdef12:h3:1',
      );
      expect(
        tpath(index: null, peerId: 'abcdef12', kind: 'h3')
            .gradeKey(peerLeg: 2),
        'rabcdef12:h3:2',
      );
    });

    test('two legs to one peer get different keys (4.108)', () {
      // The bug: both legs keyed r<peer>:<kind>, so they shared one
      // grade state and showed identical scores despite different
      // latencies. The leg ordinal is part of the key now.
      final leg1 = tpath(index: null, peerId: 'abcdef12', kind: 'PeerRelay');
      final leg2 = tpath(index: null, peerId: 'abcdef12', kind: 'PeerRelay');
      final keys = gradeKeysForPaths([leg1, leg2]);
      expect(keys, ['rabcdef12:PeerRelay:1', 'rabcdef12:PeerRelay:2']);
    });
  });

  group('scoring functions', () {
    test('loss: full marks at 0.1%, zero at 10%, linear between', () {
      expect(lossScoreFromRate(0), 100);
      expect(lossScoreFromRate(0.001), 100);
      expect(lossScoreFromRate(0.10), 0);
      expect(lossScoreFromRate(0.5), 0);
      expect(lossScoreFromRate(0.0505), closeTo(50, 0.01));
    });

    test('bandwidth: 100 when nothing saturated, 0 when all saturated', () {
      expect(bandwidthScoreFromSaturatedShare(0), 100);
      expect(bandwidthScoreFromSaturatedShare(0.5), 50);
      expect(bandwidthScoreFromSaturatedShare(1), 0);
    });
  });

  group('TransportGradeTracker', () {
    final t0 = DateTime(2026, 1, 1, 12, 0, 0);

    test('no samples: no grade', () {
      final tracker = TransportGradeTracker();
      expect(tracker.gradeFor('d0'), isNull);
      expect(tracker.grades, isEmpty);
    });

    test('non-connected snapshots are ignored', () {
      final tracker = TransportGradeTracker();
      tracker.record(
        tstatusWith(state: 'connecting', paths: [tpath()]),
        t0,
      );
      expect(tracker.gradeFor('d0'), isNull);
    });

    test('latency grades this path median RTT; non-QUIC has no loss', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 12; i++) {
        tracker.record(
          tstatusWith(paths: [tpath(rtt: 40)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.gradeFor('d0')!;
      // Median lands in the ≤50 ms bucket (midpoint 25 ms) → 100.
      expect(grade.latencyScore, 100);
      expect(grade.latencyDetail, contains('ms'));
      // No loss counters (non-QUIC): never a fabricated 0.
      expect(grade.lossScore, isNull);
      // Stability needs 60 s: not scored yet.
      expect(grade.stabilityScore, isNull);
      // No bytes moved: no active windows, bandwidth not scored.
      expect(grade.bandwidthScore, isNull);
      // Insufficient data (no loss, no bandwidth): the 4.86 prior,
      // 99, not the thin rebalanced total over latency alone.
      expect(grade.total, 99);
      expect(grade.letter, 'A');
      expect(grade.isPrior, isTrue);
      expect(grade.sampleCount, 11);
    });

    test('loss: 1% over enough packets scores ~91 and rebalances', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 12; i++) {
        // Cumulative counters grow 1000 sent / 10 lost per interval.
        tracker.record(
          tstatusWith(paths: [tpath(rtt: 40, lost: 10 * i, sent: 1000 * i)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.gradeFor('d0')!;
      // 11000 sent, 110 lost → 1.0% → (0.10-0.01)/0.099*100 ≈ 90.9.
      expect(grade.lossScore, closeTo(90.9, 0.1));
      expect(grade.lossDetail, contains('1.0% lost'));
      expect(grade.lossDetail, contains('110/11000'));
      // Total over latency (30) + loss (20):
      // (30*100 + 20*90.9) / 50 ≈ 96 → A.
      expect(grade.total, 96);
      expect(grade.letter, 'A');
    });

    test('loss: fewer than 100 packets sent means no loss score', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 12; i++) {
        tracker.record(
          tstatusWith(paths: [tpath(rtt: 40, lost: i, sent: 5 * i)]),
          t0.add(Duration(seconds: i)),
        );
      }
      // 55 sent total < 100: not a measurement.
      expect(tracker.gradeFor('d0')!.lossScore, isNull);
    });

    test('loss: a counter reset (re-dial) is not negative loss', () {
      final tracker = TransportGradeTracker();
      final sent = [0, 1000, 2000, 100, 1100];
      final lost = [0, 10, 20, 0, 10];
      for (var i = 0; i < sent.length; i++) {
        tracker.record(
          tstatusWith(paths: [tpath(rtt: 40, lost: lost[i], sent: sent[i])]),
          t0.add(Duration(seconds: i)),
        );
      }
      // Deltas: sent 1000 + 1000 + 0 (reset) + 1000 = 3000;
      // lost 10 + 10 + 0 + 10 = 30 → 1.0% → ~90.9.
      final grade = tracker.gradeFor('d0')!;
      expect(grade.lossScore, closeTo(90.9, 0.1));
    });

    test('stability: a QUIC PING counter drop counts one flap', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 62; i++) {
        // Re-dial at sample 31: the PING counter restarts at 0.
        final ping = i < 31 ? 100 + i : i - 31;
        tracker.record(
          tstatusWith(paths: [tpath(rtt: 40, ping: ping)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.gradeFor('d0')!;
      expect(grade.stabilityScore, 0);
      expect(grade.stabilityDetail, contains('1 flap'));
    });

    test('stability: rejoining after being inactive counts one flap', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 62; i++) {
        // Path down for samples 20–30, back at 31.
        final active = i < 20 || i >= 31;
        tracker.record(
          tstatusWith(paths: [tpath(rtt: 40, active: active)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.gradeFor('d0')!;
      expect(grade.stabilityScore, 0);
      expect(grade.stabilityDetail, contains('1 flap'));
    });

    test('bandwidth: active windows with no saturation score 100', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 12; i++) {
        // 10 Mbps of traffic every interval, RTT steady at 40 ms.
        tracker.record(
          tstatusWith(paths: [tpath(rtt: 40, inb: 1250000 * i)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.gradeFor('d0')!;
      expect(grade.bandwidthScore, 100);
      expect(
        grade.bandwidthDetail,
        'no saturation in 11 active windows',
      );
      expect(grade.total, 100);
    });

    test('bandwidth: RTT inflation under load counts saturated windows', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 13; i++) {
        // Traffic every interval; RTT jumps 40 → 200 ms at sample 7.
        final rtt = i < 7 ? 40 : 200;
        tracker.record(
          tstatusWith(paths: [tpath(rtt: rtt, inb: 1250000 * i)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.gradeFor('d0')!;
      // 12 active windows, 6 saturated (intervals 7–12: 200 ms is
      // ≥ 1.5× the 40 ms low-water mark and +160 ms) → 100×(1−6/12).
      expect(grade.bandwidthScore, 50);
      expect(
        grade.bandwidthDetail,
        '6 of 12 active windows saturated',
      );
      // Latency median is still the ≤50 ms bucket (6 of 12 counted
      // samples at 40 ms) → 100; total (30*100 + 20*50)/50 = 80 → B.
      expect(grade.latencyScore, 100);
      expect(grade.total, 80);
      expect(grade.letter, 'B');
    });

    test('bandwidth: a loss spike under load counts saturated windows', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 12; i++) {
        // Traffic every interval; 10% interval loss throughout.
        tracker.record(
          tstatusWith(
            paths: [tpath(rtt: 40, inb: 1250000 * i, lost: 100 * i, sent: 1000 * i)],
          ),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.gradeFor('d0')!;
      // Every active window has a ≥5% loss spike over ≥20 packets.
      expect(grade.bandwidthScore, 0);
      expect(
        grade.bandwidthDetail,
        '11 of 11 active windows saturated',
      );
      // The loss component agrees: 10% overall → 0.
      expect(grade.lossScore, 0);
    });

    test('bandwidth: fewer than 10 active windows means no score', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 5; i++) {
        tracker.record(
          tstatusWith(paths: [tpath(rtt: 40, inb: 1250000 * i)]),
          t0.add(Duration(seconds: i)),
        );
      }
      expect(tracker.gradeFor('d0')!.bandwidthScore, isNull);
    });

    test('bandwidth: idle windows never count as saturated', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 12; i++) {
        // Traffic only on even intervals; RTT inflates the whole time.
        final inb = (i ~/ 2) * 1250000;
        tracker.record(
          tstatusWith(paths: [tpath(rtt: 200, inb: inb)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.gradeFor('d0')!;
      // Active windows are intervals 2, 4, 6, 8, 10 — 5 of them,
      // below the 10-window minimum, so bandwidth is unscored
      // rather than dragged down by an idle stretch.
      expect(grade.bandwidthScore, isNull);
    });

    test('two paths are graded independently', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 12; i++) {
        tracker.record(
          tstatusWith(
            paths: [tpath(index: 0, rtt: 40), tpath(index: 1, rtt: 400)],
          ),
          t0.add(Duration(seconds: i)),
        );
      }
      expect(tracker.gradeFor('d0')!.latencyScore, 100);
      // Median in the ≤500 bucket (midpoint 425 ms) → ≈ 16.7.
      expect(tracker.gradeFor('d1')!.latencyScore, closeTo(16.7, 0.1));
      expect(tracker.grades.length, 2);
    });

    test('two peer legs to one peer are graded independently (4.108)', () {
      // Regression: both legs keyed r<peer>:<kind>, so they shared
      // one grade state and showed identical scores despite
      // different latencies (the 6a's two YeZMPfbc legs, 310 ms vs
      // 458 ms, both A·99 in the v360 bench). The leg ordinal is
      // part of the key now, so each leg accumulates its own RTTs.
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 12; i++) {
        tracker.record(
          tstatusWith(
            paths: [
              tpath(index: null, peerId: 'abcdef12', kind: 'PeerRelay', rtt: 40),
              tpath(index: null, peerId: 'abcdef12', kind: 'PeerRelay', rtt: 400),
            ],
          ),
          t0.add(Duration(seconds: i)),
        );
      }
      expect(tracker.gradeFor('rabcdef12:PeerRelay:1')!.latencyScore, 100);
      // Median in the ≤500 bucket (midpoint 425 ms) → ≈ 16.7.
      expect(
        tracker.gradeFor('rabcdef12:PeerRelay:2')!.latencyScore,
        closeTo(16.7, 0.1),
      );
      expect(tracker.grades.length, 2);
    });

    test('gaps over 35 s are skipped as unknown time', () {
      final tracker = TransportGradeTracker();
      tracker.record(
        tstatusWith(paths: [tpath(rtt: 40, lost: 0, sent: 5000)]),
        t0,
      );
      // 10-minute gap (app backgrounded): re-baselines, counts nothing.
      tracker.record(
        tstatusWith(paths: [tpath(rtt: 40, lost: 0, sent: 6000)]),
        t0.add(const Duration(minutes: 10)),
      );
      tracker.record(
        tstatusWith(paths: [tpath(rtt: 40, lost: 0, sent: 7000)]),
        t0.add(const Duration(minutes: 10, seconds: 1)),
      );
      final grade = tracker.gradeFor('d0')!;
      // Only the last 1 s interval counted: stability needs 60 s.
      expect(grade.stabilityScore, isNull);
      expect(grade.sampledFor, const Duration(seconds: 1));
      // The 5000→6000 jump across the gap never counted as loss
      // denominator: sent total is just the last interval's 1000.
      expect(grade.lossScore, 100);
    });

    test('beginSession resets all per-path state', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 12; i++) {
        tracker.record(
          tstatusWith(connectedAtMs: 1000, paths: [tpath(rtt: 40)]),
          t0.add(Duration(seconds: i)),
        );
      }
      expect(tracker.gradeFor('d0'), isNotNull);
      tracker.beginSession(2000);
      expect(tracker.gradeFor('d0'), isNull);
      expect(tracker.grades, isEmpty);
      // New session grades from its own samples.
      for (var i = 0; i < 12; i++) {
        tracker.record(
          tstatusWith(connectedAtMs: 2000, paths: [tpath(rtt: 400)]),
          t0.add(Duration(seconds: 100 + i)),
        );
      }
      expect(
        tracker.gradeFor('d0')!.latencyScore,
        closeTo(16.7, 0.1),
      );
    });
  });

  group('exploration prior (4.86)', () {
    final t0 = DateTime(2026, 1, 1, 12, 0, 0);

    test('idle peer leg with high RTT grades 99, not its thin total', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 12; i++) {
        // A peer-relay leg (OnePlus) that reports RTT but carries
        // no traffic: the idle-leg case from the v304 bench check.
        tracker.record(
          tstatusWith(
            paths: [tpath(index: null, kind: 'h3', peerId: 'abcdef12', rtt: 300)],
          ),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.gradeFor('rabcdef12:h3:1')!;
      // RTT 300 ms alone would score ~50 (D) and the leg would
      // never win traffic — the feedback loop. The prior is 99.
      expect(grade.latencyScore, 50);
      expect(grade.total, 99);
      expect(grade.letter, 'A');
      expect(grade.isPrior, isTrue);
      expect(grade.lossScore, isNull);
      expect(grade.bandwidthScore, isNull);
    });

    test('a path that just appeared, with no samples, gets the prior', () {
      final tracker = TransportGradeTracker();
      // One sample only: the re-baseline, nothing accumulated.
      tracker.record(tstatusWith(paths: [tpath(rtt: 40)]), t0);
      final grade = tracker.gradeFor('d0')!;
      expect(grade.total, 99);
      expect(grade.isPrior, isTrue);
      expect(grade.latencyScore, isNull);
      expect(grade.sampleCount, 0);
    });

    test('prior ends once the transport carries enough traffic', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 12; i++) {
        tracker.record(
          tstatusWith(paths: [tpath(rtt: 300)]),
          t0.add(Duration(seconds: i)),
        );
      }
      var grade = tracker.gradeFor('d0')!;
      expect(grade.total, 99);
      expect(grade.isPrior, isTrue);
      // Now traffic: 1000 packets sent per interval, no loss,
      // bytes moving. The first traffic sample only re-baselines
      // the counters (previous sent was null); the next two add
      // 1000 sent each, so sentTotal reaches 2000.
      for (var i = 0; i < 3; i++) {
        final n = 12 + i;
        tracker.record(
          tstatusWith(
            paths: [
              tpath(
                rtt: 300,
                sent: 1000 * (i + 1),
                lost: 0,
                inb: 1250000 * (i + 1),
              ),
            ],
          ),
          t0.add(Duration(seconds: n)),
        );
      }
      grade = tracker.gradeFor('d0')!;
      // sentTotal >= 100: the prior ends, the grade is measured.
      expect(grade.isPrior, isFalse);
      expect(grade.lossScore, 100);
      // Latency 50 (300 ms), loss 100 (0%): (30*50 + 20*100)/50.
      expect(grade.total, 70);
      expect(grade.letter, 'C');
    });

    test('bandwidth data alone ends the prior', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 12; i++) {
        // Bytes moving every interval, but no loss counters at all
        // (non-QUIC): 11 active windows, bandwidth scores 100.
        tracker.record(
          tstatusWith(paths: [tpath(rtt: 40, inb: 1250000 * i)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.gradeFor('d0')!;
      // activeIntervals >= 10, so the grade is measured even
      // though loss was never observed.
      expect(grade.isPrior, isFalse);
      expect(grade.bandwidthScore, 100);
      expect(grade.lossScore, isNull);
      // Latency 100 + bandwidth 100 → 100.
      expect(grade.total, 100);
    });

    test('a measured grade is never a prior', () {
      final tracker = TransportGradeTracker();
      for (var i = 0; i < 12; i++) {
        tracker.record(
          tstatusWith(paths: [tpath(rtt: 40, lost: 10 * i, sent: 1000 * i)]),
          t0.add(Duration(seconds: i)),
        );
      }
      final grade = tracker.gradeFor('d0')!;
      expect(grade.isPrior, isFalse);
      expect(grade.total, 96);
    });
  });
}
