import 'package:bonded_app/models/session_status.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('SessionStatus reads the wakeup counters, defaulting to zero', () {
    final status = SessionStatus.fromMap(<String, dynamic>{
      'state': 'connected',
      'serverAddress': 'example.test:443',
      'activeTransport': 'QUIC',
      'transportCount': 2,
      'peerRelayCount': 0,
      'outboundBytes': 100,
      'inboundBytes': 90,
      'relayedUpBytes': 19,
      'relayedDownBytes': 18,
      'heartbeatPingsSent': 42,
      'relayTasksStarted': 2,
      'relayTasksEnded': 1,
      'connectedAtMs': 1700000000000,
      'paths': <Map<String, dynamic>>[
        <String, dynamic>{
          'pathIndex': 0,
          'kind': 'QUIC',
          'active': true,
          'outboundBytes': 100,
          'inboundBytes': 90,
          'wireTxBytes': 120,
          'wireRxBytes': 110,
          'quicPingFrames': 7,
          'lastRttMs': 12,
        },
        <String, dynamic>{
          'pathIndex': 1,
          'kind': 'WebSocketTls',
          'active': false,
          'outboundBytes': 0,
          'inboundBytes': 0,
          'lastRttMs': 0,
        },
      ],
    });
    expect(status.heartbeatPingsSent, 42);
    expect(status.relayTasksStarted, 2);
    expect(status.relayTasksEnded, 1);
    expect(status.relayedUpBytes, 19);
    expect(status.paths[0].quicPingFrames, 7);
    expect(status.paths[1].quicPingFrames, isNull);
    expect(status.paths[0].wireTxBytes, 120);
    expect(status.paths[0].wireRxBytes, 110);
    expect(status.paths[1].wireTxBytes, isNull);
    expect(status.paths[1].wireRxBytes, isNull);

    // An older snapshot without the keys still parses, with zeros.
    final legacy = SessionStatus.fromMap(<String, dynamic>{
      'state': 'connected',
      'paths': <Map<String, dynamic>>[
        <String, dynamic>{'kind': 'QUIC'},
      ],
    });
    expect(legacy.heartbeatPingsSent, 0);
    expect(legacy.relayTasksStarted, 0);
    expect(legacy.relayTasksEnded, 0);
    expect(legacy.paths[0].quicPingFrames, isNull);
    expect(legacy.paths[0].wireTxBytes, isNull);
    expect(legacy.paths[0].wireRxBytes, isNull);
  });
}
