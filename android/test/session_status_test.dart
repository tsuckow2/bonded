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
          'quicLostPackets': 3,
          'quicLostBytes': 3600,
          'quicSentPackets': 100,
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
    expect(status.paths[0].quicLostPackets, 3);
    expect(status.paths[0].quicLostBytes, 3600);
    expect(status.paths[0].quicSentPackets, 100);
    expect(status.paths[1].quicLostPackets, isNull);
    expect(status.paths[1].quicLostBytes, isNull);
    expect(status.paths[1].quicSentPackets, isNull);
    expect(status.paths[0].lossRate, closeTo(0.03, 1e-9));
    expect(status.paths[0].lossDisplay, '3.0%');
    expect(status.paths[1].lossRate, isNull);
    expect(status.paths[1].lossDisplay, '—');
    expect(status.lossRate, closeTo(0.03, 1e-9));
    expect(status.lossDisplay, '3.0%');

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
    expect(legacy.paths[0].quicLostPackets, isNull);
    expect(legacy.paths[0].lossRate, isNull);
    expect(legacy.paths[0].lossDisplay, '—');
    expect(legacy.lossRate, isNull);
    expect(legacy.lossDisplay, '—');
  });

  test('loss rate is null while nothing has been sent', () {
    final status = SessionStatus.fromMap(<String, dynamic>{
      'state': 'connected',
      'paths': <Map<String, dynamic>>[
        <String, dynamic>{
          'pathIndex': 0,
          'kind': 'QUIC',
          'active': true,
          'quicLostPackets': 0,
          'quicLostBytes': 0,
          'quicSentPackets': 0,
        },
      ],
    });
    expect(status.paths[0].lossRate, isNull);
    expect(status.paths[0].lossDisplay, '—');
    expect(status.lossRate, isNull);
  });

  test('SessionStatus reads relayed peers, defaulting to empty', () {
    final status = SessionStatus.fromMap(<String, dynamic>{
      'state': 'connected',
      'relayedUpBytes': 1900,
      'relayedDownBytes': 1800,
      'relayedPeers': <Map<String, dynamic>>[
        <String, dynamic>{
          'peerId': 'eNaeK60nAAA',
          'upBytes': 1900,
          'downBytes': 1800,
        },
        <String, dynamic>{
          'peerId': 'YeZMPfbcBBB',
          'upBytes': 0,
          'downBytes': 0,
        },
        // An entry without an id is not a peer.
        <String, dynamic>{'upBytes': 5, 'downBytes': 5},
      ],
      'paths': <Map<String, dynamic>>[],
    });
    expect(status.relayedPeers.length, 2);
    expect(status.relayedPeers[0].peerId, 'eNaeK60nAAA');
    expect(status.relayedPeers[0].upBytes, 1900);
    expect(status.relayedPeers[0].downBytes, 1800);
    expect(status.relayedPeers[1].peerId, 'YeZMPfbcBBB');
    expect(status.relayedPeers[1].upBytes, 0);

    // An older snapshot without the key still parses, with none.
    final legacy = SessionStatus.fromMap(<String, dynamic>{
      'state': 'connected',
      'paths': <Map<String, dynamic>>[],
    });
    expect(legacy.relayedPeers, isEmpty);
  });

  test('PathStat reads network names and orders the display lines', () {
    PathStat pathWith(Map<String, dynamic> pathMap) {
      return SessionStatus.fromMap(<String, dynamic>{
        'state': 'connected',
        'paths': <Map<String, dynamic>>[pathMap],
      }).paths[0];
    }

    // ASN org first, PTR second when it differs.
    final named = pathWith(<String, dynamic>{
      'pathIndex': 0,
      'kind': 'QUIC',
      'active': true,
      'serverSeenAddress': '75.164.76.151:54321',
      'networkAsnOrg': 'GOOGLE - Google LLC',
      'networkPtr': 'c-75-164-76-151.hsd1.example.net',
    });
    expect(named.networkAsnOrg, 'GOOGLE - Google LLC');
    expect(named.networkPtr, 'c-75-164-76-151.hsd1.example.net');
    expect(named.networkNameLines, [
      'GOOGLE - Google LLC',
      'c-75-164-76-151.hsd1.example.net',
    ]);

    // A PTR identical to the ASN org shows once, not twice.
    final sameName = pathWith(<String, dynamic>{
      'pathIndex': 0,
      'kind': 'QUIC',
      'active': true,
      'networkAsnOrg': 'EXAMPLE',
      'networkPtr': 'EXAMPLE',
    });
    expect(sameName.networkNameLines, ['EXAMPLE']);

    // A PTR with no ASN org still shows as the network name.
    final ptrOnly = pathWith(<String, dynamic>{
      'pathIndex': 0,
      'kind': 'QUIC',
      'active': true,
      'serverSeenAddress': '75.164.76.151:54321',
      'networkPtr': 'c-75-164-76-151.hsd1.example.net',
    });
    expect(ptrOnly.networkNameLines, ['c-75-164-76-151.hsd1.example.net']);

    // Neither name: fall back to the public IP, as before.
    final unnamed = pathWith(<String, dynamic>{
      'pathIndex': 0,
      'kind': 'QUIC',
      'active': true,
      'serverSeenAddress': '75.164.76.151:54321',
    });
    expect(unnamed.networkAsnOrg, isNull);
    expect(unnamed.networkPtr, isNull);
    expect(unnamed.networkNameLines, ['Public IP 75.164.76.151']);

    // Nothing known at all: no lines, and blank strings parse as null.
    final blank = pathWith(<String, dynamic>{
      'pathIndex': 0,
      'kind': 'QUIC',
      'active': true,
      'networkAsnOrg': '  ',
      'networkPtr': '',
    });
    expect(blank.networkAsnOrg, isNull);
    expect(blank.networkPtr, isNull);
    expect(blank.networkNameLines, isEmpty);
  });
}
