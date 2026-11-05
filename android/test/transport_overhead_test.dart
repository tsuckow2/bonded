import 'package:bonded_app/models/session_status.dart';
import 'package:bonded_app/models/transport_overhead.dart';
import 'package:bonded_app/screens/network_tests_screen.dart';
import 'package:bonded_app/widgets/transport_overhead_card.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

PathStat stat({
  required int outbound,
  required int inbound,
  int? wireTx,
  int? wireRx,
  String kind = 'NaiveTCP',
}) => PathStat(
  pathIndex: 0,
  kind: kind,
  active: true,
  outboundBytes: outbound,
  inboundBytes: inbound,
  wireTxBytes: wireTx,
  wireRxBytes: wireRx,
  lastRttMs: 12,
  serverSeenAddress: null,
);

void main() {
  test('fromSnapshots computes inside, wire, overhead and bandwidths', () {
    final result = TransportOverheadResult.fromSnapshots(
      transportLabel: 'NaiveTCP',
      before: stat(outbound: 1000, inbound: 2000, wireTx: 1100, wireRx: 2200),
      after: stat(
        outbound: 11000,
        inbound: 12000,
        wireTx: 12100,
        wireRx: 13200,
      ),
      elapsed: const Duration(seconds: 10),
      isLiveWindow: true,
    )!;
    expect(result.insideTxBytes, 10000);
    expect(result.insideRxBytes, 10000);
    expect(result.wireTxBytes, 11000);
    expect(result.wireRxBytes, 11000);
    expect(result.overheadTxBytes, 1000);
    expect(result.overheadRxBytes, 1000);
    expect(result.overheadTxRatio, closeTo(0.1, 1e-9));
    expect(result.overheadRxRatio, closeTo(0.1, 1e-9));
    // Payload stands in for inside bytes on the live window.
    expect(result.payloadBytes, 10000);
    expect(result.payloadBandwidthBps, 8000.0);
    expect(result.insideTxBandwidthBps, 8000.0);
    expect(result.wireTxBandwidthBps, 8800.0);
  });

  test('unmeasured wire bytes give null overhead but live bandwidths', () {
    final result = TransportOverheadResult.fromSnapshots(
      transportLabel: 'WebSocketTls',
      before: stat(outbound: 1000, inbound: 2000),
      after: stat(outbound: 11000, inbound: 12000),
      elapsed: const Duration(seconds: 10),
      isLiveWindow: true,
    )!;
    expect(result.wireTxBytes, null);
    expect(result.overheadTxBytes, null);
    expect(result.overheadTxRatio, null);
    expect(result.payloadBandwidthBps, 8000.0);
    expect(result.insideRxBandwidthBps, 8000.0);
    expect(result.wireTxBandwidthBps, null);
  });

  test('zero elapsed gives zero bandwidths, not infinity', () {
    const result = TransportOverheadResult(
      transportLabel: 'NaiveTCP',
      payloadBytes: 1024,
      insideTxBytes: 1024,
      insideRxBytes: 1024,
      wireTxBytes: 1100,
      wireRxBytes: 1100,
      elapsed: Duration.zero,
    );
    expect(result.payloadBandwidthBps, 0.0);
    expect(result.wireTxBandwidthBps, 0.0);
  });

  test('a backwards counter marks the result reset, not negative', () {
    final result = TransportOverheadResult.fromSnapshots(
      transportLabel: 'NaiveTCP',
      before: stat(outbound: 5000, inbound: 5000, wireTx: 6000, wireRx: 6000),
      after: stat(outbound: 100, inbound: 100, wireTx: 200, wireRx: 200),
      elapsed: const Duration(seconds: 10),
      isLiveWindow: true,
    )!;
    expect(result.countersReset, true);
    expect(result.insideTxBytes, 0);
    expect(result.wireTxBytes, null);
  });

  test('wire status table documents the WSS limitation', () {
    expect(wireMeasurementStatus('WebSocketTls'), contains('Not measured'));
    expect(wireMeasurementStatus('QUIC'), contains('Measured'));
    expect(wireMeasurementStatus('WireGuard'), contains('Measured'));
    expect(wireMeasurementStatus('NaiveTCP'), contains('Measured'));
  });

  testWidgets('result card shows payload, inside, wire and overhead', (
    WidgetTester tester,
  ) async {
    const result = TransportOverheadResult(
      transportLabel: 'NaiveTCP',
      payloadBytes: 1024 * 1024,
      insideTxBytes: 10000,
      insideRxBytes: 10000,
      wireTxBytes: 11000,
      wireRxBytes: 11000,
      elapsed: Duration(seconds: 10),
    );
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(body: TransportOverheadCard(result: result)),
      ),
    );
    expect(find.text('NaiveTCP'), findsOneWidget);
    expect(find.text('1.00 MB'), findsOneWidget);
    expect(find.text('9.8 KB'), findsNWidgets(2)); // inside sent + received
    expect(find.text('10.7 KB'), findsNWidgets(2)); // wire sent + received
    expect(find.text('1000 B (10.0%)'), findsNWidgets(2));
    expect(find.text('10000 ms'), findsOneWidget);
  });

  testWidgets('result card says not measured when wire bytes are null', (
    WidgetTester tester,
  ) async {
    const result = TransportOverheadResult(
      transportLabel: 'WebSocketTls',
      payloadBytes: 1024,
      insideTxBytes: 1024,
      insideRxBytes: 1024,
      wireTxBytes: null,
      wireRxBytes: null,
      elapsed: Duration(seconds: 10),
    );
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(body: TransportOverheadCard(result: result)),
      ),
    );
    expect(find.text('WebSocketTls'), findsOneWidget);
    expect(find.text('not measured'), findsNWidgets(6));
  });

  testWidgets('live 10 s measurement renders a result card', (
    WidgetTester tester,
  ) async {
    TestWidgetsFlutterBinding.ensureInitialized();
    const channel = MethodChannel('bonded/native');
    var snapshotCalls = 0;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          switch (call.method) {
            case 'getPairedServers':
              return <Map<String, dynamic>>[];
            case 'getNetworkTestLogs':
              return <String>[];
            case 'getVpnSessionStatus':
              snapshotCalls += 1;
              final first = snapshotCalls == 1;
              return <String, dynamic>{
                'state': 'connected',
                'serverAddress': 'example.com:443',
                'activeTransport': 'NaiveTCP',
                'transportCount': 1,
                'peerRelayCount': 0,
                'outboundBytes': first ? 1000 : 11000,
                'inboundBytes': first ? 2000 : 12000,
                'connectedAtMs': 0,
                'paths': <Map<String, dynamic>>[
                  <String, dynamic>{
                    'pathIndex': 0,
                    'kind': 'NaiveTCP',
                    'active': true,
                    'paused': false,
                    'outboundBytes': first ? 1000 : 11000,
                    'inboundBytes': first ? 2000 : 12000,
                    'wireTxBytes': first ? 1100 : 12100,
                    'wireRxBytes': first ? 2200 : 13200,
                    'lastRttMs': 12,
                  },
                ],
              };
            default:
              return null;
          }
        });
    addTearDown(() {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
    });

    await tester.pumpWidget(const MaterialApp(home: NetworkTestsScreen()));
    await tester.pump();

    // Fixed-payload run is disabled until the server echo exists.
    final fixedButton = find.text('Run fixed-payload TCP test');
    expect(fixedButton, findsOneWidget);
    expect(
      find.ancestor(of: fixedButton, matching: find.byType(ElevatedButton)),
      findsOneWidget,
    );

    await tester.ensureVisible(find.text('Measure live overhead (10 s)'));
    await tester.pump();
    await tester.tap(find.text('Measure live overhead (10 s)'));
    await tester.pump(const Duration(seconds: 10));
    await tester.pump();
    await tester.pump();
    expect(find.text('NaiveTCP — live 10 s window'), findsOneWidget);
    expect(find.text('9.8 KB'), findsNWidgets(2));
    expect(find.text('10.7 KB'), findsNWidgets(2));
    expect(find.text('1000 B (10.0%)'), findsNWidgets(2));
  });
}
