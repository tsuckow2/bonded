import 'dart:io';

import 'package:bonded_app/models/session_status.dart';
import 'package:bonded_app/models/transport_overhead.dart';
import 'package:bonded_app/screens/network_tests_screen.dart';
import 'package:bonded_app/services/tcp_echo_client.dart';
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

    // The fixed-payload run is enabled now (tunnel echo endpoint);
    // its own widget tests below cover the run and the error state.
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

  testWidgets('fixed-payload run measures each transport and renders cards', (
    WidgetTester tester,
  ) async {
    TestWidgetsFlutterBinding.ensureInitialized();
    const channel = MethodChannel('bonded/native');
    // The echo server must live in the real async zone: a server
    // created in the test's fake zone only accepts/echoes when the
    // fake zone runs, so the widget's echo run stalls between pumps.
    // Created here (inside runAsync), its accept/echo callbacks run
    // in real time; the widget's own socket data is still delivered
    // on pumps, so the run completes after a few pumps below.
    late final ServerSocket echoServer;
    await tester.runAsync(() async {
      echoServer = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      echoServer.listen((socket) {
        socket.listen(socket.add, onError: (_) {}, onDone: () {});
      });
    });
    addTearDown(echoServer.close);

    // Counters per path. While a run is in progress (another path is
    // paused), the unpaused target's counters advance by a full
    // payload-plus-headers on each snapshot; paused paths stay still,
    // so the flow-pinned-elsewhere check sees only the target move.
    final paused = <int>{};
    final counters = <int, Map<String, int>>{
      0: {'out': 1000, 'in': 2000, 'wireOut': 1100, 'wireIn': 2200},
      1: {'out': 5000, 'in': 6000, 'wireOut': 5500, 'wireIn': 6600},
    };
    final pauseCalls = <Map<String, dynamic>>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          switch (call.method) {
            case 'getPairedServers':
              return <Map<String, dynamic>>[];
            case 'getNetworkTestLogs':
              return <String>[];
            case 'pausePath':
              final args = call.arguments as Map;
              final index = args['pathIndex'] as int;
              final isPaused = args['paused'] as bool;
              if (isPaused) {
                paused.add(index);
              } else {
                paused.remove(index);
              }
              pauseCalls.add({'pathIndex': index, 'paused': isPaused});
              return true;
            case 'getVpnSessionStatus':
              if (paused.isNotEmpty) {
                for (final entry in counters.entries) {
                  if (!paused.contains(entry.key)) {
                    entry.value['out'] = entry.value['out']! + 1100000;
                    entry.value['in'] = entry.value['in']! + 1200000;
                    entry.value['wireOut'] =
                        entry.value['wireOut']! + 1210000;
                    entry.value['wireIn'] = entry.value['wireIn']! + 1320000;
                  }
                }
              }
              return <String, dynamic>{
                'state': 'connected',
                'serverAddress': 'example.com:443',
                'activeTransport': 'NaiveTCP',
                'transportCount': 2,
                'peerRelayCount': 0,
                'outboundBytes':
                    counters[0]!['out']! + counters[1]!['out']!,
                'inboundBytes': counters[0]!['in']! + counters[1]!['in']!,
                'connectedAtMs': 0,
                'paths': <Map<String, dynamic>>[
                  for (final entry in counters.entries)
                    <String, dynamic>{
                      'pathIndex': entry.key,
                      'kind': entry.key == 0 ? 'NaiveTCP' : 'QUIC',
                      'active': true,
                      'paused': paused.contains(entry.key),
                      'outboundBytes': entry.value['out'],
                      'inboundBytes': entry.value['in'],
                      'wireTxBytes': entry.value['wireOut'],
                      'wireRxBytes': entry.value['wireIn'],
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

    await tester.pumpWidget(
      MaterialApp(
        home: NetworkTestsScreen(
          echoClient: TcpEchoClient(
            host: InternetAddress.loopbackIPv4,
            port: echoServer.port,
          ),
        ),
      ),
    );
    await tester.pump();

    await tester.ensureVisible(find.text('Run fixed-payload TCP test'));
    await tester.pump();
    await tester.tap(find.text('Run fixed-payload TCP test'));
    // The server echoes in real time, but the widget's socket data
    // callbacks live in the fake zone: real I/O events only fire
    // while the real event loop runs (runAsync), and the handler's
    // continuations only drain on pumps. Interleave both until the
    // first result card appears (bounded: the run is local loopback).
    for (var i = 0; i < 8; i++) {
      await tester.runAsync(
        () => Future<void>.delayed(const Duration(seconds: 1)),
      );
      await tester.pump();
      if (find.text('NaiveTCP').evaluate().isNotEmpty) break;
    }
    await tester.pump();

    expect(find.text('NaiveTCP'), findsOneWidget);
    expect(find.text('QUIC'), findsOneWidget);
    // Default payload is 1 MiB, shown once per transport card.
    expect(find.text('1.00 MB'), findsNWidgets(2));
    // Each run paused the other path and resumed it afterwards.
    expect(pauseCalls.where((c) => c['paused'] == true).length, 2);
    expect(pauseCalls.where((c) => c['paused'] == false).length, 2);
  });

  testWidgets('unreachable echo reports the endpoint as unavailable', (
    WidgetTester tester,
  ) async {
    TestWidgetsFlutterBinding.ensureInitialized();
    const channel = MethodChannel('bonded/native');
    // No real socket here: the refused connect is already proven by
    // the TcpEchoClient unit test. Inject a connect that fails at
    // once so this test proves only the UI error path (note shown,
    // no cards, paths resumed) without depending on socket delivery
    // in the widget test's fake async zone.
    final unreachableClient = TcpEchoClient(
      connect: (_, _, {Duration? timeout}) async {
        throw const SocketException('Connection refused');
      },
    );

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          switch (call.method) {
            case 'getPairedServers':
              return <Map<String, dynamic>>[];
            case 'getNetworkTestLogs':
              return <String>[];
            case 'pausePath':
              return true;
            case 'getVpnSessionStatus':
              return <String, dynamic>{
                'state': 'connected',
                'serverAddress': 'example.com:443',
                'activeTransport': 'NaiveTCP',
                'transportCount': 1,
                'peerRelayCount': 0,
                'outboundBytes': 1000,
                'inboundBytes': 2000,
                'connectedAtMs': 0,
                'paths': <Map<String, dynamic>>[
                  <String, dynamic>{
                    'pathIndex': 0,
                    'kind': 'NaiveTCP',
                    'active': true,
                    'paused': false,
                    'outboundBytes': 1000,
                    'inboundBytes': 2000,
                    'wireTxBytes': 1100,
                    'wireRxBytes': 2200,
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

    await tester.pumpWidget(
      MaterialApp(
        home: NetworkTestsScreen(echoClient: unreachableClient),
      ),
    );
    await tester.pump();

    await tester.ensureVisible(find.text('Run fixed-payload TCP test'));
    await tester.pump();
    await tester.tap(find.text('Run fixed-payload TCP test'));
    await tester.pump();
    await tester.pump();
    await tester.pump();

    expect(find.textContaining('not available on this server'), findsOneWidget);
    // No result cards rendered.
    expect(find.byType(TransportOverheadCard), findsNothing);
  });
}
