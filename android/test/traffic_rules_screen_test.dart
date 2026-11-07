import 'dart:convert';

import 'package:bonded_app/screens/traffic_rules_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('bonded/native');

  late Map<String, dynamic> storedSettings;
  late List<MethodCall> calls;

  Map<String, dynamic> settingsMap({String trafficRulesJson = '{}'}) {
    return {
      'autoConnectOnOpen': false,
      'autoConnectOnBoot': false,
      'selectedServerId': null,
      'allowLocalTraffic': false,
      'excludedAppPackages': <String>[],
      'batterySaver': false,
      'trafficRulesJson': trafficRulesJson,
    };
  }

  setUp(() {
    calls = <MethodCall>[];
    storedSettings = settingsMap();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          calls.add(call);
          switch (call.method) {
            case 'getAppSettings':
              return storedSettings;
            case 'updateAppSettings':
              final args = call.arguments as Map;
              if (args['trafficRulesJson'] is String) {
                storedSettings = settingsMap(
                  trafficRulesJson: args['trafficRulesJson'] as String,
                );
              }
              return true;
            case 'updateTrafficRules':
              return true;
            default:
              return null;
          }
        });
  });

  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  Future<void> pumpScreen(WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(home: TrafficRulesScreen()),
    );
    await tester.pump();
    await tester.pump();
  }

  testWidgets('shows the default mode picker and the empty-rules state', (
    WidgetTester tester,
  ) async {
    await pumpScreen(tester);

    expect(find.text('Traffic modes & rules'), findsOneWidget);
    expect(find.text('Default (flow spreading)'), findsOneWidget);
    expect(find.text('No rules yet'), findsOneWidget);
    expect(find.text('Add rule'), findsOneWidget);
  });

  testWidgets('lists a rule with its mode and resolved IPs', (
    WidgetTester tester,
  ) async {
    storedSettings = settingsMap(
      trafficRulesJson: jsonEncode({
        'defaultMode': 'default',
        'rules': [
          {
            'id': 'mixlr',
            'kind': 'domain',
            // Fixture IPs (TEST-NET documentation range): the screen
            // only renders the stored strings, it never resolves.
            'target': 'listen.mixlr.com',
            'resolvedIps': ['203.0.113.5', '203.0.113.6'],
            'mode': 'redundant',
          },
        ],
      }),
    );
    await pumpScreen(tester);

    expect(find.text('listen.mixlr.com'), findsOneWidget);
    expect(
      find.textContaining('Redundant (all transports)'),
      findsOneWidget,
    );
    expect(find.textContaining('203.0.113.5, 203.0.113.6'), findsOneWidget);
  });

  testWidgets('flags an unresolved domain rule', (
    WidgetTester tester,
  ) async {
    storedSettings = settingsMap(
      trafficRulesJson: jsonEncode({
        'defaultMode': 'default',
        'rules': [
          {
            'id': 'bad',
            'kind': 'domain',
            'target': 'unresolved.example',
            'resolvedIps': <String>[],
            'mode': 'redundant',
          },
        ],
      }),
    );
    await pumpScreen(tester);

    expect(find.text('unresolved.example'), findsOneWidget);
    expect(find.textContaining('could not resolve'), findsOneWidget);
  });

  testWidgets('no mode shows the fallback note any more (all five implemented)', (
    WidgetTester tester,
  ) async {
    // 4.54 implemented the last mode, so the fallback note — which
    // used to appear for `redundant` — must show for no mode now.
    // `redundant` as the default mode is the sharpest case: it was
    // the last unimplemented one.
    storedSettings = settingsMap(
      trafficRulesJson: jsonEncode({
        'defaultMode': 'redundant',
        'rules': <Map<String, dynamic>>[],
      }),
    );
    await pumpScreen(tester);

    expect(find.textContaining('falls back to Default until'), findsNothing);
  });

  testWidgets('adding an IP rule saves it and pushes it live', (
    WidgetTester tester,
  ) async {
    await pumpScreen(tester);

    await tester.tap(find.text('Add rule'));
    await tester.pumpAndSettle();

    await tester.enterText(
      find.byType(TextField).first,
      '192.0.2.1',
    );
    await tester.pump();
    expect(find.textContaining('Detected: IP address'), findsOneWidget);

    await tester.tap(find.text('Save'));
    await tester.pumpAndSettle();

    expect(find.text('192.0.2.1'), findsOneWidget);
    // Persisted via updateAppSettings and pushed live via
    // updateTrafficRules.
    expect(
      calls.any((c) => c.method == 'updateAppSettings'),
      isTrue,
    );
    expect(
      calls.any((c) => c.method == 'updateTrafficRules'),
      isTrue,
    );
    final saved = jsonDecode(
      storedSettings['trafficRulesJson'] as String,
    ) as Map<String, dynamic>;
    final rules = saved['rules'] as List;
    expect(rules.single['target'], '192.0.2.1');
    expect(rules.single['kind'], 'ip');
  });
}
