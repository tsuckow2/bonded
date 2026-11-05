import 'dart:ui';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:bonded_app/main.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('bonded/native');

  var sessionStatusCalls = 0;

  setUp(() {
    sessionStatusCalls = 0;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          switch (call.method) {
            case 'getPairedServers':
              return <Map<String, dynamic>>[];
            case 'getVpnStatus':
              return false;
            case 'getVpnSessionStatus':
              sessionStatusCalls++;
              return <String, dynamic>{};
            default:
              return null;
          }
        });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  testWidgets('Home screen renders', (WidgetTester tester) async {
    await tester.pumpWidget(const BondedApp());
    await tester.pumpAndSettle();

    expect(find.text('Bonded VPN'), findsOneWidget);
    expect(find.text('No paired servers'), findsOneWidget);
    expect(
      find.text('Scan a server QR code, or pair this device with your phone'),
      findsOneWidget,
    );
    expect(find.text('Scan QR Code'), findsOneWidget);
    expect(find.text('Show pairing code for a phone'), findsOneWidget);
  });

  testWidgets('Home screen stops polling session status when backgrounded',
      (WidgetTester tester) async {
    await tester.pumpWidget(const BondedApp());
    await tester.pumpAndSettle();
    // The test binding starts with a null lifecycle state; in a real
    // app the engine reports resumed while foregrounded.
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    final baseline = sessionStatusCalls;

    // Foreground: the 1s poll keeps asking for the session snapshot.
    await tester.pump(const Duration(seconds: 3));
    expect(sessionStatusCalls, greaterThan(baseline));

    // Background the app: the poll timer must stop asking, which is
    // also the native monitor's signal to back off to 30s.
    final afterForeground = sessionStatusCalls;
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pump(const Duration(seconds: 3));
    expect(sessionStatusCalls, afterForeground);

    // Foreground again: polling resumes.
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump(const Duration(seconds: 3));
    expect(sessionStatusCalls, greaterThan(afterForeground));
  });
}
