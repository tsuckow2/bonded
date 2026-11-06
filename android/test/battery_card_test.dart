import 'package:bonded_app/widgets/battery_card.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('bonded/native');

  late Map<String, dynamic>? profile;

  Map<String, dynamic> liveProfile() => <String, dynamic>{
        'live': true,
        'chargeCounterAvailable': true,
        'windowMs': 3600000,
        'windowSamples': 120,
        'windowStartMs': 1762387200000,
        'mahPerHour': 12.5,
        'cpuMsPerHour': 4500.0,
        'wakeupsPerHour': 88.0,
        'currentUa': 150000,
        'capacityPct': 80,
        'segments': <String, dynamic>{'idle': 9.0, 'wifi': 11.0},
        'segmentSamples': <String, dynamic>{'idle': 80, 'wifi': 100},
        'totalSamples': 120,
        'aggregates': <Map<String, dynamic>>[],
      };

  Future<void> pumpCard(WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(home: Scaffold(body: BatteryCard())),
    );
    await tester.pump();
    await tester.pump();
  }

  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  setUp(() {
    profile = liveProfile();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          if (call.method == 'getBatteryProfile') return profile;
          return null;
        });
  });

  testWidgets('shows last-hour rates and segments with the honesty note', (
    WidgetTester tester,
  ) async {
    await pumpCard(tester);

    expect(find.text('Battery'), findsOneWidget);
    expect(find.textContaining('12.5 mAh/h'), findsWidgets);
    expect(find.textContaining('4500 ms/h'), findsOneWidget);
    expect(find.textContaining('88 /h'), findsOneWidget);
    expect(find.text('Idle'), findsOneWidget);
    expect(find.textContaining('9.0 mAh/h'), findsOneWidget);
    expect(find.text('Wi-Fi'), findsOneWidget);
    // The honesty note: whole-device drain, not the app's share alone.
    expect(find.textContaining('whole-device drain'), findsOneWidget);
    expect(find.textContaining('never wakes the device'), findsOneWidget);
  });

  testWidgets('empty profile explains sampling has not started', (
    WidgetTester tester,
  ) async {
    profile = null;
    await pumpCard(tester);

    expect(find.text('Battery'), findsOneWidget);
    expect(find.textContaining('No battery samples yet'), findsOneWidget);
    expect(find.text('Copy CSV'), findsOneWidget);
    // Nothing to export yet.
    final button = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Copy CSV'),
    );
    expect(button.onPressed, isNull);
  });

  testWidgets('copy CSV copies the profile and confirms', (
    WidgetTester tester,
  ) async {
    await pumpCard(tester);

    final button = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Copy CSV'),
    );
    expect(button.onPressed, isNotNull);

    // Clipboard.setData awaits a platform reply; with no handler the
    // test messenger delegates to the (absent) engine and the future
    // never completes, so the SnackBar never shows. Answer only the
    // clipboard call; other framework calls on this channel are
    // fire-and-forget and get no reply, as usual in tests. Note the
    // platform channel uses JSONMethodCodec, not the standard one.
    const platform = MethodChannel('flutter/platform');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMessageHandler(platform.name, (message) async {
          final call = const JSONMethodCodec().decodeMethodCall(message);
          if (call.method == 'Clipboard.setData') {
            return const JSONMethodCodec().encodeSuccessEnvelope(null);
          }
          return null;
        });

    await tester.tap(find.text('Copy CSV'));
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pump(const Duration(milliseconds: 500));
    expect(find.text('Battery profile copied as CSV'), findsOneWidget);
  });

  testWidgets('charge counter unavailable says so instead of a number', (
    WidgetTester tester,
  ) async {
    profile = liveProfile()
      ..['chargeCounterAvailable'] = false
      ..['mahPerHour'] = null;
    await pumpCard(tester);

    expect(find.textContaining('charge counter unavailable'), findsOneWidget);
  });
}
