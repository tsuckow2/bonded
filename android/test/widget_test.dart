import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:bonded_app/main.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('bonded/native');

  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          switch (call.method) {
            case 'getPairedServers':
              return <Map<String, dynamic>>[];
            case 'getVpnStatus':
              return false;
            case 'getVpnSessionStatus':
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
}
