import 'package:bonded_app/models/pair_device_model.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('PairDevicePayload.parseQrData', () {
    test('parses a TV pairing code and round-trips through QR data', () {
      const qrData =
          '{"kind":"bonded-pair-device","version":1,"code":"AbCdEfGhIjKlMnOpQrStUv","hosts":["192.168.1.50"],"port":48117,"device_label":"TV","device_key":"dGVzdGtleWJhc2U2NA=="}';

      final payload = PairDevicePayload.parseQrData(qrData);

      expect(payload, isNotNull);
      expect(payload!.code, 'AbCdEfGhIjKlMnOpQrStUv');
      expect(payload.hosts, ['192.168.1.50']);
      expect(payload.port, 48117);
      expect(payload.deviceLabel, 'TV');
      expect(payload.deviceKey, 'dGVzdGtleWJhc2U2NA==');
      expect(payload.deviceKeyFingerprint, 'dGVzdGtl');

      final reparsed = PairDevicePayload.parseQrData(payload.toQrData());
      expect(reparsed, isNotNull);
      expect(reparsed!.code, payload.code);
      expect(reparsed.hosts, payload.hosts);
      expect(reparsed.deviceKey, payload.deviceKey);
    });

    test('rejects server QR payloads (no kind field)', () {
      const qrData =
          '{"server_public_address":"bonded.example.com:8080","invite_token":"token-123","server_public_key":"pub-key"}';
      expect(PairDevicePayload.parseQrData(qrData), isNull);
    });

    test('rejects payloads missing code, hosts, port, or device key', () {
      expect(
        PairDevicePayload.parseQrData(
          '{"kind":"bonded-pair-device","hosts":["192.168.1.50"],"port":48117,"device_key":"key"}',
        ),
        isNull,
      );
      expect(
        PairDevicePayload.parseQrData(
          '{"kind":"bonded-pair-device","code":"code","port":48117,"device_key":"key"}',
        ),
        isNull,
      );
      expect(
        PairDevicePayload.parseQrData(
          '{"kind":"bonded-pair-device","code":"code","hosts":["192.168.1.50"],"device_key":"key"}',
        ),
        isNull,
      );
      expect(
        PairDevicePayload.parseQrData(
          '{"kind":"bonded-pair-device","code":"code","hosts":["192.168.1.50"],"port":48117}',
        ),
        isNull,
      );
      expect(PairDevicePayload.parseQrData('not json'), isNull);
    });
  });

  group('PairDeviceDelivery.fromJson', () {
    test('parses a phone delivery and rejects a wrong-shape body', () {
      final delivery = PairDeviceDelivery.fromJson({
        'code': 'code-123',
        'server_public_address': 'bonded.example.com:8080',
        'server_identity_public_key': 'server-key',
        'invite_token': 'token-123',
        'supported_protocols': ['h3', 'wss'],
      });
      expect(delivery, isNotNull);
      expect(delivery!.code, 'code-123');
      expect(delivery.supportedProtocols, ['h3', 'wss']);
      expect(
        PairDeviceDelivery.fromJson({'code': 'code-123'}),
        isNull,
      );
    });
  });
}
