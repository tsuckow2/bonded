import 'dart:convert';

/// QR payload a camera-less client (e.g. TV) displays so a phone can pair
/// it with one of the phone's existing servers. The phone distinguishes
/// this from a server QR by the `kind` field.
class PairDevicePayload {
  static const int pairingPort = 48117;

  final String code;
  final List<String> hosts;
  final int port;
  final String deviceLabel;
  final String deviceKey;

  PairDevicePayload({
    required this.code,
    required this.hosts,
    required this.port,
    required this.deviceLabel,
    required this.deviceKey,
  });

  /// Short fingerprint shown on both screens so the user can confirm the
  /// phone scanned the TV in front of them.
  String get deviceKeyFingerprint =>
      deviceKey.length > 8 ? deviceKey.substring(0, 8) : deviceKey;

  String toQrData() => jsonEncode({
        'kind': 'bonded-pair-device',
        'version': 1,
        'code': code,
        'hosts': hosts,
        'port': port,
        'device_label': deviceLabel,
        'device_key': deviceKey,
      });

  static PairDevicePayload? parseQrData(String data) {
    try {
      final json = jsonDecode(data) as Map<String, dynamic>;
      if (json['kind'] != 'bonded-pair-device') return null;
      final code = (json['code'] ?? '').toString().trim();
      final hosts = List<String>.from(json['hosts'] ?? [])
          .map((h) => h.toString().trim())
          .where((h) => h.isNotEmpty)
          .toList();
      final port = (json['port'] as num?)?.toInt() ?? 0;
      final deviceKey = (json['device_key'] ?? '').toString().trim();
      if (code.isEmpty ||
          hosts.isEmpty ||
          port <= 0 ||
          port > 65535 ||
          deviceKey.isEmpty) {
        return null;
      }
      return PairDevicePayload(
        code: code,
        hosts: hosts,
        port: port,
        deviceLabel: (json['device_label'] ?? 'TV').toString(),
        deviceKey: deviceKey,
      );
    } catch (_) {
      return null;
    }
  }
}

/// Credentials the phone delivers to the TV's LAN listener.
class PairDeviceDelivery {
  final String code;
  final String serverPublicAddress;
  final String serverIdentityPublicKey;
  final String inviteToken;
  final List<String> supportedProtocols;

  PairDeviceDelivery({
    required this.code,
    required this.serverPublicAddress,
    required this.serverIdentityPublicKey,
    required this.inviteToken,
    required this.supportedProtocols,
  });

  Map<String, dynamic> toJson() => {
        'code': code,
        'server_public_address': serverPublicAddress,
        'server_identity_public_key': serverIdentityPublicKey,
        'invite_token': inviteToken,
        'supported_protocols': supportedProtocols,
      };

  static PairDeviceDelivery? fromJson(Map<String, dynamic> json) {
    try {
      final code = (json['code'] ?? '').toString().trim();
      final serverPublicAddress =
          (json['server_public_address'] ?? '').toString().trim();
      final serverIdentityPublicKey =
          (json['server_identity_public_key'] ?? json['server_public_key'] ?? '')
              .toString()
              .trim();
      final inviteToken = (json['invite_token'] ?? '').toString().trim();
      if (code.isEmpty ||
          serverPublicAddress.isEmpty ||
          serverIdentityPublicKey.isEmpty ||
          inviteToken.isEmpty) {
        return null;
      }
      return PairDeviceDelivery(
        code: code,
        serverPublicAddress: serverPublicAddress,
        serverIdentityPublicKey: serverIdentityPublicKey,
        inviteToken: inviteToken,
        supportedProtocols: List<String>.from(json['supported_protocols'] ?? []),
      );
    } catch (_) {
      return null;
    }
  }
}
