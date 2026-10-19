import 'package:flutter/services.dart';

import '../models/pairing_model.dart';

class PairingService {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  /// Redeem an invite token with the server and store the device keypair.
  /// Returns the generated device ID on success.
  static Future<String> redeemInviteToken({
    required String serverAddress,
    required String serverIdentityPublicKey,
    required String inviteToken,
  }) async {
    try {
      final String deviceId =
          await _channel.invokeMethod<String>('redeemInviteToken', {
            'serverAddress': serverAddress,
            'serverIdentityPublicKey': serverIdentityPublicKey,
            'inviteToken': inviteToken,
          }) ??
          '';
      return deviceId;
    } on PlatformException catch (e) {
      throw PairingException('Failed to redeem invite token: ${e.message}');
    }
  }

  /// Store a paired server configuration locally.
  static Future<void> storePairedServer({
    required String deviceId,
    required String publicAddress,
    required String serverIdentityPublicKey,
    List<String> supportedProtocols = const [],
    bool peerShareEnabled = false,
    String peerShareBindAddress = '',
    String peerShareAdvertiseIp = '',
    int peerShareMaxConsumers = 4,
    int peerShareRelayBandwidthKbps = 0,
  }) async {
    try {
      await _channel.invokeMethod<void>('storePairedServer', {
        'deviceId': deviceId,
        'publicAddress': publicAddress,
        'serverIdentityPublicKey': serverIdentityPublicKey,
        'supportedProtocols': supportedProtocols,
        'peerShareEnabled': peerShareEnabled,
        'peerShareBindAddress': peerShareBindAddress,
        'peerShareAdvertiseIp': peerShareAdvertiseIp,
        'peerShareMaxConsumers': peerShareMaxConsumers,
        'peerShareRelayBandwidthKbps': peerShareRelayBandwidthKbps,
      });
    } on PlatformException catch (e) {
      throw PairingException('Failed to store paired server: ${e.message}');
    }
  }

  /// Retrieve all paired servers.
  static Future<List<Map<String, dynamic>>> getPairedServers() async {
    try {
      final List<dynamic> result =
          await _channel.invokeMethod<List<dynamic>>('getPairedServers') ?? [];
      return List<Map<String, dynamic>>.from(
        result.map((e) => Map<String, dynamic>.from(e as Map)),
      );
    } on PlatformException catch (e) {
      throw PairingException('Failed to get paired servers: ${e.message}');
    }
  }

  static Future<void> updatePairedServer(PairedServer server) async {
    try {
      await _channel.invokeMethod<void>('updatePairedServer', {
        'deviceId': server.id,
        'publicAddress': server.publicAddress,
        'serverIdentityPublicKey': server.serverIdentityPublicKey,
        'supportedProtocols': server.supportedProtocols,
        'peerShareEnabled': server.peerShareEnabled,
        'peerShareBindAddress': server.peerShareBindAddress,
        'peerShareAdvertiseIp': server.peerShareAdvertiseIp,
        'peerShareMaxConsumers': server.peerShareMaxConsumers,
        'peerShareRelayBandwidthKbps': server.peerShareRelayBandwidthKbps,
        'diagnosticsUploadEnabled': server.diagnosticsUploadEnabled,
        'diagnosticsUploadPeriodSecs': server.diagnosticsUploadPeriodSecs,
      });
    } on PlatformException catch (e) {
      throw PairingException('Failed to update paired server: ${e.message}');
    }
  }

  static Future<void> deletePairedServer(String deviceId) async {
    try {
      await _channel.invokeMethod<void>('deletePairedServer', {
        'deviceId': deviceId,
      });
    } on PlatformException catch (e) {
      throw PairingException('Failed to delete paired server: ${e.message}');
    }
  }
}

class PairingException implements Exception {
  final String message;
  PairingException(this.message);

  @override
  String toString() => message;
}
