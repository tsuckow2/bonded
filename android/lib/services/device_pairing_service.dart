import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/services.dart';

import '../models/pair_device_model.dart';
import 'pairing_service.dart';

class DevicePairingService {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  /// This device's public key (creating the keypair on first run).
  static Future<String> getDevicePublicKey() async {
    try {
      final String key =
          await _channel.invokeMethod<String>('getDevicePublicKey') ?? '';
      if (key.isEmpty) {
        throw PairingException('Empty device key from native runtime');
      }
      return key;
    } on PlatformException catch (e) {
      throw PairingException('Failed to get device key: ${e.message}');
    }
  }

  /// Mint a bound invite for [targetDeviceKey] from the given server.
  static Future<String> mintInviteToken({
    required String serverAddress,
    required String serverIdentityPublicKey,
    required String targetDeviceKey,
  }) async {
    try {
      final String token =
          await _channel.invokeMethod<String>('mintInviteToken', {
            'serverAddress': serverAddress,
            'serverIdentityPublicKey': serverIdentityPublicKey,
            'targetDeviceKey': targetDeviceKey,
          }) ??
          '';
      if (token.isEmpty) {
        throw PairingException('Empty invite token from native runtime');
      }
      return token;
    } on PlatformException catch (e) {
      throw PairingException('Failed to mint invite token: ${e.message}');
    }
  }

  /// POST [delivery] to the TV's listener, trying each advertised host in
  /// order. Throws [PairingException] if no host accepts it.
  static Future<void> deliverPairingCredentials(
    PairDevicePayload payload,
    PairDeviceDelivery delivery,
  ) async {
    final errors = <String>[];
    final client = HttpClient();
    try {
      for (final host in payload.hosts) {
        try {
          final request = await client
              .post(host, payload.port, '/pair')
              .timeout(const Duration(seconds: 5));
          request.headers.contentType = ContentType.json;
          request.write(jsonEncode(delivery.toJson()));
          final response =
              await request.close().timeout(const Duration(seconds: 5));
          await response.drain();
          if (response.statusCode == 200) return;
          errors.add('$host: HTTP ${response.statusCode}');
        } catch (e) {
          errors.add('$host: $e');
        }
      }
    } finally {
      client.close(force: true);
    }
    throw PairingException(
      'Could not reach the TV on any advertised address (${errors.join('; ')})',
    );
  }

  /// Local LAN IPv4 addresses (non-loopback) for the TV QR payload.
  static Future<List<String>> localLanAddresses() async {
    final addresses = <String>[];
    for (final interface in await NetworkInterface.list()) {
      for (final address in interface.addresses) {
        if (address.type == InternetAddressType.IPv4 && !address.isLoopback) {
          addresses.add(address.address);
        }
      }
    }
    return addresses;
  }
}

/// Single-use LAN listener the TV runs while its pairing QR is on screen.
/// Completes [waitForDelivery] with the first code-valid delivery, or throws
/// on expiry (5 minutes) or after 5 bad codes.
class PairingListener {
  static const int port = PairDevicePayload.pairingPort;
  static const Duration lifetime = Duration(minutes: 5);
  static const int maxBadCodes = 5;

  final String code;
  HttpServer? _server;
  Timer? _timer;
  final Completer<PairDeviceDelivery> _completer = Completer();
  int _badCodes = 0;
  bool _closed = false;

  PairingListener._(this.code);

  /// Generate a fresh 128-bit pairing code (base64url, no padding).
  static String generateCode() {
    final random = Random.secure();
    final bytes = List<int>.generate(16, (_) => random.nextInt(256));
    return base64UrlEncode(bytes).replaceAll('=', '');
  }

  static Future<PairingListener> start() async {
    final listener = PairingListener._(generateCode());
    listener._server = await HttpServer.bind(InternetAddress.anyIPv4, port);
    listener._server!.listen(listener._handleRequest);
    listener._timer = Timer(lifetime, () {
      if (!listener._completer.isCompleted) {
        listener._completer.completeError(
          TimeoutException('Pairing code expired after 5 minutes'),
        );
      }
      listener.close();
    });
    return listener;
  }

  Future<PairDeviceDelivery> get waitForDelivery => _completer.future;

  Future<void> _handleRequest(HttpRequest request) async {
    try {
      if (request.method != 'POST' || request.uri.path != '/pair') {
        request.response.statusCode = HttpStatus.notFound;
        await request.response.close();
        return;
      }
      final body = await utf8.decoder.bind(request).join();
      final delivery = PairDeviceDelivery.fromJson(
        jsonDecode(body) as Map<String, dynamic>,
      );
      if (delivery == null || delivery.code != code) {
        _badCodes++;
        request.response.statusCode = HttpStatus.forbidden;
        await request.response.close();
        if (_badCodes >= maxBadCodes && !_completer.isCompleted) {
          _completer.completeError(
            PairingException('Too many invalid pairing attempts'),
          );
          await close();
        }
        return;
      }
      request.response.statusCode = HttpStatus.ok;
      await request.response.close();
      if (!_completer.isCompleted) _completer.complete(delivery);
      await close();
    } catch (_) {
      try {
        request.response.statusCode = HttpStatus.badRequest;
        await request.response.close();
      } catch (_) {}
    }
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _timer?.cancel();
    await _server?.close(force: true);
    _server = null;
  }
}
