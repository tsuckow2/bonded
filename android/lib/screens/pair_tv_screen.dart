import 'dart:async';

import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../models/pair_device_model.dart';
import '../services/app_settings_service.dart';
import '../services/device_pairing_service.dart';
import '../services/pairing_service.dart';

/// Camera-less client side of QR pairing: shows a big QR code for a phone
/// running the Bonded app to scan, then redeems the credentials the phone
/// delivers over LAN.
class PairTvScreen extends StatefulWidget {
  const PairTvScreen({super.key});

  @override
  State<PairTvScreen> createState() => _PairTvScreenState();
}

class _PairTvScreenState extends State<PairTvScreen> {
  PairingListener? _listener;
  PairDevicePayload? _payload;
  String? _error;
  String _status = 'Starting…';
  int _secondsLeft = 300;
  Timer? _countdown;
  bool _pairing = false;

  @override
  void initState() {
    super.initState();
    _start();
  }

  Future<void> _start() async {
    await _listener?.close();
    _countdown?.cancel();
    setState(() {
      _error = null;
      _status = 'Starting…';
      _secondsLeft = 300;
      _payload = null;
      _pairing = false;
    });
    try {
      final deviceKey = await DevicePairingService.getDevicePublicKey();
      final hosts = await DevicePairingService.localLanAddresses();
      if (hosts.isEmpty) {
        throw PairingException('No LAN address found on this device');
      }
      final listener = await PairingListener.start();
      if (!mounted) {
        await listener.close();
        return;
      }
      final payload = PairDevicePayload(
        code: listener.code,
        hosts: hosts,
        port: PairDevicePayload.pairingPort,
        deviceLabel: 'TV',
        deviceKey: deviceKey,
      );
      setState(() {
        _listener = listener;
        _payload = payload;
        _status = 'Waiting for your phone to scan…';
      });
      _countdown = Timer.periodic(const Duration(seconds: 1), (_) {
        if (!mounted) return;
        setState(() {
          _secondsLeft = (_secondsLeft - 1).clamp(0, 300);
          if (_secondsLeft == 0) {
            _status = 'Code expired — generate a new one.';
          }
        });
      });
      final delivery = await listener.waitForDelivery;
      if (!mounted) return;
      await _redeem(delivery);
    } on PairingException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } on TimeoutException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message ?? 'Pairing code expired');
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = 'Pairing failed: $e');
    }
  }

  Future<void> _redeem(PairDeviceDelivery delivery) async {
    setState(() {
      _pairing = true;
      _status = 'Pairing with server…';
    });
    try {
      final deviceId = await PairingService.redeemInviteToken(
        serverAddress: delivery.serverPublicAddress,
        serverIdentityPublicKey: delivery.serverIdentityPublicKey,
        inviteToken: delivery.inviteToken,
      );
      await PairingService.storePairedServer(
        deviceId: deviceId,
        publicAddress: delivery.serverPublicAddress,
        serverIdentityPublicKey: delivery.serverIdentityPublicKey,
        supportedProtocols: delivery.supportedProtocols,
      );
      final settings = await AppSettingsService.load();
      await AppSettingsService.update(
        settings.copyWith(selectedServerId: deviceId),
      );
      if (!mounted) return;
      setState(() => _status = 'Paired! Opening home…');
      Navigator.of(context).pushNamedAndRemoveUntil('/home', (route) => false);
    } on PairingException catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.message;
        _pairing = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = 'Pairing failed: $e';
        _pairing = false;
      });
    }
  }

  @override
  void dispose() {
    _countdown?.cancel();
    _listener?.close();
    super.dispose();
  }

  String get _countdownText {
    final minutes = _secondsLeft ~/ 60;
    final seconds = _secondsLeft % 60;
    return 'Code expires in $minutes:${seconds.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Pair with your phone')),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              if (_payload == null && _error == null)
                const CircularProgressIndicator()
              else if (_payload != null) ...[
                Container(
                  padding: const EdgeInsets.all(16),
                  color: Colors.white,
                  child: QrImageView(
                    data: _payload!.toQrData(),
                    version: QrVersions.auto,
                    size: 320,
                  ),
                ),
                const SizedBox(height: 24),
                const Text(
                  'Scan with the Bonded app on your phone',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.w500),
                ),
                const SizedBox(height: 8),
                Text(
                  'This TV · key ${_payload!.deviceKeyFingerprint}',
                  style: TextStyle(color: Colors.grey[600]),
                ),
                const SizedBox(height: 8),
                Text(
                  _countdownText,
                  style: TextStyle(color: Colors.grey[600]),
                ),
              ],
              const SizedBox(height: 16),
              Text(
                _status,
                textAlign: TextAlign.center,
                style: const TextStyle(fontSize: 16),
              ),
              if (_pairing) ...[
                const SizedBox(height: 16),
                const CircularProgressIndicator(),
              ],
              if (_error != null) ...[
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.red.withAlpha(50),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: Colors.red),
                  ),
                  child: Text(
                    _error!,
                    style: const TextStyle(color: Colors.red),
                  ),
                ),
              ],
              const SizedBox(height: 32),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  OutlinedButton.icon(
                    onPressed: _pairing ? null : _start,
                    icon: const Icon(Icons.refresh),
                    label: const Text('New code'),
                  ),
                  const SizedBox(width: 16),
                  OutlinedButton.icon(
                    onPressed: _pairing
                        ? null
                        : () => Navigator.of(context).pop(),
                    icon: const Icon(Icons.close),
                    label: const Text('Cancel'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
