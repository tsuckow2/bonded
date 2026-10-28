import 'package:flutter/material.dart';
import '../models/pairing_model.dart';
import '../services/app_settings_service.dart';
import '../services/pairing_service.dart';

class PairingConfirmScreen extends StatefulWidget {
  final ServerPairingPayload payload;

  const PairingConfirmScreen({super.key, required this.payload});

  @override
  State<PairingConfirmScreen> createState() => _PairingConfirmScreenState();
}

class _PairingConfirmScreenState extends State<PairingConfirmScreen> {
  bool _isPairing = false;
  String? _error;

  Future<void> _confirmPairing() async {
    setState(() {
      _isPairing = true;
      _error = null;
    });

    try {
      // Redeem the invite token and get device ID
      final deviceId = await PairingService.redeemInviteToken(
        serverAddress: widget.payload.publicAddress,
        serverIdentityPublicKey: widget.payload.serverIdentityPublicKey,
        inviteToken: widget.payload.inviteToken,
      );

      // Store paired server configuration
      await PairingService.storePairedServer(
        deviceId: deviceId,
        publicAddress: widget.payload.publicAddress,
        serverIdentityPublicKey: widget.payload.serverIdentityPublicKey,
      );

      // Success: make the new server the selected one and land on the
      // main screen, one tap from connecting.
      final settings = await AppSettingsService.load();
      await AppSettingsService.update(
        settings.copyWith(selectedServerId: deviceId),
      );
      if (mounted) {
        Navigator.of(context).pushNamedAndRemoveUntil('/home', (route) => false);
      }
    } on PairingException catch (e) {
      setState(() {
        _error = e.message;
        _isPairing = false;
      });
    } catch (e) {
      setState(() {
        _error = 'Pairing failed: $e';
        _isPairing = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Confirm Pairing')),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(
                Icons.check_circle_outline,
                size: 64,
                color: Colors.teal,
              ),
              const SizedBox(height: 24),
              const Text(
                'Pair with Server',
                style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 32),
              // Server details
              _buildDetailRow('Server Address', widget.payload.publicAddress),
              const SizedBox(height: 16),
              _buildDetailRow(
                'Server Identity Key (first 16 chars)',
                widget.payload.serverIdentityPublicKey.substring(
                  0,
                  widget.payload.serverIdentityPublicKey.length > 16
                      ? 16
                      : widget.payload.serverIdentityPublicKey.length,
                ),
              ),
              const SizedBox(height: 32),
              // Error message if applicable
              if (_error != null) ...{
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
                const SizedBox(height: 32),
              },
              // Action buttons
              ElevatedButton.icon(
                onPressed: _isPairing ? null : _confirmPairing,
                icon: _isPairing
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          valueColor: AlwaysStoppedAnimation<Color>(
                            Colors.white,
                          ),
                        ),
                      )
                    : const Icon(Icons.check),
                label: Text(_isPairing ? 'Pairing...' : 'Confirm Pairing'),
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 32,
                    vertical: 16,
                  ),
                  backgroundColor: Colors.teal,
                  disabledBackgroundColor: Colors.grey,
                ),
              ),
              const SizedBox(height: 16),
              OutlinedButton.icon(
                onPressed: _isPairing
                    ? null
                    : () => Navigator.of(context).pop(),
                icon: const Icon(Icons.close),
                label: const Text('Cancel'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: const TextStyle(
            fontSize: 12,
            color: Colors.grey,
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 6),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Colors.grey[100],
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: Colors.grey[300]!),
          ),
          child: Text(
            value,
            style: const TextStyle(fontSize: 14),
            maxLines: 3,
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }
}
