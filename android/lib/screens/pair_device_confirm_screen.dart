import 'package:flutter/material.dart';

import '../models/pair_device_model.dart';
import '../models/pairing_model.dart';
import '../services/device_pairing_service.dart';
import '../services/pairing_service.dart';

/// Phone side of QR pairing: after scanning a TV's pairing code, pick one
/// of this phone's servers, mint a bound invite for the TV, and deliver the
/// server credentials to the TV over LAN.
class PairDeviceConfirmScreen extends StatefulWidget {
  final PairDevicePayload payload;

  const PairDeviceConfirmScreen({super.key, required this.payload});

  @override
  State<PairDeviceConfirmScreen> createState() =>
      _PairDeviceConfirmScreenState();
}

class _PairDeviceConfirmScreenState extends State<PairDeviceConfirmScreen> {
  List<PairedServer> _servers = [];
  PairedServer? _selected;
  bool _loading = true;
  bool _busy = false;
  bool _sent = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadServers();
  }

  Future<void> _loadServers() async {
    try {
      final raw = await PairingService.getPairedServers();
      final servers =
          raw.map((json) => PairedServer.fromJson(json)).toList();
      if (!mounted) return;
      setState(() {
        _servers = servers;
        _selected = servers.isNotEmpty ? servers.first : null;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = 'Failed to load paired servers: $e';
        _loading = false;
      });
    }
  }

  Future<void> _pair() async {
    final server = _selected;
    if (server == null) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final token = await DevicePairingService.mintInviteToken(
        serverAddress: server.publicAddress,
        serverIdentityPublicKey: server.serverIdentityPublicKey,
        targetDeviceKey: widget.payload.deviceKey,
      );
      final delivery = PairDeviceDelivery(
        code: widget.payload.code,
        serverPublicAddress: server.publicAddress,
        serverIdentityPublicKey: server.serverIdentityPublicKey,
        inviteToken: token,
        supportedProtocols: server.supportedProtocols,
      );
      await DevicePairingService.deliverPairingCredentials(
        widget.payload,
        delivery,
      );
      if (!mounted) return;
      setState(() {
        _sent = true;
        _busy = false;
      });
    } on PairingException catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.message;
        _busy = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = 'Pairing failed: $e';
        _busy = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Pair device')),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(
                Icons.tv,
                size: 64,
                color: Colors.teal,
              ),
              const SizedBox(height: 24),
              const Text(
                'Pair this device',
                style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 32),
              _buildDetailRow('Device', widget.payload.deviceLabel),
              const SizedBox(height: 16),
              _buildDetailRow(
                'Device key',
                widget.payload.deviceKeyFingerprint,
              ),
              const SizedBox(height: 16),
              if (_loading)
                const CircularProgressIndicator()
              else if (_servers.isEmpty)
                const Text(
                  'No paired servers on this phone yet. Pair a server first, then come back.',
                  textAlign: TextAlign.center,
                )
              else if (_servers.length == 1)
                _buildDetailRow('Server', _servers.first.publicAddress)
              else
                Row(
                  children: [
                    const Text('Server'),
                    const SizedBox(width: 16),
                    Expanded(
                      child: DropdownButton<PairedServer>(
                        isExpanded: true,
                        value: _selected,
                        items: [
                          for (final server in _servers)
                            DropdownMenuItem(
                              value: server,
                              child: Text(
                                server.publicAddress,
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                        ],
                        onChanged: _busy
                            ? null
                            : (server) =>
                                setState(() => _selected = server),
                      ),
                    ),
                  ],
                ),
              if (_error != null) ...[
                const SizedBox(height: 32),
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
              if (_sent) ...[
                const SizedBox(height: 32),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.green.withAlpha(50),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: Colors.green),
                  ),
                  child: const Text(
                    'Credentials sent — finish pairing on the TV.',
                    style: TextStyle(color: Colors.green),
                  ),
                ),
                const SizedBox(height: 32),
                ElevatedButton.icon(
                  onPressed: () => Navigator.of(context).pop(),
                  icon: const Icon(Icons.check),
                  label: const Text('Done'),
                ),
              ] else ...[
                const SizedBox(height: 32),
                ElevatedButton.icon(
                  onPressed:
                      (_busy || _selected == null) ? null : _pair,
                  icon: _busy
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.qr_code_2),
                  label: Text(_busy ? 'Pairing…' : 'Pair TV'),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Row(
      children: [
        SizedBox(
          width: 120,
          child: Text(
            label,
            style: TextStyle(color: Colors.grey[600]),
          ),
        ),
        Expanded(
          child: Text(value, overflow: TextOverflow.ellipsis),
        ),
      ],
    );
  }
}
