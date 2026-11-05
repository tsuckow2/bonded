import 'package:flutter/material.dart';
import '../models/pairing_model.dart';
import '../widgets/remote_text_field.dart';
import '../services/pairing_service.dart';

class ServerConfigScreen extends StatefulWidget {
  final PairedServer server;

  const ServerConfigScreen({super.key, required this.server});

  @override
  State<ServerConfigScreen> createState() => _ServerConfigScreenState();
}

class _ServerConfigScreenState extends State<ServerConfigScreen> {
  late TextEditingController _serverAddressController;
  late TextEditingController _publicKeyController;
  late TextEditingController _peerShareBindAddressController;
  late TextEditingController _peerShareAdvertiseIpController;
  late TextEditingController _peerShareMaxConsumersController;
  late TextEditingController _peerShareRelayBandwidthController;
  late List<String> _selectedProtocols;
  late bool _peerShareEnabled;
  late bool _diagnosticsUploadEnabled;
  late TextEditingController _diagnosticsUploadPeriodController;
  bool _isSaving = false;
  // Remote navigation: Back exits editing instead of popping the page
  // while any field below is editing. See RemoteTextField.
  bool _isAnyFieldEditing = false;
  final _serverAddressFieldKey = GlobalKey<RemoteTextFieldState>();
  final _publicKeyFieldKey = GlobalKey<RemoteTextFieldState>();
  final _peerShareBindFieldKey = GlobalKey<RemoteTextFieldState>();
  final _peerShareAdvertiseFieldKey = GlobalKey<RemoteTextFieldState>();
  final _peerShareMaxConsumersFieldKey = GlobalKey<RemoteTextFieldState>();
  final _peerShareBandwidthFieldKey = GlobalKey<RemoteTextFieldState>();
  final _diagnosticsPeriodFieldKey = GlobalKey<RemoteTextFieldState>();

  @override
  void initState() {
    super.initState();
    _serverAddressController = TextEditingController(
      text: widget.server.publicAddress,
    );
    _publicKeyController = TextEditingController(
      text: widget.server.serverIdentityPublicKey,
    );
    _peerShareBindAddressController = TextEditingController(
      text: widget.server.peerShareBindAddress,
    );
    _peerShareAdvertiseIpController = TextEditingController(
      text: widget.server.peerShareAdvertiseIp,
    );
    _peerShareMaxConsumersController = TextEditingController(
      text: widget.server.peerShareMaxConsumers.toString(),
    );
    _peerShareRelayBandwidthController = TextEditingController(
      text: widget.server.peerShareRelayBandwidthKbps.toString(),
    );
    _selectedProtocols = List.from(widget.server.supportedProtocols);
    _peerShareEnabled = widget.server.peerShareEnabled;
    _diagnosticsUploadEnabled = widget.server.diagnosticsUploadEnabled;
    _diagnosticsUploadPeriodController = TextEditingController(
      text: widget.server.diagnosticsUploadPeriodSecs.toString(),
    );
  }

  @override
  void dispose() {
    _serverAddressController.dispose();
    _publicKeyController.dispose();
    _peerShareBindAddressController.dispose();
    _peerShareAdvertiseIpController.dispose();
    _peerShareMaxConsumersController.dispose();
    _peerShareRelayBandwidthController.dispose();
    _diagnosticsUploadPeriodController.dispose();
    super.dispose();
  }

  Future<void> _saveConfiguration() async {
    final updatedServer = PairedServer(
      id: widget.server.id,
      publicAddress: _serverAddressController.text.trim(),
      serverIdentityPublicKey: _publicKeyController.text.trim(),
      supportedProtocols: List<String>.from(_selectedProtocols),
      peerShareEnabled: _peerShareEnabled,
      peerShareBindAddress: _peerShareBindAddressController.text.trim(),
      peerShareAdvertiseIp: _peerShareAdvertiseIpController.text.trim(),
      peerShareMaxConsumers:
          int.tryParse(_peerShareMaxConsumersController.text.trim()) ?? 4,
      peerShareRelayBandwidthKbps:
          int.tryParse(_peerShareRelayBandwidthController.text.trim()) ?? 0,
      diagnosticsUploadEnabled: _diagnosticsUploadEnabled,
      diagnosticsUploadPeriodSecs:
          int.tryParse(_diagnosticsUploadPeriodController.text.trim()) ?? 900,
      pairedAt: widget.server.pairedAt,
    );

    if (updatedServer.publicAddress.isEmpty ||
        updatedServer.serverIdentityPublicKey.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Server address and identity key are required'),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }

    setState(() => _isSaving = true);

    try {
      await PairingService.updatePairedServer(updatedServer);

      if (!mounted) {
        return;
      }

      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Configuration saved'),
          backgroundColor: Colors.green,
        ),
      );
      setState(() => _isSaving = false);
      Navigator.of(context).pop(true);
    } on PairingException catch (e) {
      if (!mounted) {
        return;
      }

      setState(() => _isSaving = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.message), backgroundColor: Colors.red),
      );
    } catch (e) {
      if (!mounted) {
        return;
      }

      setState(() => _isSaving = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Failed to save configuration: $e'),
          backgroundColor: Colors.red,
        ),
      );
    }
  }

  Future<void> _deleteServer() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder:
          (context) => AlertDialog(
            title: const Text('Delete Server?'),
            content: Text(
              'Remove ${widget.server.publicAddress} from paired servers?',
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('Cancel'),
              ),
              TextButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text(
                  'Delete',
                  style: TextStyle(color: Colors.red),
                ),
              ),
            ],
          ),
    );

    if (confirm != true || !mounted) {
      return;
    }

    setState(() => _isSaving = true);

    try {
      await PairingService.deletePairedServer(widget.server.id);

      if (!mounted) {
        return;
      }

      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Server removed')));
      setState(() => _isSaving = false);
      Navigator.of(context).pop(true);
    } on PairingException catch (e) {
      if (!mounted) {
        return;
      }

      setState(() => _isSaving = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.message), backgroundColor: Colors.red),
      );
    } catch (e) {
      if (!mounted) {
        return;
      }

      setState(() => _isSaving = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Failed to delete server: $e'),
          backgroundColor: Colors.red,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    // Back on a remote: while a field is editing, Back exits editing
    // (hides the keyboard, keeps focus on the field) instead of popping
    // this page. A second Back, with nothing editing, pops as usual.
    return PopScope(
      canPop: !_isAnyFieldEditing,
      onPopInvokedWithResult: (didPop, _) {
        if (didPop || !_isAnyFieldEditing) return;
        for (final key in [
          _serverAddressFieldKey,
          _publicKeyFieldKey,
          _peerShareBindFieldKey,
          _peerShareAdvertiseFieldKey,
          _peerShareMaxConsumersFieldKey,
          _peerShareBandwidthFieldKey,
          _diagnosticsPeriodFieldKey,
        ]) {
          key.currentState?.cancelEditing();
        }
      },
      child: Scaffold(
        appBar: AppBar(title: const Text('Server Configuration')),
        body: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'On a remote: move to a field and press OK to edit it. '
                'Back exits editing without leaving this page.',
                style: TextStyle(fontSize: 13, color: Colors.grey),
              ),
              const SizedBox(height: 16),
            const Text(
              'Server Address',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            RemoteTextField(
              key: _serverAddressFieldKey,
              controller: _serverAddressController,
              onEditingChanged:
                  (editing) => setState(() => _isAnyFieldEditing = editing),
              decoration: InputDecoration(
                hintText: 'Server address',
                filled: true,
                fillColor: Colors.grey[100],
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Server Identity Key',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            RemoteTextField(
              key: _publicKeyFieldKey,
              controller: _publicKeyController,
              maxLines: 3,
              onEditingChanged:
                  (editing) => setState(() => _isAnyFieldEditing = editing),
              decoration: InputDecoration(
                hintText: 'Trusted ed25519 identity key (base64)',
                filled: true,
                fillColor: Colors.grey[100],
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Supported Protocols',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 12),
            // Remote navigation: chip delete buttons are still tappable,
            // but they are excluded from D-pad traversal, so moving down
            // from the key field lands on the peer-sharing switch instead
            // of stepping through every protocol chip's delete button.
            ExcludeFocus(
              child: Wrap(
                spacing: 8,
                children:
                  _selectedProtocols
                      .map(
                        (protocol) => Chip(
                          label: Text(protocol),
                          onDeleted: () {
                            setState(() {
                              _selectedProtocols.remove(protocol);
                            });
                          },
                        ),
                      )
                      .toList(),
                ),
              ),
            const SizedBox(height: 24),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Enable Peer Sharing'),
              subtitle: const Text(
                'Advertise this device to nearby peers using the same Bonded server.',
              ),
              value: _peerShareEnabled,
              onChanged:
                  _isSaving
                      ? null
                      : (value) {
                        setState(() {
                          _peerShareEnabled = value;
                        });
                      },
            ),
            const SizedBox(height: 12),
            const Text(
              'Peer Share Bind Address',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            RemoteTextField(
              key: _peerShareBindFieldKey,
              controller: _peerShareBindAddressController,
              onEditingChanged:
                  (editing) => setState(() => _isAnyFieldEditing = editing),
              decoration: InputDecoration(
                hintText: '0.0.0.0:54443',
                filled: true,
                fillColor: Colors.grey[100],
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Peer Share Advertise IP',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            RemoteTextField(
              key: _peerShareAdvertiseFieldKey,
              controller: _peerShareAdvertiseIpController,
              onEditingChanged:
                  (editing) => setState(() => _isAnyFieldEditing = editing),
              decoration: InputDecoration(
                hintText: 'Optional LAN IP override',
                filled: true,
                fillColor: Colors.grey[100],
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Max Concurrent Consumers',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            RemoteTextField(
              key: _peerShareMaxConsumersFieldKey,
              controller: _peerShareMaxConsumersController,
              keyboardType: TextInputType.number,
              onEditingChanged:
                  (editing) => setState(() => _isAnyFieldEditing = editing),
              decoration: InputDecoration(
                hintText: '4',
                helperText: 'Max peers that can relay through this device',
                filled: true,
                fillColor: Colors.grey[100],
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Relay Bandwidth Cap (kbps)',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            RemoteTextField(
              key: _peerShareBandwidthFieldKey,
              controller: _peerShareRelayBandwidthController,
              keyboardType: TextInputType.number,
              onEditingChanged:
                  (editing) => setState(() => _isAnyFieldEditing = editing),
              decoration: InputDecoration(
                hintText: '0 = unlimited',
                helperText: 'Per-relay bandwidth limit, kilobits per second',
                filled: true,
                fillColor: Colors.grey[100],
              ),
            ),
            const SizedBox(height: 32),
            const Text(
              'Diagnostics',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Upload diagnostic logs'),
              subtitle: const Text(
                'Periodically send this device\'s diagnostic log to the server, signed with the device key. Successful uploads are silent; only failures are logged.',
              ),
              value: _diagnosticsUploadEnabled,
              onChanged:
                  _isSaving
                      ? null
                      : (value) {
                        setState(() {
                          _diagnosticsUploadEnabled = value;
                        });
                      },
            ),
            const SizedBox(height: 12),
            const Text(
              'Upload interval (seconds)',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            RemoteTextField(
              key: _diagnosticsPeriodFieldKey,
              controller: _diagnosticsUploadPeriodController,
              keyboardType: TextInputType.number,
              onEditingChanged:
                  (editing) => setState(() => _isAnyFieldEditing = editing),
              decoration: InputDecoration(
                hintText: '900',
                helperText: 'How often the log uploads (60–3600 seconds)',
                filled: true,
                fillColor: Colors.grey[100],
              ),
            ),
            const SizedBox(height: 32),
            const Text(
              'Device Information',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.grey[100],
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Colors.grey[300]!),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _buildInfoRow('Device ID', widget.server.id),
                  const SizedBox(height: 12),
                  _buildInfoRow(
                    'Paired At',
                    widget.server.pairedAt.toString().split('.')[0],
                  ),
                ],
              ),
            ),
            const SizedBox(height: 32),
            // Action buttons
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
              children: [
                ElevatedButton.icon(
                  onPressed: _isSaving ? null : _saveConfiguration,
                  icon:
                      _isSaving
                          ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                          : const Icon(Icons.save),
                  label: Text(_isSaving ? 'Saving...' : 'Save'),
                  style: ElevatedButton.styleFrom(backgroundColor: Colors.teal),
                ),
                OutlinedButton.icon(
                  onPressed: _isSaving ? null : _deleteServer,
                  icon: const Icon(Icons.delete),
                  label: const Text('Delete'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: Colors.red,
                    side: const BorderSide(color: Colors.red),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
      ),
    );
  }

  Widget _buildInfoRow(String label, String value) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label, style: const TextStyle(fontSize: 12, color: Colors.grey)),
        Flexible(
          child: Text(
            value,
            textAlign: TextAlign.end,
            style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }
}
