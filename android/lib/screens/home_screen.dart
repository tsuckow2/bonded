import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../services/pairing_service.dart';
import '../models/pairing_model.dart';
import '../services/background_service.dart';
import '../widgets/app_update_checker.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  Future<List<Map<String, dynamic>>>? _pairedServersFuture;
  static const _statusChannel = MethodChannel('bonded/native');
  String? _activeDeviceId;
  bool _vpnRunning = false;

  @override
  void initState() {
    super.initState();
    _loadPairedServers();
    _refreshVpnStatus();
  }

  void _loadPairedServers() {
    setState(() {
      _pairedServersFuture = PairingService.getPairedServers();
    });
  }

  Future<void> _refreshVpnStatus() async {
    try {
      final running =
          await _statusChannel.invokeMethod<bool>('getVpnStatus') ?? false;
      final status = await _statusChannel.invokeMethod<Map<dynamic, dynamic>>(
        'getVpnSessionStatus',
      );
      final serverAddress = status?['serverAddress'] as String? ?? '';
      if (mounted) {
        setState(() {
          _vpnRunning = running;
          // Try to match running server address to a device ID via the paired
          // server list – good enough for status display without extra channels.
          if (!running) {
            _activeDeviceId = null;
          } else if (serverAddress.isNotEmpty) {
            _activeDeviceId = serverAddress;
          }
        });
      }
    } catch (_) {}
  }

  Future<void> _disconnectVpn() async {
    try {
      await BackgroundService.stopBackgroundService();
      if (mounted) {
        setState(() {
          _vpnRunning = false;
          _activeDeviceId = null;
        });
      }
    } on BackgroundServiceException catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Disconnect failed: ${e.message}'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  Future<void> _openQrScanner() async {
    final result = await Navigator.of(context).pushNamed('/qr-scanner');
    if (result != null && mounted) {
      _loadPairedServers();
    }
  }

  Future<void> _openServerConfig(Map<String, dynamic> server) async {
    final pairedServer = PairedServer.fromJson(server);
    final result = await Navigator.of(
      context,
    ).pushNamed('/server-config', arguments: pairedServer);
    if (result == true && mounted) {
      _loadPairedServers();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Bonded VPN'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        actions: [
          if (_vpnRunning)
            Padding(
              padding: const EdgeInsets.only(right: 8),
              child: Chip(
                avatar: const Icon(
                  Icons.vpn_lock,
                  size: 16,
                  color: Colors.white,
                ),
                label: const Text(
                  'Connected',
                  style: TextStyle(color: Colors.white, fontSize: 12),
                ),
                backgroundColor: Colors.green,
                padding: EdgeInsets.zero,
              ),
            ),
          IconButton(
            icon: const Icon(Icons.bolt),
            tooltip: 'Protocol Stress Test',
            onPressed: () {
              Navigator.of(context).pushNamed('/stress-tests');
            },
          ),
          IconButton(
            icon: const Icon(Icons.science),
            tooltip: 'Network Tests',
            onPressed: () {
              Navigator.of(context).pushNamed('/network-tests');
            },
          ),
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: () {
              _loadPairedServers();
              _refreshVpnStatus();
            },
          ),
        ],
      ),
      body: Column(
        children: [
          // The app update check lives on the first page (build 178):
          // banner when Play has a newer build, plus the manual check
          // button. It used to be buried on the per-server dashboard.
          const AppUpdateChecker(),
          Expanded(
            child: FutureBuilder<List<Map<String, dynamic>>>(
              future: _pairedServersFuture,
              builder: (context, snapshot) {
                if (snapshot.connectionState == ConnectionState.waiting) {
                  return const Center(child: CircularProgressIndicator());
                }

                final pairedServers = snapshot.data ?? [];

                if (pairedServers.isEmpty) {
                  return Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(
                          Icons.security,
                          size: 64,
                          color: Colors.grey,
                        ),
                        const SizedBox(height: 16),
                        const Text(
                          'No paired servers',
                          style: TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Scan a server QR code to get started',
                          style: TextStyle(
                            fontSize: 14,
                            color: Colors.grey[600],
                          ),
                        ),
                        const SizedBox(height: 32),
                        ElevatedButton.icon(
                          onPressed: _openQrScanner,
                          icon: const Icon(Icons.qr_code_2),
                          label: const Text('Scan QR Code'),
                          style: ElevatedButton.styleFrom(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 32,
                              vertical: 16,
                            ),
                          ),
                        ),
                      ],
                    ),
                  );
                }

                return ListView.builder(
                  padding: const EdgeInsets.all(16),
                  itemCount: pairedServers.length + 1,
                  itemBuilder: (context, index) {
                    if (index == pairedServers.length) {
                      return Padding(
                        padding: const EdgeInsets.symmetric(vertical: 16),
                        child: ElevatedButton.icon(
                          onPressed: _openQrScanner,
                          icon: const Icon(Icons.add),
                          label: const Text('Add Server'),
                        ),
                      );
                    }

                    final server = pairedServers[index];
                    return _buildServerCard(context, server);
                  },
                );
              },
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildServerCard(BuildContext context, Map<String, dynamic> server) {
    final serverAddress = server['publicAddress'] as String? ?? '';
    // Consider this server "active" when VPN is running and the address matches.
    final isActive =
        _vpnRunning &&
        (_activeDeviceId == server['id'] || _activeDeviceId == serverAddress);

    return Card(
      child: ListTile(
        leading: const Icon(Icons.dns, color: Colors.teal),
        title: Text(
          server['publicAddress'] ?? 'Unknown Server',
          style: const TextStyle(fontWeight: FontWeight.bold),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const SizedBox(height: 4),
            Text(
              'Protocols: ${(server['supportedProtocols'] as List?)?.join(', ') ?? 'unknown'}',
              style: const TextStyle(fontSize: 12),
            ),
            if (isActive)
              const Text(
                'Active',
                style: TextStyle(
                  fontSize: 12,
                  color: Colors.green,
                  fontWeight: FontWeight.w600,
                ),
              ),
          ],
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (isActive)
              IconButton(
                icon: const Icon(Icons.stop_circle, color: Colors.red),
                tooltip: 'Disconnect',
                onPressed: _disconnectVpn,
              )
            else
              IconButton(
                icon: const Icon(Icons.play_circle, color: Colors.green),
                tooltip: 'Connect',
                onPressed: () async {
                  final deviceId = server['id'] as String? ?? '';
                  await Navigator.of(
                    context,
                  ).pushNamed('/dashboard', arguments: {'deviceId': deviceId});
                  if (mounted) _refreshVpnStatus();
                },
              ),
            PopupMenuButton(
              itemBuilder: (context) => [
                PopupMenuItem(
                  onTap: () {
                    Navigator.of(context).pushNamed(
                      '/dashboard',
                      arguments: {'deviceId': server['id'] ?? ''},
                    );
                  },
                  child: const Text('Open dashboard'),
                ),
                PopupMenuItem(
                  onTap: () => _openServerConfig(server),
                  child: const Text('Configure'),
                ),
              ],
            ),
          ],
        ),
        onTap: () {
          Navigator.of(context).pushNamed(
            '/dashboard',
            arguments: {'deviceId': server['id'] ?? ''},
          );
        },
      ),
    );
  }
}
