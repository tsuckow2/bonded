import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/pairing_model.dart';
import '../services/background_service.dart';
import '../services/pairing_service.dart';
import '../utils/background_notification_helper.dart';

class DashboardScreen extends StatefulWidget {
  final String deviceId;

  const DashboardScreen({super.key, required this.deviceId});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  String _vpnStatus = 'Unknown';
  String _connectedServer = 'Not connected';
  int _activePathCount = 1;
  bool _isConnecting = false;
  bool _isBackgroundRunning = false;
  bool _vpnRunning = false;
  StreamSubscription<BackgroundServiceEvent>? _backgroundEventsSubscription;

  // Bytes / uptime
  int _outboundBytes = 0;
  int _inboundBytes = 0;
  int _connectedAtMs = 0;
  int _transportCount = 0;
  int _peerRelayCount = 0;
  String _activeTransport = 'Unknown';
  String? _lastError;
  String? _peerShareError;
  PairedServer? _pairedServer;

  @override
  void initState() {
    super.initState();
    _loadPairedServer();
    _refreshStatus();
    _listenToBackgroundEvents();
  }

  Future<void> _loadPairedServer() async {
    try {
      final pairedServers = await PairingService.getPairedServers();
      final match = pairedServers
          .map(PairedServer.fromJson)
          .where((server) => server.id == widget.deviceId)
          .cast<PairedServer?>()
          .firstWhere((server) => server != null, orElse: () => null);
      if (!mounted) {
        return;
      }
      setState(() {
        _pairedServer = match;
      });
    } catch (_) {
      // Dashboard still works without paired-server metadata.
    }
  }

  void _listenToBackgroundEvents() {
    try {
      _backgroundEventsSubscription = BackgroundService.backgroundEvents.listen(
        (event) async {
          if (!mounted) {
            return;
          }

          setState(() {
            if (event.type == 'started') {
              _isBackgroundRunning = true;
            } else if (event.type == 'stopped' || event.type == 'error') {
              _isBackgroundRunning = false;
            }
          });

          if (event.type == 'session_status' ||
              event.type == 'started' ||
              event.type == 'error' ||
              event.type == 'stopped') {
            await _refreshStatus();
          }

          if (!mounted) {
            return;
          }

          if (event.message != null) {
            ScaffoldMessenger.of(
              context,
            ).showSnackBar(SnackBar(content: Text(event.message!)));
          }
        },
        onError: (error) {
          // Background event stream errors are non-fatal
          debugPrint('Background service event error: $error');
        },
      );
    } catch (e) {
      debugPrint('Failed to listen to background events: $e');
    }
  }

  Future<void> _refreshStatus() async {
    try {
      final bool vpnRunning =
          await _channel.invokeMethod<bool>('getVpnStatus') ?? false;
      final bool backgroundRunning =
          await BackgroundService.isBackgroundVpnRunning();
      final Map<dynamic, dynamic>? sessionStatus = await _channel
          .invokeMethod<Map<dynamic, dynamic>>('getVpnSessionStatus');
      final String sessionState = sessionStatus?['state'] as String? ?? '';
      final String serverAddress =
          sessionStatus?['serverAddress'] as String? ?? 'bonded.example.com';
      final int networkPathCount =
          (sessionStatus?['networkPathCount'] as num?)?.toInt() ?? 1;

      final int outboundBytes =
          (sessionStatus?['outboundBytes'] as num?)?.toInt() ?? 0;
      final int inboundBytes =
          (sessionStatus?['inboundBytes'] as num?)?.toInt() ?? 0;
      final int connectedAtMs =
          (sessionStatus?['connectedAtMs'] as num?)?.toInt() ?? 0;
        final int transportCount =
          (sessionStatus?['transportCount'] as num?)?.toInt() ?? 0;
        final int peerRelayCount =
          (sessionStatus?['peerRelayCount'] as num?)?.toInt() ?? 0;
        final String activeTransport =
          sessionStatus?['activeTransport'] as String? ?? 'Unknown';
      final String? lastError = sessionStatus?['lastError'] as String?;
      final String? peerShareError =
          sessionStatus?['peerShareError'] as String?;

      if (mounted) {
        setState(() {
          _vpnRunning = vpnRunning;
          _vpnStatus = switch (sessionState) {
            'connected' => 'Connected',
            'connecting' => 'Connecting',
            'error' => 'Error',
            _ => vpnRunning ? 'Connected' : 'Disconnected',
          };
          _connectedServer = serverAddress;
          _outboundBytes = outboundBytes;
          _inboundBytes = inboundBytes;
          _connectedAtMs = connectedAtMs;
          _transportCount = transportCount;
          _peerRelayCount = peerRelayCount;
          _activeTransport = activeTransport;
          _lastError = lastError?.isNotEmpty == true ? lastError : null;
          _peerShareError =
              peerShareError?.isNotEmpty == true ? peerShareError : null;
          _activePathCount = networkPathCount;
          _isBackgroundRunning = backgroundRunning;
        });
      }
    } on PlatformException {
      if (mounted) {
        setState(() {
          _vpnStatus = 'Unknown';
        });
      }
    }
  }

  Future<void> _toggleVpn() async {
    setState(() => _isConnecting = true);

    try {
      if (_vpnRunning) {
        await BackgroundService.stopBackgroundService();
      } else {
        await BackgroundService.startBackgroundService(
          deviceId: widget.deviceId,
        );
      }
      await _refreshStatus();
    } on BackgroundServiceException catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error: ${e.message}'),
            backgroundColor: Colors.red,
          ),
        );
      }
    } on PlatformException catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error: ${e.message}'),
            backgroundColor: Colors.red,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isConnecting = false);
      }
    }
  }

  @override
  void dispose() {
    _backgroundEventsSubscription?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isConnected = _vpnStatus == 'Connected';
    final isConnecting = _vpnStatus == 'Connecting';
    final isError = _vpnStatus == 'Error';
    final statusColor = isConnected
        ? Colors.green
        : isConnecting
        ? Colors.orange
        : isError
        ? Colors.red
        : Colors.grey;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Bonded VPN'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _refreshStatus,
          ),
          IconButton(
            icon: const Icon(Icons.article_outlined),
            tooltip: 'Client Logs',
            onPressed: () => Navigator.of(context).pushNamed('/client-logs'),
          ),
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () => Navigator.of(context).pushNamed('/settings'),
          ),
        ],
      ),
      body: Column(
        children: [
          if (_isBackgroundRunning)
            BackgroundNotificationHelper.buildBackgroundIndicator(
              _isBackgroundRunning,
              _connectedServer,
            ),
          Expanded(
            child: Center(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    // Large VPN status indicator
                    _StatusIndicator(status: _vpnStatus, color: statusColor),
                    const SizedBox(height: 32),
                    // Connection stats card
                    _ConnectionStatsCard(
                      server: _connectedServer,
                      activePaths: _activePathCount,
                      activeTransport: _activeTransport,
                      transportCount: _transportCount,
                      outboundBytes: _outboundBytes,
                      inboundBytes: _inboundBytes,
                      connectedAtMs: _connectedAtMs,
                      isConnected: isConnected,
                    ),
                    if (_pairedServer != null) ...[
                      const SizedBox(height: 12),
                      _TrustStatusCard(
                        server: _pairedServer!,
                        activeTransport: _activeTransport,
                      ),
                      const SizedBox(height: 12),
                      _PeerShareStatusCard(
                        server: _pairedServer!,
                        peerRelayCount: _peerRelayCount,
                        peerShareError: _peerShareError,
                      ),
                    ],
                    if (_lastError != null) ...[
                      const SizedBox(height: 12),
                      _ErrorBanner(message: _lastError!),
                    ],
                    const SizedBox(height: 32),
                    // Connect / Disconnect
                    _ConnectButton(
                      isConnected: _vpnRunning,
                      isConnecting: _isConnecting,
                      onTap: _toggleVpn,
                    ),
                    const SizedBox(height: 16),
                    OutlinedButton.icon(
                      onPressed: () =>
                          Navigator.of(context).pushNamed('/client-logs'),
                      icon: const Icon(Icons.article_outlined),
                      label: const Text('View Client Logs'),
                    ),
                    const SizedBox(height: 8),
                    OutlinedButton(
                      onPressed: () => Navigator.of(context).pop(),
                      child: const Text('Back'),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// ── Reusable sub-widgets ──────────────────────────────────────────────────────

class _StatusIndicator extends StatelessWidget {
  final String status;
  final Color color;
  const _StatusIndicator({required this.status, required this.color});

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Container(
          width: 120,
          height: 120,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: color.withAlpha(40),
            border: Border.all(color: color, width: 3),
          ),
          child: Center(
            child: Icon(
              status == 'Connected' ? Icons.vpn_lock : Icons.lock_open,
              size: 60,
              color: color,
            ),
          ),
        ),
        const SizedBox(height: 16),
        Text(
          status,
          style: TextStyle(
            fontSize: 28,
            fontWeight: FontWeight.bold,
            color: color,
          ),
        ),
      ],
    );
  }
}

class _ConnectionStatsCard extends StatelessWidget {
  final String server;
  final int activePaths;
  final String activeTransport;
  final int transportCount;
  final int outboundBytes;
  final int inboundBytes;
  final int connectedAtMs;
  final bool isConnected;

  const _ConnectionStatsCard({
    required this.server,
    required this.activePaths,
    required this.activeTransport,
    required this.transportCount,
    required this.outboundBytes,
    required this.inboundBytes,
    required this.connectedAtMs,
    required this.isConnected,
  });

  String _fmtBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) {
      return '${(bytes / 1024).toStringAsFixed(1)} KB';
    }
    return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB';
  }

  String _uptime() {
    if (!isConnected || connectedAtMs == 0) return '—';
    final elapsed = DateTime.now().millisecondsSinceEpoch - connectedAtMs;
    if (elapsed <= 0) return '—';
    final d = Duration(milliseconds: elapsed);
    final h = d.inHours;
    final m = d.inMinutes.remainder(60);
    final s = d.inSeconds.remainder(60);
    if (h > 0) return '${h}h ${m}m ${s}s';
    if (m > 0) return '${m}m ${s}s';
    return '${s}s';
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.grey[100],
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.grey[300]!),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _Row('Server', server),
          const Divider(height: 16),
          _Row('Active transport', activeTransport),
          const Divider(height: 16),
          _Row('Session transports', '$transportCount'),
          const Divider(height: 16),
          _Row('Active paths', '$activePaths'),
          const Divider(height: 16),
          _Row('Uptime', _uptime()),
          const Divider(height: 16),
          _Row('Sent', _fmtBytes(outboundBytes)),
          const Divider(height: 16),
          _Row('Received', _fmtBytes(inboundBytes)),
        ],
      ),
    );
  }
}

class _TrustStatusCard extends StatelessWidget {
  final PairedServer server;
  final String activeTransport;

  const _TrustStatusCard({required this.server, required this.activeTransport});

  String _shortKey(String value) {
    if (value.length <= 20) {
      return value;
    }
    return '${value.substring(0, 12)}...${value.substring(value.length - 8)}';
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.blueGrey[50],
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.blueGrey[100]!),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Trust and Transport',
            style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
          ),
          const SizedBox(height: 12),
          _Row('Trusted identity', _shortKey(server.serverIdentityPublicKey)),
          const Divider(height: 16),
          _Row(
            'Advertised protocols',
            server.supportedProtocols.isEmpty
                ? 'Auto'
                : server.supportedProtocols.join(', '),
          ),
          const Divider(height: 16),
          _Row('Current transport', activeTransport),
        ],
      ),
    );
  }
}

class _PeerShareStatusCard extends StatelessWidget {
  final PairedServer server;
  final int peerRelayCount;
  final String? peerShareError;

  const _PeerShareStatusCard({
    required this.server,
    required this.peerRelayCount,
    this.peerShareError,
  });

  String _displayValue(String value) => value.isEmpty ? 'Not set' : value;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.teal[50],
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.teal[100]!),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Peer Sharing',
            style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
          ),
          const SizedBox(height: 12),
          _Row('Enabled', server.peerShareEnabled ? 'Yes' : 'No'),
          const Divider(height: 16),
          _Row('Bind address', _displayValue(server.peerShareBindAddress)),
          const Divider(height: 16),
          _Row('Advertise IP', _displayValue(server.peerShareAdvertiseIp)),
          const Divider(height: 16),
          _Row('Max consumers', '${server.peerShareMaxConsumers}'),
          const Divider(height: 16),
          _Row(
            'Bandwidth cap',
            server.peerShareRelayBandwidthKbps == 0
                ? 'Unlimited'
                : '${server.peerShareRelayBandwidthKbps} kbps',
          ),
          const Divider(height: 16),
          _Row('Active peer relays', '$peerRelayCount'),
          if (peerShareError != null) ...[
            const Divider(height: 16),
            Text(
              'Peer-share failed to start — this device is connected directly only.\n$peerShareError',
              style: TextStyle(color: Colors.red[700], fontSize: 13),
            ),
          ],
        ],
      ),
    );
  }
}

class _Row extends StatelessWidget {
  final String label;
  final String value;
  const _Row(this.label, this.value);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: TextStyle(color: Colors.grey[600], fontSize: 14)),
          Text(
            value,
            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
          ),
        ],
      ),
    );
  }
}

class _ErrorBanner extends StatelessWidget {
  final String message;
  const _ErrorBanner({required this.message});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.red[50],
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.red[200]!),
      ),
      child: Row(
        children: [
          const Icon(Icons.error_outline, color: Colors.red, size: 18),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              message,
              style: const TextStyle(color: Colors.red, fontSize: 13),
            ),
          ),
        ],
      ),
    );
  }
}

class _ConnectButton extends StatelessWidget {
  final bool isConnected;
  final bool isConnecting;
  final VoidCallback onTap;
  const _ConnectButton({
    required this.isConnected,
    required this.isConnecting,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return FilledButton.icon(
      onPressed: isConnecting ? null : onTap,
      style: FilledButton.styleFrom(
        backgroundColor: isConnected ? Colors.red : Colors.green,
        padding: const EdgeInsets.symmetric(horizontal: 48, vertical: 18),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(32)),
      ),
      icon: isConnecting
          ? const SizedBox(
              width: 18,
              height: 18,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: Colors.white,
              ),
            )
          : Icon(isConnected ? Icons.stop_circle : Icons.play_circle, size: 22),
      label: Text(
        isConnected ? 'Disconnect' : 'Connect',
        style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w600),
      ),
    );
  }
}
