import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/pairing_model.dart';
import '../models/session_status.dart';
import '../services/background_service.dart';
import '../services/pairing_service.dart';

/// The old dashboard, demoted to what it was actually good at: a
/// read-only deep view of the current session and the selected server.
/// Connecting and disconnecting live on the main screen now.
class DetailsScreen extends StatefulWidget {
  final String deviceId;

  const DetailsScreen({super.key, required this.deviceId});

  @override
  State<DetailsScreen> createState() => _DetailsScreenState();
}

class _DetailsScreenState extends State<DetailsScreen> {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  SessionStatus _status = SessionStatus.empty;
  bool _vpnRunning = false;
  PairedServer? _pairedServer;
  StreamSubscription<BackgroundServiceEvent>? _eventsSubscription;
  Timer? _pollTimer;

  @override
  void initState() {
    super.initState();
    _loadPairedServer();
    _refreshStatus();
    _eventsSubscription = BackgroundService.backgroundEvents.listen((event) {
      if (event.type == 'session_status' ||
          event.type == 'started' ||
          event.type == 'error' ||
          event.type == 'stopped') {
        _refreshStatus();
      }
    }, onError: (_) {});
    _pollTimer = Timer.periodic(
      const Duration(seconds: 2),
      (_) => _refreshStatus(),
    );
  }

  @override
  void dispose() {
    _eventsSubscription?.cancel();
    _pollTimer?.cancel();
    super.dispose();
  }

  Future<void> _loadPairedServer() async {
    try {
      final pairedServers = await PairingService.getPairedServers();
      final match = pairedServers
          .map(PairedServer.fromJson)
          .where((server) => server.id == widget.deviceId)
          .cast<PairedServer?>()
          .firstWhere((server) => server != null, orElse: () => null);
      if (mounted) setState(() => _pairedServer = match);
    } catch (_) {
      // Details still work without paired-server metadata.
    }
  }

  Future<void> _refreshStatus() async {
    try {
      final running =
          await _channel.invokeMethod<bool>('getVpnStatus') ?? false;
      final raw = await _channel.invokeMethod<Map<dynamic, dynamic>>(
        'getVpnSessionStatus',
      );
      if (!mounted) return;
      setState(() {
        _vpnRunning = running;
        _status = SessionStatus.fromMap(raw);
      });
    } catch (_) {}
  }

  String get _statusText {
    if (_status.isError) return 'Error';
    if (_status.isConnecting) return 'Connecting';
    if (_vpnRunning || _status.isConnected) return 'Connected';
    return 'Disconnected';
  }

  @override
  Widget build(BuildContext context) {
    final isConnected = _vpnRunning || _status.isConnected;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Session details'),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _refreshStatus),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _Card(
              title: 'Session',
              rows: [
                ('Status', _statusText),
                ('Server', _status.serverAddress.isEmpty ? '—' : _status.serverAddress),
                ('Active transport', _status.activeTransport),
                ('Session transports', '${_status.transportCount}'),
                ('Network paths', '${_status.networkPathCount}'),
                ('Uptime', _uptime(isConnected)),
                ('Sent', _fmtBytes(_status.outboundBytes)),
                ('Received', _fmtBytes(_status.inboundBytes)),
              ],
            ),
            if (_status.directPaths.isNotEmpty) ...[
              const SizedBox(height: 12),
              _Card(
                title: 'Paths',
                rows: [
                  for (final path in _status.directPaths) ...[
                    (
                      _pathLabel(path),
                      [
                        path.kind,
                        if (path.active) 'active',
                        if (path.lastRttMs > 0) '${path.lastRttMs} ms',
                        '↓ ${_fmtBytes(path.inboundBytes)}',
                        '↑ ${_fmtBytes(path.outboundBytes)}',
                      ].join(' · '),
                    ),
                    if (path.serverSeenAddress != null)
                      (
                        '${_pathLabel(path)} — server sees',
                        path.serverSeenAddress!,
                      ),
                  ],
                ],
              ),
            ],
            if (_pairedServer != null) ...[
              const SizedBox(height: 12),
              _Card(
                title: 'Trust and transport',
                rows: [
                  ('Trusted identity', _shortKey(_pairedServer!.serverIdentityPublicKey)),
                  (
                    'Advertised protocols',
                    _pairedServer!.supportedProtocols.isEmpty
                        ? 'Auto'
                        : _pairedServer!.supportedProtocols.join(', '),
                  ),
                  ('Current transport', _status.activeTransport),
                ],
              ),
              const SizedBox(height: 12),
              _Card(
                title: 'Peer sharing',
                rows: [
                  ('Enabled', _pairedServer!.peerShareEnabled ? 'Yes' : 'No'),
                  ('Bind address', _display(_pairedServer!.peerShareBindAddress)),
                  ('Advertise IP', _display(_pairedServer!.peerShareAdvertiseIp)),
                  ('Max consumers', '${_pairedServer!.peerShareMaxConsumers}'),
                  (
                    'Bandwidth cap',
                    _pairedServer!.peerShareRelayBandwidthKbps == 0
                        ? 'Unlimited'
                        : '${_pairedServer!.peerShareRelayBandwidthKbps} kbps',
                  ),
                  ('Active peer relays', '${_status.peerRelayCount}'),
                  (
                    'Diagnostics upload',
                    _pairedServer!.diagnosticsUploadEnabled
                        ? 'Every ${_pairedServer!.diagnosticsUploadPeriodSecs}s'
                        : 'Off',
                  ),
                ],
              ),
            ],
            if (_status.interception != null) ...[
              const SizedBox(height: 12),
              _InterceptionCard(status: _status),
            ],
            if (_status.peerShareError != null) ...[
              const SizedBox(height: 12),
              _ErrorBanner(
                message:
                    'Peer-share failed to start — this device is connected directly only.\n${_status.peerShareError}',
              ),
            ],
            if (_status.lastError != null) ...[
              const SizedBox(height: 12),
              _ErrorBanner(message: _status.lastError!),
            ],
          ],
        ),
      ),
    );
  }

  String _pathLabel(PathStat path) {
    final summary = _status.summaryFor(path.pathIndex);
    if (summary != null) {
      final split = summary.indexOf(':');
      if (split > 0) {
        final kind = summary.substring(0, split);
        final label = switch (kind.toLowerCase()) {
          'wifi' => 'Wi-Fi',
          'cellular' => 'Cellular',
          'ethernet' => 'Ethernet',
          _ => kind,
        };
        return '$label (${summary.substring(split + 1)})';
      }
    }
    return 'Path ${path.pathIndex}';
  }

  String _uptime(bool isConnected) {
    if (!isConnected || _status.connectedAtMs == 0) return '—';
    final elapsed =
        DateTime.now().millisecondsSinceEpoch - _status.connectedAtMs;
    if (elapsed <= 0) return '—';
    final d = Duration(milliseconds: elapsed);
    final h = d.inHours;
    final m = d.inMinutes.remainder(60);
    final s = d.inSeconds.remainder(60);
    if (h > 0) return '${h}h ${m}m ${s}s';
    if (m > 0) return '${m}m ${s}s';
    return '${s}s';
  }

  static String _fmtBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB';
  }

  static String _shortKey(String value) {
    if (value.length <= 20) return value;
    return '${value.substring(0, 12)}...${value.substring(value.length - 8)}';
  }

  static String _display(String value) => value.isEmpty ? 'Not set' : value;
}

class _Card extends StatelessWidget {
  final String title;
  final List<(String, String)> rows;
  const _Card({required this.title, required this.rows});

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 8),
            for (var i = 0; i < rows.length; i++) ...[
              if (i > 0) const Divider(height: 16),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    rows[i].$1,
                    style: TextStyle(color: Colors.grey[600], fontSize: 14),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: Text(
                      rows[i].$2,
                      textAlign: TextAlign.end,
                      style: const TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 14,
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _InterceptionCard extends StatelessWidget {
  final SessionStatus status;
  const _InterceptionCard({required this.status});

  @override
  Widget build(BuildContext context) {
    final warning = status.interception!;
    final (label, address) = status.describePath(warning.pathIndex);
    final connection = warning.pathIndex == null
        ? 'Identity check (before any path)'
        : '$label${address != null ? ' ($address)' : ''}';
    final when = DateTime.fromMillisecondsSinceEpoch(warning.atMs);
    final whenLabel =
        '${when.year}-${when.month.toString().padLeft(2, '0')}-${when.day.toString().padLeft(2, '0')} '
        '${when.hour.toString().padLeft(2, '0')}:${when.minute.toString().padLeft(2, '0')}:${when.second.toString().padLeft(2, '0')}';
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Colors.red[50],
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.red[300]!, width: 1.4),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.gpp_maybe, color: Colors.red, size: 20),
              SizedBox(width: 8),
              Text(
                'Possible traffic interception',
                style: TextStyle(
                  color: Colors.red,
                  fontSize: 15,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text('Connection: $connection'),
          Text('When: $whenLabel'),
          const SizedBox(height: 8),
          const Text(
            'The connection presented a server certificate that does not '
            'match the identity this device paired with. Bonded refused '
            'to use it.',
          ),
          const SizedBox(height: 8),
          Text(
            warning.detail,
            style: TextStyle(fontSize: 12, color: Colors.grey[800]),
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
