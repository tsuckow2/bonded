import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/pairing_model.dart';
import '../models/session_status.dart';
import '../services/app_settings_service.dart';
import '../services/background_service.dart';
import '../services/pairing_service.dart';
import '../widgets/app_update_checker.dart';
import '../widgets/session_charts.dart';

/// The connect-first main screen (redesign, build 183): a server dropdown
/// and one big connect button up top, live per-path stats and rolling
/// graphs while connected. Everything else lives behind the app-bar menu:
/// Diagnostics (stress test, network tests, logs), Details (the old
/// dashboard's read-only session view), and Settings.
class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  static const _channel = MethodChannel('bonded/native');
  static const _addServerValue = '__add_server__';
  static bool _autoConnectAttempted = false;

  List<PairedServer> _servers = [];
  bool _serversLoaded = false;
  AppSettings _settings = const AppSettings();
  String? _selectedId;

  bool _vpnRunning = false;
  bool _toggling = false;
  SessionStatus _status = SessionStatus.empty;
  int _dismissedInterceptionAtMs = 0;
  Timer? _pollTimer;
  StreamSubscription<BackgroundServiceEvent>? _eventsSubscription;

  // Graph state, sampled once per poll while connected.
  final List<RateSample> _rateSamples = [];
  final List<double> _rttSamples = [];
  int _sampledConnectedAtMs = 0;
  int? _lastInBytes;
  int? _lastOutBytes;
  DateTime? _lastSampleAt;

  @override
  void initState() {
    super.initState();
    _init();
    _eventsSubscription = BackgroundService.backgroundEvents.listen((event) {
      if (event.type == 'session_status' ||
          event.type == 'started' ||
          event.type == 'stopped' ||
          event.type == 'error') {
        _refreshStatus();
      }
    }, onError: (_) {});
    _pollTimer = Timer.periodic(
      const Duration(seconds: 1),
      (_) => _refreshStatus(),
    );
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _eventsSubscription?.cancel();
    super.dispose();
  }

  Future<void> _init() async {
    final settings = await AppSettingsService.load();
    await _loadServers();
    if (!mounted) return;
    setState(() => _settings = settings);
    await _refreshStatus();
    _maybeAutoConnect();
  }

  Future<void> _loadServers() async {
    try {
      final raw = await PairingService.getPairedServers();
      final servers = raw.map(PairedServer.fromJson).toList();
      if (!mounted) return;
      setState(() {
        _servers = servers;
        _serversLoaded = true;
        if (_selectedId == null ||
            !servers.any((s) => s.id == _selectedId)) {
          final stored = _settings.selectedServerId;
          _selectedId = servers.any((s) => s.id == stored)
              ? stored
              : (servers.isNotEmpty ? servers.first.id : null);
        }
      });
    } catch (_) {
      if (mounted) setState(() => _serversLoaded = true);
    }
  }

  Future<void> _refreshStatus() async {
    try {
      final running =
          await _channel.invokeMethod<bool>('getVpnStatus') ?? false;
      final raw = await _channel.invokeMethod<Map<dynamic, dynamic>>(
        'getVpnSessionStatus',
      );
      final status = SessionStatus.fromMap(raw);
      if (!mounted) return;
      setState(() {
        _vpnRunning = running;
        _status = status;
      });
      _sampleGraphs(status, running);
    } catch (_) {}
  }

  void _sampleGraphs(SessionStatus status, bool running) {
    if (!running || !status.isConnected) {
      _lastInBytes = null;
      _lastOutBytes = null;
      _lastSampleAt = null;
      return;
    }
    if (status.connectedAtMs != _sampledConnectedAtMs) {
      _sampledConnectedAtMs = status.connectedAtMs;
      _rateSamples.clear();
      _rttSamples.clear();
      _lastInBytes = null;
      _lastOutBytes = null;
      _lastSampleAt = null;
    }
    final now = DateTime.now();
    if (_lastInBytes != null && _lastSampleAt != null) {
      final dt = now.difference(_lastSampleAt!).inMilliseconds / 1000.0;
      if (dt > 0) {
        final down = (status.inboundBytes - _lastInBytes!) / dt;
        final up = (status.outboundBytes - _lastOutBytes!) / dt;
        _rateSamples.add(
          RateSample(down < 0 ? 0 : down, up < 0 ? 0 : up),
        );
        if (_rateSamples.length > 180) _rateSamples.removeAt(0);
        final rtt = status.activePath?.lastRttMs ?? 0;
        _rttSamples.add(rtt.toDouble());
        if (_rttSamples.length > 180) _rttSamples.removeAt(0);
      }
    }
    _lastInBytes = status.inboundBytes;
    _lastOutBytes = status.outboundBytes;
    _lastSampleAt = now;
  }

  void _maybeAutoConnect() {
    if (_autoConnectAttempted) return;
    _autoConnectAttempted = true;
    if (!_settings.autoConnectOnOpen) return;
    if (_vpnRunning || _selectedId == null) return;
    _toggleVpn();
  }

  PairedServer? get _selected {
    for (final server in _servers) {
      if (server.id == _selectedId) return server;
    }
    return null;
  }

  /// The server the live session belongs to, when one is running: the
  /// dropdown shows (and locks to) it regardless of the stored selection.
  PairedServer? get _displayedServer {
    if (_vpnRunning && _status.serverAddress.isNotEmpty) {
      for (final server in _servers) {
        if (server.publicAddress == _status.serverAddress) return server;
      }
    }
    return _selected;
  }

  bool get _isConnecting => _status.isConnecting || _toggling;

  bool get _showInterceptionWarning =>
      _status.interception != null &&
      _status.interception!.atMs != _dismissedInterceptionAtMs;

  Future<void> _onDropdownChanged(String? value) async {
    if (value == null) return;
    if (value == _addServerValue) {
      final result = await Navigator.of(context).pushNamed('/qr-scanner');
      if (result != null && mounted) {
        await _loadServers();
      }
      return;
    }
    setState(() => _selectedId = value);
    _settings = _settings.copyWith(selectedServerId: value);
    await AppSettingsService.update(_settings);
  }

  Future<void> _toggleVpn() async {
    if (_toggling) return;
    setState(() => _toggling = true);
    try {
      if (_vpnRunning) {
        await BackgroundService.stopBackgroundService();
      } else {
        final target = _selectedId;
        if (target == null) return;
        await BackgroundService.startBackgroundService(deviceId: target);
      }
      await _refreshStatus();
    } on BackgroundServiceException catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(e.message), backgroundColor: Colors.red),
        );
      }
    } finally {
      if (mounted) setState(() => _toggling = false);
    }
  }

  Future<void> _openServerConfig() async {
    final server = _selected;
    if (server == null) return;
    final result = await Navigator.of(
      context,
    ).pushNamed('/server-config', arguments: server);
    if (result == true && mounted) {
      await _loadServers();
      await _refreshStatus();
    }
  }

  String get _statusText {
    if (_status.isError) return 'Error';
    if (_isConnecting) return 'Connecting…';
    if (_vpnRunning || _status.isConnected) return 'Connected';
    return 'Disconnected';
  }

  Color get _statusColor {
    if (_status.isError) return Colors.red;
    if (_isConnecting) return Colors.orange;
    if (_vpnRunning || _status.isConnected) return Colors.green;
    return Colors.grey;
  }

  @override
  Widget build(BuildContext context) {
    final connected = _vpnRunning || _status.isConnected;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Bonded VPN'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        actions: [
          if (connected)
            Padding(
              padding: const EdgeInsets.only(right: 4),
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
          PopupMenuButton<String>(
            onSelected: (value) {
              switch (value) {
                case 'diagnostics':
                  Navigator.of(context).pushNamed('/diagnostics');
                case 'details':
                  final id = _displayedServer?.id ?? _selectedId;
                  if (id != null) {
                    Navigator.of(
                      context,
                    ).pushNamed('/details', arguments: {'deviceId': id});
                  }
                case 'settings':
                  Navigator.of(context).pushNamed('/settings').then((_) {
                    AppSettingsService.load().then((settings) {
                      if (mounted) setState(() => _settings = settings);
                    });
                  });
                case 'refresh':
                  _loadServers();
                  _refreshStatus();
              }
            },
            itemBuilder: (context) => const [
              PopupMenuItem(
                value: 'diagnostics',
                child: ListTile(
                  leading: Icon(Icons.science),
                  title: Text('Diagnostics'),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
              PopupMenuItem(
                value: 'details',
                child: ListTile(
                  leading: Icon(Icons.insights),
                  title: Text('Session details'),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
              PopupMenuItem(
                value: 'settings',
                child: ListTile(
                  leading: Icon(Icons.settings),
                  title: Text('Settings'),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
              PopupMenuItem(
                value: 'refresh',
                child: ListTile(
                  leading: Icon(Icons.refresh),
                  title: Text('Refresh'),
                  contentPadding: EdgeInsets.zero,
                ),
              ),
            ],
          ),
        ],
      ),
      body: Column(
        children: [
          const AppUpdateChecker(),
          Expanded(
            child: !_serversLoaded
                ? const Center(child: CircularProgressIndicator())
                : _servers.isEmpty
                ? _buildEmptyState()
                : _buildMain(),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.security, size: 64, color: Colors.grey),
            const SizedBox(height: 16),
            const Text(
              'No paired servers',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.w500),
            ),
            const SizedBox(height: 8),
            Text(
              'Scan a server QR code to get started',
              style: TextStyle(fontSize: 14, color: Colors.grey[600]),
            ),
            const SizedBox(height: 32),
            ElevatedButton.icon(
              onPressed: () async {
                final result = await Navigator.of(
                  context,
                ).pushNamed('/qr-scanner');
                if (result != null && mounted) _loadServers();
              },
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
      ),
    );
  }

  Widget _buildMain() {
    final locked = _vpnRunning || _isConnecting;
    final displayed = _displayedServer;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // ── Server picker + status ──────────────────────────────
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(Icons.circle, size: 12, color: _statusColor),
                      const SizedBox(width: 8),
                      Text(
                        _statusText,
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.w600,
                          color: _statusColor,
                        ),
                      ),
                      const Spacer(),
                      if (_vpnRunning && _status.connectedAtMs > 0)
                        Text(
                          _uptimeText(),
                          style: TextStyle(color: Colors.grey[600]),
                        ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Expanded(
                        child: DropdownButton<String>(
                          isExpanded: true,
                          value: displayed?.id,
                          items: [
                            for (final server in _servers)
                              DropdownMenuItem(
                                value: server.id,
                                child: Text(
                                  server.publicAddress,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                            if (!locked)
                              const DropdownMenuItem(
                                value: _addServerValue,
                                child: Row(
                                  children: [
                                    Icon(Icons.add, size: 18),
                                    SizedBox(width: 6),
                                    Text('Add server…'),
                                  ],
                                ),
                              ),
                          ],
                          onChanged: locked ? null : _onDropdownChanged,
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.tune),
                        tooltip: 'Configure server',
                        onPressed: locked ? null : _openServerConfig,
                      ),
                    ],
                  ),
                  if (locked)
                    Text(
                      'Disconnect to switch servers',
                      style: TextStyle(fontSize: 12, color: Colors.grey[600]),
                    ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          // ── The one big button ──────────────────────────────────
          FilledButton.icon(
            onPressed: _toggling ? null : _toggleVpn,
            style: FilledButton.styleFrom(
              backgroundColor: _vpnRunning ? Colors.red : Colors.green,
              padding: const EdgeInsets.symmetric(vertical: 18),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(32),
              ),
            ),
            icon: _isConnecting
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: Colors.white,
                    ),
                  )
                : Icon(
                    _vpnRunning ? Icons.stop_circle : Icons.play_circle,
                    size: 22,
                  ),
            label: Text(
              _vpnRunning ? 'Disconnect' : 'Connect',
              style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w600),
            ),
          ),
          if (_showInterceptionWarning) ...[
            const SizedBox(height: 12),
            _InterceptionWarningCard(
              status: _status,
              onDismiss: () => setState(
                () =>
                    _dismissedInterceptionAtMs = _status.interception!.atMs,
              ),
              onViewDetails: () {
                final id = _displayedServer?.id ?? _selectedId;
                if (id != null) {
                  Navigator.of(
                    context,
                  ).pushNamed('/details', arguments: {'deviceId': id});
                }
              },
            ),
          ] else if (_status.lastError != null) ...[
            const SizedBox(height: 12),
            _ErrorBanner(message: _status.lastError!),
          ],
          if (_vpnRunning || _status.isConnected) ...[
            const SizedBox(height: 20),
            _buildTotalsRow(),
            const SizedBox(height: 16),
            _buildPathsCard(),
            const SizedBox(height: 16),
            _buildGraphsCard(),
          ],
        ],
      ),
    );
  }

  String _uptimeText() {
    final elapsed =
        DateTime.now().millisecondsSinceEpoch - _status.connectedAtMs;
    if (elapsed <= 0) return '';
    final d = Duration(milliseconds: elapsed);
    final h = d.inHours;
    final m = d.inMinutes.remainder(60);
    final s = d.inSeconds.remainder(60);
    if (h > 0) return '${h}h ${m}m';
    if (m > 0) return '${m}m ${s}s';
    return '${s}s';
  }

  Widget _buildTotalsRow() {
    return Row(
      children: [
        Expanded(
          child: _StatTile(
            icon: Icons.arrow_downward,
            label: 'Received',
            value: _fmtBytes(_status.inboundBytes),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: _StatTile(
            icon: Icons.arrow_upward,
            label: 'Sent',
            value: _fmtBytes(_status.outboundBytes),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: _StatTile(
            icon: Icons.alt_route,
            label: 'Paths',
            value: '${_status.directPaths.length}',
          ),
        ),
      ],
    );
  }

  Widget _buildPathsCard() {
    final paths = _status.directPaths;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Paths',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 8),
            if (paths.isEmpty)
              Text(
                'No direct paths',
                style: TextStyle(color: Colors.grey[600]),
              ),
            for (final path in paths) _PathRow(status: _status, path: path),
          ],
        ),
      ),
    );
  }

  Widget _buildGraphsCard() {
    final currentDown = _rateSamples.isNotEmpty
        ? _rateSamples.last.downBps
        : 0.0;
    final currentUp = _rateSamples.isNotEmpty ? _rateSamples.last.upBps : 0.0;
    final activeRtt = _status.activePath?.lastRttMs ?? 0;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Text(
                  'Throughput',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
                ),
                const Spacer(),
                Text(
                  '↓ ${_fmtRate(currentDown)}  ↑ ${_fmtRate(currentUp)}',
                  style: TextStyle(color: Colors.grey[700], fontSize: 13),
                ),
              ],
            ),
            const SizedBox(height: 8),
            ThroughputChart(samples: _rateSamples),
            const SizedBox(height: 16),
            Row(
              children: [
                const Text(
                  'Latency (active path)',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
                ),
                const Spacer(),
                Text(
                  activeRtt > 0 ? '$activeRtt ms' : '—',
                  style: TextStyle(color: Colors.grey[700], fontSize: 13),
                ),
              ],
            ),
            const SizedBox(height: 8),
            RttChart(samplesMs: _rttSamples),
          ],
        ),
      ),
    );
  }

  static String _fmtBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  static String _fmtRate(double bps) {
    if (bps < 1024) return '${bps.toStringAsFixed(0)} B/s';
    if (bps < 1024 * 1024) return '${(bps / 1024).toStringAsFixed(1)} KB/s';
    return '${(bps / (1024 * 1024)).toStringAsFixed(2)} MB/s';
  }
}

class _StatTile extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;
  const _StatTile({
    required this.icon,
    required this.label,
    required this.value,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 8),
        child: Column(
          children: [
            Icon(icon, size: 18, color: Colors.teal),
            const SizedBox(height: 4),
            Text(
              value,
              style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
            ),
            Text(
              label,
              style: TextStyle(fontSize: 12, color: Colors.grey[600]),
            ),
          ],
        ),
      ),
    );
  }
}

class _PathRow extends StatelessWidget {
  static const _channel = MethodChannel('bonded/native');
  final SessionStatus status;
  final PathStat path;
  const _PathRow({required this.status, required this.path});

  @override
  Widget build(BuildContext context) {
    final summary = status.summaryFor(path.pathIndex);
    String networkLabel = 'Path ${path.pathIndex}';
    String? bindAddress;
    if (summary != null) {
      final split = summary.indexOf(':');
      if (split > 0) {
        final kind = summary.substring(0, split);
        networkLabel = switch (kind.toLowerCase()) {
          'wifi' => 'Wi-Fi',
          'cellular' => 'Cellular',
          'ethernet' => 'Ethernet',
          _ => kind,
        };
        bindAddress = summary.substring(split + 1);
      }
    }
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: InkWell(
        // Long-press is the path debug menu (pause/resume, reset).
        // Relay transports have no supervisor path index, so they
        // get no menu.
        onLongPress: path.isDirect
            ? () => _showPathMenu(context, networkLabel)
            : null,
        child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Icon(
            networkLabel == 'Wi-Fi'
                ? Icons.wifi
                : networkLabel == 'Cellular'
                ? Icons.signal_cellular_alt
                : Icons.alt_route,
            size: 20,
            color: path.active ? Colors.teal : Colors.grey,
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  networkLabel,
                  style: const TextStyle(fontWeight: FontWeight.w600),
                ),
                Text(
                  [
                    ?bindAddress,
                    path.kind,
                    if (path.lastRttMs > 0) '${path.lastRttMs} ms',
                    '↓ ${_bytes(path.inboundBytes)} · ↑ ${_bytes(path.outboundBytes)}',
                  ].join(' · '),
                  style: TextStyle(fontSize: 12, color: Colors.grey[700]),
                ),
                if (path.publicIp != null)
                  Text(
                    'Public IP ${path.publicIp}',
                    style: TextStyle(fontSize: 12, color: Colors.grey[700]),
                  ),
              ],
            ),
          ),
          if (path.active)
            const Chip(
              label: Text('Active', style: TextStyle(fontSize: 11)),
              visualDensity: VisualDensity.compact,
              padding: EdgeInsets.zero,
            ),
          if (path.paused)
            const Chip(
              label: Text('Paused', style: TextStyle(fontSize: 11)),
              visualDensity: VisualDensity.compact,
              padding: EdgeInsets.zero,
            ),
        ],
        ),
      ),
    );
  }

  /// Debug menu for one path: pause/resume (stays connected, treated
  /// as a bad connection) or reset (tear down and re-dial just this
  /// path). Reached by long-pressing the path row.
  Future<void> _showPathMenu(BuildContext context, String networkLabel) async {
    final pathIndex = path.pathIndex;
    if (pathIndex == null) return;
    final action = await showModalBottomSheet<String>(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              title: Text('$networkLabel (path $pathIndex)'),
              subtitle: const Text('Debug path controls'),
            ),
            ListTile(
              leading: Icon(path.paused ? Icons.play_arrow : Icons.pause),
              title: Text(path.paused ? 'Resume path' : 'Pause path'),
              subtitle: Text(
                path.paused
                    ? 'Return the path to normal flow assignment'
                    : 'Stay connected, but treat as a bad connection',
              ),
              onTap: () => Navigator.pop(context, 'pause'),
            ),
            ListTile(
              leading: const Icon(Icons.refresh),
              title: const Text('Reset path'),
              subtitle: const Text('Tear down and re-dial this path only'),
              onTap: () => Navigator.pop(context, 'reset'),
            ),
          ],
        ),
      ),
    );
    if (action == null || !context.mounted) return;
    final bool ok;
    switch (action) {
      case 'pause':
        ok = await _channel.invokeMethod<bool>('pausePath', {
              'pathIndex': pathIndex,
              'paused': !path.paused,
            }) ??
            false;
      case 'reset':
        ok = await _channel.invokeMethod<bool>('resetPath', {
              'pathIndex': pathIndex,
            }) ??
            false;
      default:
        return;
    }
    if (!ok && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Path action failed (no session running?)'),
        ),
      );
    }
  }

  static String _bytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB';
  }
}

/// Dedicated warning for a server-identity failure: one of the device's
/// connections presented a certificate that does not match the paired
/// server — the signature of an intercepting network. Shown instead of
/// the generic error banner; the raw detail lives on the Details page.
class _InterceptionWarningCard extends StatelessWidget {
  final SessionStatus status;
  final VoidCallback onDismiss;
  final VoidCallback onViewDetails;
  const _InterceptionWarningCard({
    required this.status,
    required this.onDismiss,
    required this.onViewDetails,
  });

  @override
  Widget build(BuildContext context) {
    final warning = status.interception!;
    final String body;
    if (warning.pathIndex != null) {
      final (label, address) = status.describePath(warning.pathIndex);
      body =
          'Your $label connection${address != null ? ' ($address)' : ''} '
          'presented a server certificate that does not match the one '
          'this device paired with, so Bonded refused to use it. This is '
          'what an intercepting ("man in the middle") network looks '
          'like — the connection may be monitored.';
    } else {
      body =
          'While verifying the server\'s identity, a connection '
          'presented a certificate that does not match the one this '
          'device paired with, so Bonded refused to continue. This is '
          'what an intercepting ("man in the middle") network looks '
          'like — the connection may be monitored.';
    }
    final when = DateTime.fromMillisecondsSinceEpoch(warning.atMs);
    final timeLabel =
        '${when.hour}:${when.minute.toString().padLeft(2, '0')}';
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
          const SizedBox(height: 8),
          Text(body, style: const TextStyle(fontSize: 13.5, height: 1.35)),
          const SizedBox(height: 4),
          Text(
            'Detected at $timeLabel',
            style: TextStyle(fontSize: 12, color: Colors.grey[700]),
          ),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              TextButton(
                onPressed: onViewDetails,
                child: const Text('View details'),
              ),
              TextButton(
                onPressed: onDismiss,
                child: const Text('Dismiss'),
              ),
            ],
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
