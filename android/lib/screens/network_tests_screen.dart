import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/session_status.dart';
import '../models/transport_overhead.dart';
import '../services/pairing_service.dart';
import '../widgets/transport_overhead_card.dart';

class NetworkTestsScreen extends StatefulWidget {
  const NetworkTestsScreen({super.key});

  @override
  State<NetworkTestsScreen> createState() => _NetworkTestsScreenState();
}

class _NetworkTestsScreenState extends State<NetworkTestsScreen> {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  final TextEditingController _dnsHostController = TextEditingController(
    text: 'unifi.g.codingwell.net',
  );
  final TextEditingController _dnsExpectedIpController = TextEditingController(
    text: '34.82.88.79',
  );
  final TextEditingController _tcpHostController = TextEditingController(
    text: 'example.com',
  );
  final TextEditingController _tcpPortController = TextEditingController(
    text: '443',
  );
  final TextEditingController _httpUrlController = TextEditingController(
    text: 'https://example.com',
  );

  String _lastResult = 'No tests run yet.';
  bool _running = false;
  bool _autoRefreshLogs = true;
  bool _loadingLogs = false;
  bool _loadingPairedServer = false;
  List<String> _logs = const [];
  Map<String, dynamic>? _firstPairedServer;
  Timer? _logRefreshTimer;

  // Transport overhead diagnostic (slice 5).
  int _payloadSizeBytes = 1024 * 1024;
  bool _measuringOverhead = false;
  String? _overheadNote;
  List<TransportOverheadResult> _overheadResults = const [];

  @override
  void initState() {
    super.initState();
    _loadFirstPairedServer();
    _refreshLogs();
    _setAutoRefresh(true);
  }

  Future<void> _loadFirstPairedServer() async {
    setState(() {
      _loadingPairedServer = true;
    });
    try {
      final pairedServers = await PairingService.getPairedServers();
      if (!mounted) return;
      setState(() {
        _firstPairedServer = pairedServers.isEmpty ? null : pairedServers.first;
      });
    } on PairingException catch (e) {
      if (!mounted) return;
      setState(() {
        _lastResult = e.message;
      });
    } finally {
      if (mounted) {
        setState(() {
          _loadingPairedServer = false;
        });
      }
    }
  }

  ({String host, int port})? _parseAddress(String rawAddress) {
    final trimmed = rawAddress.trim();
    if (trimmed.isEmpty) {
      return null;
    }

    final uri = Uri.tryParse('https://$trimmed');
    if (uri == null || uri.host.isEmpty) {
      return null;
    }

    return (host: uri.host, port: uri.hasPort ? uri.port : 443);
  }

  void _applyFirstPairedServer() {
    final server = _firstPairedServer;
    if (server == null) {
      setState(() {
        _lastResult = 'No paired server available to populate connection checks.';
      });
      return;
    }

    final parsed = _parseAddress((server['publicAddress'] ?? '').toString());
    if (parsed == null) {
      setState(() {
        _lastResult = 'Could not parse paired server address.';
      });
      return;
    }

    _tcpHostController.text = parsed.host;
    _tcpPortController.text = parsed.port.toString();
    _httpUrlController.text = 'https://${server['publicAddress']}/';
    _dnsHostController.text = parsed.host;
    _dnsExpectedIpController.clear();

    setState(() {
      _lastResult =
          'Loaded paired server ${server['publicAddress']} (${_protocolSummary(server)}).';
    });
  }

  String _protocolSummary(Map<String, dynamic> server) {
    final protocols = (server['supportedProtocols'] as List?)
        ?.map((value) => value.toString())
        .where((value) => value.isNotEmpty)
        .toList();

    if (protocols == null || protocols.isEmpty) {
      return 'protocols unknown';
    }

    return protocols.join(', ');
  }

  Future<void> _sendTestAction(
    String action, {
    Map<String, dynamic>? extras,
  }) async {
    final payload = <String, dynamic>{'action': action, ...?extras};
    await _channel.invokeMethod<String>('runNetworkTest', payload);
    await Future<void>.delayed(const Duration(milliseconds: 350));
  }

  Future<void> _runPairedServerChecks() async {
    final server = _firstPairedServer;
    if (server == null) {
      setState(() {
        _lastResult = 'No paired server available for connection checks.';
      });
      return;
    }

    final publicAddress = (server['publicAddress'] ?? '').toString();
    final parsed = _parseAddress(publicAddress);
    if (parsed == null) {
      setState(() {
        _lastResult = 'Could not parse paired server address for connection checks.';
      });
      return;
    }

    setState(() {
      _running = true;
      _lastResult = 'Running paired server checks for $publicAddress...';
    });

    try {
      _applyFirstPairedServer();

      var checksQueued = 0;
      await _sendTestAction('com.bonded.bonded_app.TEST_VPN_STATUS');
      checksQueued += 1;

      if (InternetAddress.tryParse(parsed.host) == null) {
        await _sendTestAction(
          'com.bonded.bonded_app.TEST_DNS',
          extras: {'host': parsed.host, 'expected_ip': ''},
        );
        checksQueued += 1;
      }

      await _sendTestAction(
        'com.bonded.bonded_app.TEST_TCP',
        extras: {'host': parsed.host, 'port': parsed.port},
      );
      checksQueued += 1;

      await _refreshLogs();
      if (!mounted) return;
      setState(() {
        _lastResult =
            'Queued $checksQueued paired-server checks for $publicAddress.';
      });
    } on PlatformException catch (e) {
      if (!mounted) return;
      setState(() {
        _lastResult =
            'Failed paired server checks: ${e.code} ${e.message ?? ''}';
      });
    } finally {
      if (mounted) {
        setState(() {
          _running = false;
        });
      }
    }
  }

  Future<SessionStatus> _fetchSessionStatus() async {
    final raw = await _channel.invokeMethod<Map<dynamic, dynamic>>(
      'getVpnSessionStatus',
    );
    return SessionStatus.fromMap(raw);
  }

  /// Live-window overhead measurement: snapshots the session counters,
  /// waits 10 s of real traffic, snapshots again, and reports per-path
  /// inside (TUN) vs wire (socket) bytes. This is real traffic, not a
  /// fixed payload — the payload is unknown, so inside bytes stand in
  /// for it (the result cards say so). Paths are matched by position
  /// in the transport list; a path whose kind changed mid-window is
  /// skipped rather than misattributed.
  Future<void> _measureLiveOverhead() async {
    setState(() {
      _measuringOverhead = true;
      _overheadNote = 'Measuring live traffic for 10 s…';
      _overheadResults = const [];
    });
    try {
      final before = await _fetchSessionStatus();
      if (!before.isConnected) {
        if (!mounted) return;
        setState(() {
          _overheadNote = 'VPN is not connected; start the VPN first.';
        });
        return;
      }
      await Future<void>.delayed(const Duration(seconds: 10));
      if (!mounted) return;
      final after = await _fetchSessionStatus();
      final results = <TransportOverheadResult>[];
      final skipped = <String>[];
      for (var i = 0; i < before.paths.length; i++) {
        final beforePath = before.paths[i];
        if (i >= after.paths.length ||
            after.paths[i].kind != beforePath.kind) {
          skipped.add(beforePath.kind);
          continue;
        }
        final result = TransportOverheadResult.fromSnapshots(
          transportLabel: beforePath.kind,
          before: beforePath,
          after: after.paths[i],
          elapsed: const Duration(seconds: 10),
          isLiveWindow: true,
        );
        if (result != null) results.add(result);
      }
      if (!mounted) return;
      setState(() {
        _overheadResults = results;
        _overheadNote = results.isEmpty
            ? 'No paths survived the window.'
            : skipped.isEmpty
                ? 'Live traffic over 10 s. Payload is unknown for live '
                      'traffic, so inside bytes stand in for it.'
                : 'Skipped ${skipped.join(', ')} (transport changed '
                      'during the window).';
      });
    } on PlatformException catch (e) {
      if (!mounted) return;
      setState(() {
        _overheadNote =
            'Failed to read session status: ${e.code} ${e.message ?? ''}';
      });
    } finally {
      if (mounted) {
        setState(() {
          _measuringOverhead = false;
        });
      }
    }
  }

  void _setAutoRefresh(bool enabled) {
    _logRefreshTimer?.cancel();
    if (!enabled) {
      return;
    }
    _logRefreshTimer = Timer.periodic(const Duration(seconds: 2), (_) {
      _refreshLogs();
    });
  }

  Future<void> _refreshLogs() async {
    if (_loadingLogs) return;
    setState(() {
      _loadingLogs = true;
    });
    try {
      final logs = await _channel.invokeMethod<List<dynamic>>(
        'getNetworkTestLogs',
      );
      if (!mounted) return;
      setState(() {
        _logs = (logs ?? const []).map((e) => e.toString()).toList();
      });
    } on PlatformException {
      if (!mounted) return;
      setState(() {
        _logs = const ['Failed to load logs from native layer.'];
      });
    } finally {
      if (mounted) {
        setState(() {
          _loadingLogs = false;
        });
      }
    }
  }

  Future<void> _clearLogs() async {
    try {
      await _channel.invokeMethod<void>('clearNetworkTestLogs');
      if (!mounted) return;
      setState(() {
        _logs = const [];
      });
    } on PlatformException catch (e) {
      if (!mounted) return;
      setState(() {
        _lastResult = 'Failed to clear logs: ${e.code} ${e.message ?? ''}';
      });
    }
  }

  Future<void> _runTest(String action, {Map<String, dynamic>? extras}) async {
    setState(() {
      _running = true;
      _lastResult = 'Running $action...';
    });

    try {
      await _sendTestAction(action, extras: extras);
      await _refreshLogs();
      if (!mounted) return;
      setState(() {
        _lastResult = 'Sent $action at ${DateTime.now().toIso8601String()}';
      });
    } on PlatformException catch (e) {
      if (!mounted) return;
      setState(() {
        _lastResult = 'Failed to send $action: ${e.code} ${e.message ?? ''}';
      });
    } finally {
      if (mounted) {
        setState(() {
          _running = false;
        });
      }
    }
  }

  Future<void> _runUiCodingwellProbe() async {
    setState(() {
      _running = true;
      _lastResult = 'Running UI probe for https://codingwell.net...';
    });

    final stopwatch = Stopwatch()..start();
    HttpClient? client;
    try {
      client = HttpClient();
      client.connectionTimeout = const Duration(seconds: 10);

      final request = await client.getUrl(Uri.parse('https://codingwell.net'));
      request.followRedirects = true;
      final response = await request.close().timeout(
        const Duration(seconds: 10),
      );

      await response.drain<void>();
      stopwatch.stop();

      if (!mounted) return;
      setState(() {
        _lastResult =
            'UI probe success in ${stopwatch.elapsedMilliseconds}ms: '
            'HTTP ${response.statusCode} (${response.reasonPhrase})';
      });
    } on Exception catch (e) {
      stopwatch.stop();
      if (!mounted) return;
      setState(() {
        _lastResult =
            'UI probe failed in ${stopwatch.elapsedMilliseconds}ms: $e';
      });
    } finally {
      client?.close(force: true);
      if (mounted) {
        setState(() {
          _running = false;
        });
      }
    }
  }

  @override
  void dispose() {
    _logRefreshTimer?.cancel();
    _dnsHostController.dispose();
    _dnsExpectedIpController.dispose();
    _tcpHostController.dispose();
    _tcpPortController.dispose();
    _httpUrlController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Network Tests')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(
            'Run Android network diagnostics from inside the app.',
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 12),
          Align(
            alignment: Alignment.centerLeft,
            child: OutlinedButton.icon(
              onPressed: () {
                Navigator.of(context).pushNamed('/stress-tests');
              },
              icon: const Icon(Icons.bolt),
              label: const Text('Open Stress Test Page'),
            ),
          ),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Text(_lastResult),
            ),
          ),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Paired Server Checks',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  if (_loadingPairedServer)
                    const Text('Loading paired server details...')
                  else if (_firstPairedServer == null)
                    const Text(
                      'No paired server found. Pair a server first, then use these checks to probe the real Bonded endpoint.',
                    )
                  else ...[
                    Text(
                      'Server: ${_firstPairedServer!['publicAddress']}',
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Protocols: ${_protocolSummary(_firstPairedServer!)}',
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'This checklist runs VPN status, optional DNS, and TCP reachability against the first paired server. It intentionally avoids HTTPS bootstrap validation because local self-signed certs fail normal platform trust checks.',
                    ),
                    const SizedBox(height: 12),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        ElevatedButton.icon(
                          onPressed: _running ? null : _runPairedServerChecks,
                          icon: const Icon(Icons.playlist_add_check),
                          label: const Text('Run Paired Server Checks'),
                        ),
                        OutlinedButton.icon(
                          onPressed: _running ? null : _applyFirstPairedServer,
                          icon: const Icon(Icons.download),
                          label: const Text('Use First Paired Server'),
                        ),
                        OutlinedButton.icon(
                          onPressed: _running ? null : _loadFirstPairedServer,
                          icon: const Icon(Icons.refresh),
                          label: const Text('Reload Paired Server'),
                        ),
                      ],
                    ),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Transport Overhead',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Inside bytes are TUN IP packet bytes; wire bytes are '
                    'bytes actually written to / read from the transport '
                    'socket, including framing/encryption (IP/UDP/TCP '
                    'headers below the socket are excluded). Overhead is '
                    'wire minus inside.',
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      const Text('Fixed payload size: '),
                      DropdownButton<int>(
                        value: _payloadSizeBytes,
                        items: const [
                          DropdownMenuItem(
                            value: 256 * 1024,
                            child: Text('256 KiB'),
                          ),
                          DropdownMenuItem(
                            value: 1024 * 1024,
                            child: Text('1 MiB'),
                          ),
                          DropdownMenuItem(
                            value: 10 * 1024 * 1024,
                            child: Text('10 MiB'),
                          ),
                        ],
                        onChanged: _measuringOverhead
                            ? null
                            : (value) {
                                if (value != null) {
                                  setState(() {
                                    _payloadSizeBytes = value;
                                  });
                                }
                              },
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Wire measurement status per transport:',
                    style: TextStyle(fontWeight: FontWeight.w600),
                  ),
                  const SizedBox(height: 4),
                  ...[
                    'NaiveTCP',
                    'QUIC',
                    'WireGuard',
                    'WebSocketTls',
                  ].map(
                    (kind) => Padding(
                      padding: const EdgeInsets.symmetric(vertical: 2),
                      child: Text('$kind: ${wireMeasurementStatus(kind)}'),
                    ),
                  ),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      ElevatedButton.icon(
                        onPressed: _measuringOverhead || _running
                            ? null
                            : _measureLiveOverhead,
                        icon: const Icon(Icons.speed),
                        label: const Text('Measure live overhead (10 s)'),
                      ),
                      ElevatedButton.icon(
                        onPressed: null,
                        icon: const Icon(Icons.play_arrow),
                        label: const Text('Run fixed-payload TCP test'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'The fixed-payload test is not yet available: it needs '
                    'a TCP echo endpoint on the tunnel gateway (10.8.0.1), '
                    'which is not deployed. The measurement itself is '
                    'proven in Rust tests against a loopback server; use '
                    'the live 10 s window above for real traffic.',
                  ),
                  if (_overheadNote != null) ...[
                    const SizedBox(height: 8),
                    Text(_overheadNote!),
                  ],
                  if (_overheadResults.isNotEmpty) ...[
                    const SizedBox(height: 8),
                    ..._overheadResults.map(
                      (result) => Padding(
                        padding: const EdgeInsets.only(bottom: 8),
                        child: TransportOverheadCard(result: result),
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              ElevatedButton(
                onPressed: _running
                    ? null
                    : () => _runTest('com.bonded.bonded_app.TEST_VPN_PREPARED'),
                child: const Text('VPN Prepared'),
              ),
              ElevatedButton(
                onPressed: _running
                    ? null
                    : () => _runTest('com.bonded.bonded_app.TEST_VPN_STATUS'),
                child: const Text('VPN Status'),
              ),
              ElevatedButton(
                onPressed: _running
                    ? null
                    : () => _runTest('com.bonded.bonded_app.TEST_VPN_CONNECT'),
                child: const Text('VPN Connect'),
              ),
              ElevatedButton(
                onPressed: _running
                    ? null
                    : () =>
                          _runTest('com.bonded.bonded_app.TEST_VPN_DISCONNECT'),
                child: const Text('VPN Disconnect'),
              ),
              ElevatedButton(
                onPressed: _running
                    ? null
                    : () => _runTest(
                        'com.bonded.bonded_app.TEST_HTTP_CODINGWELL',
                      ),
                child: const Text('HTTP Codingwell'),
              ),
              ElevatedButton(
                onPressed: _running ? null : _runUiCodingwellProbe,
                child: const Text('UI Probe Codingwell'),
              ),
              OutlinedButton(
                onPressed: _running
                    ? null
                    : () => _runTest('com.bonded.bonded_app.TEST_ALL'),
                child: const Text('Run TEST_ALL'),
              ),
            ],
          ),
          const SizedBox(height: 20),
          TextField(
            controller: _dnsHostController,
            decoration: const InputDecoration(
              labelText: 'DNS host',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _dnsExpectedIpController,
            decoration: const InputDecoration(
              labelText: 'Expected IP (optional)',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          ElevatedButton(
            onPressed: _running
                ? null
                : () => _runTest(
                    'com.bonded.bonded_app.TEST_DNS',
                    extras: {
                      'host': _dnsHostController.text.trim(),
                      'expected_ip': _dnsExpectedIpController.text.trim(),
                    },
                  ),
            child: const Text('Run DNS Test'),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _tcpHostController,
            decoration: const InputDecoration(
              labelText: 'TCP host',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _tcpPortController,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(
              labelText: 'TCP port',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          ElevatedButton(
            onPressed: _running
                ? null
                : () => _runTest(
                    'com.bonded.bonded_app.TEST_TCP',
                    extras: {
                      'host': _tcpHostController.text.trim(),
                      'port':
                          int.tryParse(_tcpPortController.text.trim()) ?? 443,
                    },
                  ),
            child: const Text('Run TCP Test'),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _httpUrlController,
            decoration: const InputDecoration(
              labelText: 'HTTP/HTTPS URL',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          ElevatedButton(
            onPressed: _running
                ? null
                : () => _runTest(
                    'com.bonded.bonded_app.TEST_HTTP',
                    extras: {'url': _httpUrlController.text.trim()},
                  ),
            child: const Text('Run HTTP Test'),
          ),
          const SizedBox(height: 20),
          Row(
            children: [
              Text(
                'In-app Logs',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const Spacer(),
              const Text('Auto refresh'),
              Switch(
                value: _autoRefreshLogs,
                onChanged: (value) {
                  setState(() {
                    _autoRefreshLogs = value;
                  });
                  _setAutoRefresh(value);
                },
              ),
            ],
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              OutlinedButton.icon(
                onPressed: _loadingLogs ? null : _refreshLogs,
                icon: const Icon(Icons.refresh),
                label: const Text('Refresh Logs'),
              ),
              OutlinedButton.icon(
                onPressed: _logs.isEmpty ? null : _clearLogs,
                icon: const Icon(Icons.clear_all),
                label: const Text('Clear Logs'),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Container(
            height: 260,
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: Colors.black,
              borderRadius: BorderRadius.circular(8),
            ),
            child: _logs.isEmpty
                ? const Center(
                    child: Text(
                      'No logs yet. Run a test.',
                      style: TextStyle(color: Colors.white70),
                    ),
                  )
                : ListView.builder(
                    itemCount: _logs.length,
                    itemBuilder: (context, index) {
                      return SelectableText(
                        _logs[index],
                        style: const TextStyle(
                          color: Colors.white,
                          fontFamily: 'monospace',
                          fontSize: 12,
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}
