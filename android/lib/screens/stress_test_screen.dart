import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class StressTestScreen extends StatefulWidget {
  const StressTestScreen({super.key});

  @override
  State<StressTestScreen> createState() => _StressTestScreenState();
}

class _StressTestScreenState extends State<StressTestScreen> {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  final TextEditingController _dnsHostController = TextEditingController(
    text: 'cloudflare.com',
  );
  final TextEditingController _dnsResolverController = TextEditingController(
    text: '1.1.1.1',
  );
  final TextEditingController _httpUrlController = TextEditingController(
    text: 'http://httpforever.com/',
  );
  final TextEditingController _httpsUrlController = TextEditingController(
    text: 'https://example.com/',
  );
  final TextEditingController _http3UrlController = TextEditingController(
    text: 'https://cloudflare-quic.com/',
  );
  final TextEditingController _roundsController = TextEditingController(
    text: '5',
  );
  final TextEditingController _udpHostController = TextEditingController(
    text: 'charter.codingwell.net',
  );
  final TextEditingController _udpPortController = TextEditingController(
    text: '443',
  );

  String _lastResult = 'No stress runs started.';
  bool _running = false;
  bool _autoRefreshLogs = true;
  bool _loadingLogs = false;
  List<String> _logs = const [];
  Timer? _logRefreshTimer;

  @override
  void initState() {
    super.initState();
    _refreshLogs();
    _setAutoRefresh(true);
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

  Future<void> _runStressTest() async {
    final rounds = int.tryParse(_roundsController.text.trim()) ?? 5;
    setState(() {
      _running = true;
      _lastResult = 'Starting simultaneous protocol stress test...';
    });

    try {
      await _channel.invokeMethod<String>('runNetworkTest', {
        'action': 'com.bonded.bonded_app.TEST_PROTOCOL_STRESS',
        'host': _dnsHostController.text.trim(),
        'resolver': _dnsResolverController.text.trim(),
        'http_url': _httpUrlController.text.trim(),
        'https_url': _httpsUrlController.text.trim(),
        'http3_url': _http3UrlController.text.trim(),
        'rounds': rounds,
      });
      await Future<void>.delayed(const Duration(milliseconds: 350));
      await _refreshLogs();
      if (!mounted) return;
      setState(() {
        _lastResult =
            'Started $rounds simultaneous stress rounds at ${DateTime.now().toIso8601String()}';
      });
    } on PlatformException catch (e) {
      if (!mounted) return;
      setState(() {
        _lastResult =
            'Failed to start stress test: ${e.code} ${e.message ?? ''}';
      });
    } finally {
      if (mounted) {
        setState(() {
          _running = false;
        });
      }
    }
  }

  Future<void> _runUdpProbe() async {
    final port = int.tryParse(_udpPortController.text.trim()) ?? 443;
    setState(() {
      _running = true;
      _lastResult = 'Starting UDP probe...';
    });

    try {
      await _channel.invokeMethod<String>('runNetworkTest', {
        'action': 'com.bonded.bonded_app.TEST_UDP_PROBE',
        'host': _udpHostController.text.trim(),
        'port': port,
      });
      await Future<void>.delayed(const Duration(milliseconds: 350));
      await _refreshLogs();
      if (!mounted) return;
      setState(() {
        _lastResult =
            'Started UDP probe of ${_udpHostController.text.trim()}:$port at ${DateTime.now().toIso8601String()} — verdict lands in the logs below';
      });
    } on PlatformException catch (e) {
      if (!mounted) return;
      setState(() {
        _lastResult = 'Failed to start UDP probe: ${e.code} ${e.message ?? ''}';
      });
    } finally {
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
    _dnsResolverController.dispose();
    _httpUrlController.dispose();
    _httpsUrlController.dispose();
    _http3UrlController.dispose();
    _roundsController.dispose();
    _udpHostController.dispose();
    _udpPortController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Protocol Stress Test')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(
            'Run simultaneous EDNS over UDP, cleartext HTTP, HTTPS, and QUIC/HTTP3 probes from Android.',
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Text(_lastResult),
            ),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _dnsHostController,
            decoration: const InputDecoration(
              labelText: 'EDNS hostname',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _dnsResolverController,
            decoration: const InputDecoration(
              labelText: 'UDP resolver IP',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _httpUrlController,
            decoration: const InputDecoration(
              labelText: 'HTTP URL',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _httpsUrlController,
            decoration: const InputDecoration(
              labelText: 'HTTPS URL',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _http3UrlController,
            decoration: const InputDecoration(
              labelText: 'HTTP/3 URL',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _roundsController,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(
              labelText: 'Rounds',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 12),
          FilledButton.icon(
            onPressed: _running ? null : _runStressTest,
            icon: const Icon(Icons.bolt),
            label: const Text('Run Simultaneous Stress Test'),
          ),
          const SizedBox(height: 24),
          const Divider(),
          Text(
            'UDP Probe',
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 4),
          Text(
            'UDP only: sends a QUIC version-negotiation packet to the host/port below and reports what (if anything) answers. Compare a known-good QUIC host (e.g. www.google.com, port 443) with the server to find where UDP dies.',
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 12),
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                flex: 2,
                child: TextField(
                  controller: _udpHostController,
                  decoration: const InputDecoration(
                    labelText: 'UDP host',
                    border: OutlineInputBorder(),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  controller: _udpPortController,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(
                    labelText: 'UDP port',
                    border: OutlineInputBorder(),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          FilledButton.icon(
            onPressed: _running ? null : _runUdpProbe,
            icon: const Icon(Icons.radar),
            label: const Text('Run UDP Probe'),
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
            height: 320,
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: Colors.black,
              borderRadius: BorderRadius.circular(8),
            ),
            child: _logs.isEmpty
                ? const Center(
                    child: Text(
                      'No logs yet. Run the stress test.',
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
