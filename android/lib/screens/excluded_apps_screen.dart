import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../services/app_settings_service.dart';

/// Picker for the per-app VPN bypass: checked apps send their traffic
/// outside the VPN, unprotected. Bonded itself is never listed (the native
/// side filters it out) because its control-plane traffic must stay
/// routable through the VPN.
class ExcludedAppsScreen extends StatefulWidget {
  const ExcludedAppsScreen({super.key});

  @override
  State<ExcludedAppsScreen> createState() => _ExcludedAppsScreenState();
}

class _LaunchableApp {
  final String packageName;
  final String label;

  _LaunchableApp({required this.packageName, required this.label});
}

class _ExcludedAppsScreenState extends State<ExcludedAppsScreen> {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  List<_LaunchableApp> _apps = [];
  Set<String> _excluded = {};
  bool _loading = true;
  String? _error;
  String _filter = '';

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final settings = await AppSettingsService.load();
      final raw = await _channel.invokeMethod<List<dynamic>>(
        'getLaunchableApps',
      );
      final apps = (raw ?? [])
          .map((entry) {
            final map = entry as Map;
            return _LaunchableApp(
              packageName: (map['packageName'] ?? '').toString(),
              label: (map['label'] ?? '').toString(),
            );
          })
          .where((app) => app.packageName.isNotEmpty)
          .toList();
      if (!mounted) return;
      setState(() {
        _apps = apps;
        _excluded = settings.excludedAppPackages.toSet();
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = 'Failed to load apps: $e';
        _loading = false;
      });
    }
  }

  Future<void> _toggle(String packageName, bool exclude) async {
    final updated = Set<String>.from(_excluded);
    if (exclude) {
      updated.add(packageName);
    } else {
      updated.remove(packageName);
    }
    setState(() => _excluded = updated);
    final settings = await AppSettingsService.load();
    await AppSettingsService.update(
      settings.copyWith(excludedAppPackages: updated.toList()),
    );
  }

  @override
  Widget build(BuildContext context) {
    final visible = _filter.isEmpty
        ? _apps
        : _apps.where((app) {
            final needle = _filter.toLowerCase();
            return app.label.toLowerCase().contains(needle) ||
                app.packageName.toLowerCase().contains(needle);
          }).toList();
    return Scaffold(
      appBar: AppBar(title: const Text('Excluded apps')),
      body: Column(
        children: [
          const Padding(
            padding: EdgeInsets.all(16),
            child: Text(
              'Checked apps bypass the VPN entirely — their traffic goes '
              'direct, unprotected by the tunnel. Applies when you next '
              'connect.',
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: TextField(
              decoration: const InputDecoration(
                hintText: 'Search apps',
                prefixIcon: Icon(Icons.search),
                border: OutlineInputBorder(),
              ),
              onChanged: (value) => setState(() => _filter = value),
            ),
          ),
          const SizedBox(height: 8),
          Expanded(
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : _error != null
                    ? Center(child: Text(_error!))
                    : visible.isEmpty
                        ? const Center(child: Text('No apps match'))
                        : ListView.builder(
                            itemCount: visible.length,
                            itemBuilder: (context, index) {
                              final app = visible[index];
                              final excluded =
                                  _excluded.contains(app.packageName);
                              return CheckboxListTile(
                                title: Text(
                                  app.label.isEmpty
                                      ? app.packageName
                                      : app.label,
                                ),
                                subtitle: Text(app.packageName),
                                value: excluded,
                                onChanged: (value) => _toggle(
                                  app.packageName,
                                  value ?? false,
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
