import 'package:flutter/material.dart';
import 'package:package_info_plus/package_info_plus.dart';

import '../services/app_settings_service.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  String _versionLabel = '';
  AppSettings _settings = const AppSettings();
  bool _settingsLoaded = false;

  @override
  void initState() {
    super.initState();
    _loadVersion();
    _loadSettings();
  }

  Future<void> _loadVersion() async {
    try {
      final info = await PackageInfo.fromPlatform();
      if (!mounted) return;
      setState(() {
        // Android's system UI only surfaces the version name; show the
        // build number (Play version code) here so testers can identify
        // exactly which build is installed.
        _versionLabel = '${info.version} (build ${info.buildNumber})';
      });
    } catch (_) {
      // Leave the label empty; dialogs fall back to the bare name.
    }
  }

  Future<void> _loadSettings() async {
    final settings = await AppSettingsService.load();
    if (!mounted) return;
    setState(() {
      _settings = settings;
      _settingsLoaded = true;
    });
  }

  Future<void> _save(AppSettings settings) async {
    setState(() => _settings = settings);
    await AppSettingsService.update(settings);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          const ListTile(
            title: Text(
              'Auto-connect',
              style: TextStyle(fontWeight: FontWeight.w700),
            ),
          ),
          SwitchListTile(
            title: const Text('Connect when the app opens'),
            subtitle: const Text(
              'Start the selected server\'s VPN as soon as Bonded opens',
            ),
            value: _settings.autoConnectOnOpen,
            onChanged: _settingsLoaded
                ? (value) =>
                      _save(_settings.copyWith(autoConnectOnOpen: value))
                : null,
          ),
          SwitchListTile(
            title: const Text('Connect after boot'),
            subtitle: const Text(
              'Start the selected server\'s VPN after the phone restarts '
              '(once it has been unlocked). Android\'s Always-on VPN '
              'setting is the system-level alternative.',
            ),
            value: _settings.autoConnectOnBoot,
            onChanged: _settingsLoaded
                ? (value) =>
                      _save(_settings.copyWith(autoConnectOnBoot: value))
                : null,
          ),
          const Divider(),
          ListTile(
            title: const Text('About Bonded'),
            subtitle: Text(
              _versionLabel.isEmpty
                  ? 'App information and licenses'
                  : 'Version $_versionLabel',
            ),
            trailing: const Icon(Icons.arrow_forward),
            onTap: () {
              showAboutDialog(
                context: context,
                applicationName: 'Bonded VPN',
                applicationVersion:
                    _versionLabel.isEmpty ? null : _versionLabel,
                children: [
                  const Text(
                    'Bonded is a secure VPN solution with multi-path support.',
                  ),
                ],
              );
            },
          ),
          const Divider(),
          ListTile(
            title: const Text('Debug Info'),
            subtitle: const Text('View technical details'),
            trailing: const Icon(Icons.arrow_forward),
            onTap: () => _showDebugInfo(context),
          ),
        ],
      ),
    );
  }

  void _showDebugInfo(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Debug Information'),
        content: SingleChildScrollView(
          child: Text(
            'Bonded VPN Android Client\n'
            'Version: ${_versionLabel.isEmpty ? 'unknown' : _versionLabel}\n'
            'Platform: Flutter 3.x\n'
            'Rust FFI: Enabled\n'
            '\n'
            'Features:\n'
            '- QR code pairing\n'
            '- Multi-path VPN\n'
            '- WebSocket + TLS support\n',
          ),
        ),
        actions: [
          TextButton(
            onPressed: Navigator.of(context).pop,
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }
}
