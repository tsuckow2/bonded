import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// The app update check: an automatic Play check that drives the
/// "update available" banner. There is deliberately no manual check
/// button (removed at the user's direction in build 186) — the
/// automatic checks on open and foreground return are enough, and the
/// banner appears on its own when Play has a newer build.
///
/// This lives on the home (server list) screen — the app's first
/// page — since build 178. It used to live on the per-server
/// dashboard, where a user had to open a server's status page to
/// learn about an app update.
class AppUpdateChecker extends StatefulWidget {
  const AppUpdateChecker({super.key});

  @override
  State<AppUpdateChecker> createState() => _AppUpdateCheckerState();
}

class _AppUpdateCheckerState extends State<AppUpdateChecker>
    with WidgetsBindingObserver {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  int? _updateAvailableVersionCode;
  DateTime? _lastUpdateCheckAt;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _checkForUpdate();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  /// Re-check for a Play update when the app returns to the foreground.
  /// The initState check alone misses updates published while the app
  /// process stays alive — which is the norm, since the VPN foreground
  /// service keeps the process around for days (2026-10-18: build 142
  /// never surfaced in-app for exactly this reason). Throttled so
  /// foregrounding the app doesn't spam Play.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed) {
      return;
    }
    final last = _lastUpdateCheckAt;
    if (last != null && DateTime.now().difference(last).inMinutes < 30) {
      return;
    }
    _checkForUpdate();
  }

  /// Ask the native side whether Play has a newer build for this install.
  /// The checks (app open, foreground return) stay silent and only
  /// drive the banner.
  Future<void> _checkForUpdate() async {
    _lastUpdateCheckAt = DateTime.now();
    int? availableVersionCode;
    try {
      final result = await _channel.invokeMapMethod<String, dynamic>(
        'checkAppUpdate',
      );
      if (result != null && result['updateAvailable'] == true) {
        availableVersionCode = (result['availableVersionCode'] as num?)
            ?.toInt();
      }
    } catch (_) {
      // Update checks must never disrupt the app.
    }
    if (!mounted) {
      return;
    }
    setState(() {
      if (availableVersionCode != null) {
        _updateAvailableVersionCode = availableVersionCode;
      }
    });
  }

  Future<void> _startUpdate() async {
    try {
      await _channel.invokeMethod<bool>('startAppUpdate');
    } catch (_) {
      // Play update flow unavailable; the banner simply stays.
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_updateAvailableVersionCode == null) {
      return const SizedBox.shrink();
    }
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
      child: _UpdateBanner(
        versionCode: _updateAvailableVersionCode!,
        onTap: _startUpdate,
      ),
    );
  }
}

class _UpdateBanner extends StatelessWidget {
  final int versionCode;
  final VoidCallback onTap;
  const _UpdateBanner({required this.versionCode, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Colors.green[50],
      borderRadius: BorderRadius.circular(8),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(8),
        child: Container(
          width: double.infinity,
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: Colors.green[300]!),
          ),
          child: Row(
            children: [
              const Icon(Icons.system_update, color: Colors.green, size: 18),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  'Update available (build $versionCode) — tap to update',
                  style: const TextStyle(color: Colors.green, fontSize: 13),
                ),
              ),
              const Icon(Icons.chevron_right, color: Colors.green, size: 18),
            ],
          ),
        ),
      ),
    );
  }
}
