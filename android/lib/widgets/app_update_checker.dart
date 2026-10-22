import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// The app update check: an automatic Play check that drives the
/// "update available" banner, plus the manual "Check for Updates"
/// button that reports every outcome to the user.
///
/// This lives on the home (server list) screen — the app's first
/// page — since build 178. It used to live on the per-server
/// dashboard, where a user had to open a server's status page to
/// learn about or check for an app update.
class AppUpdateChecker extends StatefulWidget {
  const AppUpdateChecker({super.key});

  @override
  State<AppUpdateChecker> createState() => _AppUpdateCheckerState();
}

class _AppUpdateCheckerState extends State<AppUpdateChecker>
    with WidgetsBindingObserver {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  int? _updateAvailableVersionCode;
  bool _checkingForUpdate = false;
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
  /// The automatic checks (app open, foreground return) stay silent and
  /// only drive the banner. A manual check from the "Check for Updates"
  /// button reports every outcome to the user — available, none, or
  /// failed — because the silent version of this check hid real updates
  /// for three builds in a row.
  Future<void> _checkForUpdate({bool manual = false}) async {
    _lastUpdateCheckAt = DateTime.now();
    if (manual && mounted) {
      setState(() {
        _checkingForUpdate = true;
      });
    }
    var outcome = 'failed';
    int? availableVersionCode;
    int? currentVersionCode;
    try {
      final result = await _channel.invokeMapMethod<String, dynamic>(
        'checkAppUpdate',
      );
      if (result != null) {
        currentVersionCode = (result['currentVersionCode'] as num?)?.toInt();
        if (result['updateAvailable'] == true) {
          outcome = 'available';
          availableVersionCode = (result['availableVersionCode'] as num?)
              ?.toInt();
        } else {
          outcome = 'none';
        }
      }
    } catch (_) {
      // Update checks must never disrupt the app.
    }
    if (!mounted) {
      return;
    }
    setState(() {
      _checkingForUpdate = false;
      if (outcome == 'available') {
        _updateAvailableVersionCode = availableVersionCode;
      }
    });
    if (manual) {
      final message = switch (outcome) {
        'available' => 'Update available: build $availableVersionCode',
        'none' =>
          'No update available${currentVersionCode != null ? ' — build $currentVersionCode is current for this install' : ''}',
        _ => "Couldn't check for updates — Play didn't answer",
      };
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(message)));
    }
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
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
      child: Column(
        children: [
          if (_updateAvailableVersionCode != null) ...[
            _UpdateBanner(
              versionCode: _updateAvailableVersionCode!,
              onTap: _startUpdate,
            ),
            const SizedBox(height: 8),
          ],
          OutlinedButton.icon(
            onPressed: _checkingForUpdate
                ? null
                : () => _checkForUpdate(manual: true),
            icon: _checkingForUpdate
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.system_update_outlined),
            label: Text(_checkingForUpdate ? 'Checking…' : 'Check for Updates'),
          ),
        ],
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
