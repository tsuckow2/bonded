import 'package:flutter/services.dart';

/// App-level settings backed by the native AppSettingsStore (SharedPreferences),
/// shared with the Quick Settings tile, the home-screen widget, and the
/// boot receiver — so every surface agrees on the selected server and the
/// auto-connect preferences even when the Flutter engine isn't running.
class AppSettings {
  final bool autoConnectOnOpen;
  final bool autoConnectOnBoot;
  final String? selectedServerId;

  const AppSettings({
    this.autoConnectOnOpen = false,
    this.autoConnectOnBoot = false,
    this.selectedServerId,
  });

  AppSettings copyWith({
    bool? autoConnectOnOpen,
    bool? autoConnectOnBoot,
    String? selectedServerId,
    bool clearSelectedServerId = false,
  }) {
    return AppSettings(
      autoConnectOnOpen: autoConnectOnOpen ?? this.autoConnectOnOpen,
      autoConnectOnBoot: autoConnectOnBoot ?? this.autoConnectOnBoot,
      selectedServerId: clearSelectedServerId
          ? null
          : (selectedServerId ?? this.selectedServerId),
    );
  }
}

class AppSettingsService {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  static Future<AppSettings> load() async {
    try {
      final map = await _channel.invokeMethod<Map<dynamic, dynamic>>(
        'getAppSettings',
      );
      return AppSettings(
        autoConnectOnOpen: map?['autoConnectOnOpen'] == true,
        autoConnectOnBoot: map?['autoConnectOnBoot'] == true,
        selectedServerId: (map?['selectedServerId'] as String?)?.isNotEmpty ==
                true
            ? map!['selectedServerId'] as String
            : null,
      );
    } catch (_) {
      return const AppSettings();
    }
  }

  static Future<void> update(AppSettings settings) async {
    try {
      await _channel.invokeMethod<void>('updateAppSettings', {
        'autoConnectOnOpen': settings.autoConnectOnOpen,
        'autoConnectOnBoot': settings.autoConnectOnBoot,
        'selectedServerId': settings.selectedServerId,
      });
    } catch (_) {
      // Settings are best-effort; the native surfaces fall back to the
      // preferred record when no selection is stored.
    }
  }
}
