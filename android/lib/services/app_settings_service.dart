import 'dart:convert';

import 'package:flutter/services.dart';

import '../models/traffic_mode.dart';

/// App-level settings backed by the native AppSettingsStore (SharedPreferences),
/// shared with the Quick Settings tile, the home-screen widget, and the
/// boot receiver — so every surface agrees on the selected server and the
/// auto-connect preferences even when the Flutter engine isn't running.
class AppSettings {
  final bool autoConnectOnOpen;
  final bool autoConnectOnBoot;
  final String? selectedServerId;
  final bool allowLocalTraffic;
  final List<String> excludedAppPackages;
  final bool batterySaver;

  /// Traffic-mode rule table (4.51): default mode + per-domain/IP
  /// overrides. Serialized as one JSON blob in the same
  /// SharedPreferences store as the other settings — no second store.
  final TrafficModeSettings trafficModeSettings;

  const AppSettings({
    this.autoConnectOnOpen = false,
    this.autoConnectOnBoot = false,
    this.selectedServerId,
    this.allowLocalTraffic = false,
    this.excludedAppPackages = const [],
    this.batterySaver = false,
    this.trafficModeSettings = const TrafficModeSettings(),
  });

  AppSettings copyWith({
    bool? autoConnectOnOpen,
    bool? autoConnectOnBoot,
    String? selectedServerId,
    bool clearSelectedServerId = false,
    bool? allowLocalTraffic,
    List<String>? excludedAppPackages,
    bool? batterySaver,
    TrafficModeSettings? trafficModeSettings,
  }) {
    return AppSettings(
      autoConnectOnOpen: autoConnectOnOpen ?? this.autoConnectOnOpen,
      autoConnectOnBoot: autoConnectOnBoot ?? this.autoConnectOnBoot,
      selectedServerId: clearSelectedServerId
          ? null
          : (selectedServerId ?? this.selectedServerId),
      allowLocalTraffic: allowLocalTraffic ?? this.allowLocalTraffic,
      excludedAppPackages: excludedAppPackages ?? this.excludedAppPackages,
      batterySaver: batterySaver ?? this.batterySaver,
      trafficModeSettings: trafficModeSettings ?? this.trafficModeSettings,
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
        allowLocalTraffic: map?['allowLocalTraffic'] == true,
        excludedAppPackages: (map?['excludedAppPackages'] as List?)
                ?.map((e) => e.toString())
                .toList() ??
            const [],
        batterySaver: map?['batterySaver'] == true,
        trafficModeSettings: _parseTrafficModeSettings(
          map?['trafficRulesJson'] as String?,
        ),
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
        'allowLocalTraffic': settings.allowLocalTraffic,
        'excludedAppPackages': settings.excludedAppPackages,
        'batterySaver': settings.batterySaver,
        'trafficRulesJson': jsonEncode(settings.trafficModeSettings.toJson()),
      });
    } catch (_) {
      // Settings are best-effort; the native surfaces fall back to the
      // preferred record when no selection is stored.
    }
  }

  /// A malformed stored rule table must never break settings load —
  /// fall back to the empty default table.
  static TrafficModeSettings _parseTrafficModeSettings(String? json) {
    if (json == null || json.isEmpty) {
      return const TrafficModeSettings();
    }
    try {
      final decoded = jsonDecode(json);
      if (decoded is Map<String, dynamic>) {
        return TrafficModeSettings.fromJson(decoded);
      }
      if (decoded is Map) {
        return TrafficModeSettings.fromJson(
          Map<String, dynamic>.from(decoded),
        );
      }
    } catch (_) {
      // Fall through to the default table.
    }
    return const TrafficModeSettings();
  }
}
