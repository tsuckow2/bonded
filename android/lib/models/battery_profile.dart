/// Battery profile from the native layer
/// (`BondedVpnService.getBatteryProfile`, plan 4.46).
///
/// The profiler samples on the session monitor's existing tick — no
/// new wakeups — and reports whole-device drain segmented by state.
/// These numbers are differential, never absolute: the charge
/// counter measures the whole device, so no rate here is "Bonded
/// used X mAh". The card shows the window length and sample count
/// next to every rate, and says so when the counter is unavailable.
class BatteryHourAggregate {
  final int hourStartMs;
  final int samples;
  final double? mahPerHour;
  final double? cpuMsPerHour;
  final double? wakeupsPerHour;

  /// mAh/h per segment key ("idle", "wifi", "peerSharingOn", …).
  final Map<String, double> segments;

  const BatteryHourAggregate({
    required this.hourStartMs,
    required this.samples,
    required this.mahPerHour,
    required this.cpuMsPerHour,
    required this.wakeupsPerHour,
    required this.segments,
  });

  factory BatteryHourAggregate.fromMap(Map<dynamic, dynamic> map) {
    final segments = <String, double>{};
    final rawSegments = map['segments'];
    if (rawSegments is Map) {
      for (final entry in rawSegments.entries) {
        final value = (entry.value as num?)?.toDouble();
        if (value != null) segments[entry.key.toString()] = value;
      }
    }
    return BatteryHourAggregate(
      hourStartMs: (map['hourStartMs'] as num?)?.toInt() ?? 0,
      samples: (map['samples'] as num?)?.toInt() ?? 0,
      mahPerHour: (map['mahPerHour'] as num?)?.toDouble(),
      cpuMsPerHour: (map['cpuMsPerHour'] as num?)?.toDouble(),
      wakeupsPerHour: (map['wakeupsPerHour'] as num?)?.toDouble(),
      segments: segments,
    );
  }
}

class BatteryProfile {
  /// False when the service is not running: only the persisted
  /// hourly aggregates are present, no live window.
  final bool live;

  /// Null when the service is not running. False means this device
  /// does not implement the charge counter: the card degrades to
  /// level-% deltas and says so.
  final bool? chargeCounterAvailable;

  final int windowMs;
  final int windowSamples;
  final int? windowStartMs;
  final double? mahPerHour;
  final double? cpuMsPerHour;
  final double? wakeupsPerHour;

  /// Instantaneous draw in µA at the last sample, if reported.
  final int? currentUa;

  /// Battery level % at the last sample, if known.
  final int? capacityPct;

  /// mAh/h per segment key over the live window.
  final Map<String, double> segments;

  /// Sample count per segment key over the live window.
  final Map<String, int> segmentSamples;

  final int totalSamples;
  final List<BatteryHourAggregate> aggregates;

  const BatteryProfile({
    required this.live,
    required this.chargeCounterAvailable,
    required this.windowMs,
    required this.windowSamples,
    required this.windowStartMs,
    required this.mahPerHour,
    required this.cpuMsPerHour,
    required this.wakeupsPerHour,
    required this.currentUa,
    required this.capacityPct,
    required this.segments,
    required this.segmentSamples,
    required this.totalSamples,
    required this.aggregates,
  });

  /// No data at all yet (no service, no persisted aggregates).
  static const empty = BatteryProfile(
    live: false,
    chargeCounterAvailable: null,
    windowMs: 0,
    windowSamples: 0,
    windowStartMs: null,
    mahPerHour: null,
    cpuMsPerHour: null,
    wakeupsPerHour: null,
    currentUa: null,
    capacityPct: null,
    segments: {},
    segmentSamples: {},
    totalSamples: 0,
    aggregates: [],
  );

  factory BatteryProfile.fromMap(Map<dynamic, dynamic>? map) {
    if (map == null) return empty;
    Map<String, double> doubleMap(dynamic raw) {
      final out = <String, double>{};
      if (raw is Map) {
        for (final entry in raw.entries) {
          final value = (entry.value as num?)?.toDouble();
          if (value != null) out[entry.key.toString()] = value;
        }
      }
      return out;
    }

    Map<String, int> intMap(dynamic raw) {
      final out = <String, int>{};
      if (raw is Map) {
        for (final entry in raw.entries) {
          final value = (entry.value as num?)?.toInt();
          if (value != null) out[entry.key.toString()] = value;
        }
      }
      return out;
    }

    return BatteryProfile(
      live: map['live'] == true,
      chargeCounterAvailable: map['chargeCounterAvailable'] as bool?,
      windowMs: (map['windowMs'] as num?)?.toInt() ?? 0,
      windowSamples: (map['windowSamples'] as num?)?.toInt() ?? 0,
      windowStartMs: (map['windowStartMs'] as num?)?.toInt(),
      mahPerHour: (map['mahPerHour'] as num?)?.toDouble(),
      cpuMsPerHour: (map['cpuMsPerHour'] as num?)?.toDouble(),
      wakeupsPerHour: (map['wakeupsPerHour'] as num?)?.toDouble(),
      currentUa: (map['currentUa'] as num?)?.toInt(),
      capacityPct: (map['capacityPct'] as num?)?.toInt(),
      segments: doubleMap(map['segments']),
      segmentSamples: intMap(map['segmentSamples']),
      totalSamples: (map['totalSamples'] as num?)?.toInt() ?? 0,
      aggregates: (map['aggregates'] as List? ?? const [])
          .map(
            (e) => BatteryHourAggregate.fromMap(
              Map<dynamic, dynamic>.from(e as Map),
            ),
          )
          .toList(),
    );
  }

  bool get hasData => live || aggregates.isNotEmpty;

  /// Hourly aggregates plus the live window as CSV, for the same
  /// copy-to-clipboard export the client logs use. Segment columns
  /// are `key=value` pairs joined with ';'. Null rates export empty.
  String toCsv() {
    final rows = <String>[
      'hour_start_utc,samples,mah_per_hour,cpu_ms_per_hour,wakeups_per_hour,segments',
    ];
    String num(double? value) => value == null ? '' : value.toStringAsFixed(1);
    String segmentsCsv(Map<String, double> segments) =>
        segments.entries.map((e) => '${e.key}=${e.value.toStringAsFixed(1)}').join(';');
    for (final agg in aggregates) {
      final hour = DateTime.fromMillisecondsSinceEpoch(
        agg.hourStartMs,
        isUtc: true,
      ).toIso8601String();
      rows.add(
        '$hour,${agg.samples},${num(agg.mahPerHour)},${num(agg.cpuMsPerHour)},'
        '${num(agg.wakeupsPerHour)},${segmentsCsv(agg.segments)}',
      );
    }
    if (live && windowSamples > 0) {
      final hour = windowStartMs == null
          ? 'live-window'
          : DateTime.fromMillisecondsSinceEpoch(
              windowStartMs!,
              isUtc: true,
            ).toIso8601String();
      rows.add(
        '$hour,$windowSamples,${num(mahPerHour)},${num(cpuMsPerHour)},'
        '${num(wakeupsPerHour)},${segmentsCsv(segments)}',
      );
    }
    return rows.join('\n');
  }
}

String formatMahPerHour(double? value) =>
    value == null ? '—' : '${value.toStringAsFixed(1)} mAh/h';

String formatCpuMsPerHour(double? value) =>
    value == null ? '—' : '${value.toStringAsFixed(0)} ms/h';

String formatWakeupsPerHour(double? value) =>
    value == null ? '—' : '${value.toStringAsFixed(0)} /h';

String formatCurrentUa(int? value) =>
    value == null ? '—' : '${(value / 1000).toStringAsFixed(0)} mA';
