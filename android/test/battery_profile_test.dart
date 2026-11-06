import 'package:bonded_app/models/battery_profile.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  Map<String, dynamic> profileMap() => <String, dynamic>{
        'live': true,
        'chargeCounterAvailable': true,
        'windowMs': 3600000,
        'windowSamples': 120,
        'windowStartMs': 1762387200000,
        'mahPerHour': 12.5,
        'cpuMsPerHour': 4500.0,
        'wakeupsPerHour': 88.0,
        'currentUa': 150000,
        'capacityPct': 80,
        'segments': <String, dynamic>{'idle': 9.0, 'wifi': 11.0},
        'segmentSamples': <String, dynamic>{'idle': 80, 'wifi': 100},
        'totalSamples': 120,
        'aggregates': <Map<String, dynamic>>[
          <String, dynamic>{
            'hourStartMs': 1762383600000,
            'samples': 120,
            'mahPerHour': 10.0,
            'cpuMsPerHour': 4000.0,
            'wakeupsPerHour': 80.0,
            'segments': <String, dynamic>{'idle': 8.0},
          },
          <String, dynamic>{
            'hourStartMs': 1762387200000,
            'samples': 3,
            'mahPerHour': null,
            'cpuMsPerHour': null,
            'wakeupsPerHour': null,
            'segments': <String, dynamic>{},
          },
        ],
      };

  test('fromMap parses the live window and aggregates', () {
    final profile = BatteryProfile.fromMap(profileMap());
    expect(profile.live, isTrue);
    expect(profile.chargeCounterAvailable, isTrue);
    expect(profile.windowSamples, 120);
    expect(profile.mahPerHour, 12.5);
    expect(profile.cpuMsPerHour, 4500.0);
    expect(profile.wakeupsPerHour, 88.0);
    expect(profile.currentUa, 150000);
    expect(profile.capacityPct, 80);
    expect(profile.segments['idle'], 9.0);
    expect(profile.segmentSamples['wifi'], 100);
    expect(profile.totalSamples, 120);
    expect(profile.aggregates.length, 2);
    expect(profile.aggregates[0].mahPerHour, 10.0);
    expect(profile.aggregates[0].segments['idle'], 8.0);
    expect(profile.aggregates[1].mahPerHour, isNull);
    expect(profile.hasData, isTrue);
  });

  test('fromMap null is the empty profile with no data', () {
    final profile = BatteryProfile.fromMap(null);
    expect(profile.hasData, isFalse);
    expect(profile.live, isFalse);
    expect(profile.chargeCounterAvailable, isNull);
    expect(profile.aggregates, isEmpty);
  });

  test('fromMap tolerates missing keys', () {
    final profile = BatteryProfile.fromMap(<String, dynamic>{});
    expect(profile.live, isFalse);
    expect(profile.mahPerHour, isNull);
    expect(profile.segments, isEmpty);
    expect(profile.aggregates, isEmpty);
    expect(profile.hasData, isFalse);
  });

  test('toCsv exports aggregates plus the live window', () {
    final csv = BatteryProfile.fromMap(profileMap()).toCsv();
    final lines = csv.split('\n');
    expect(lines[0],
        'hour_start_utc,samples,mah_per_hour,cpu_ms_per_hour,wakeups_per_hour,segments');
    expect(lines[1], contains('120,10.0,4000.0,80.0,idle=8.0'));
    // Null rates export empty, not "null".
    expect(lines[2], contains('3,,,,'));
    expect(lines[3], contains('120,12.5,4500.0,88.0,idle=9.0;wifi=11.0'));
  });

  test('toCsv with no live window exports aggregates only', () {
    final map = profileMap()
      ..['live'] = false
      ..['windowSamples'] = 0;
    final csv = BatteryProfile.fromMap(map).toCsv();
    expect(csv.split('\n').length, 3);
  });

  test('formatters render null as an em dash', () {
    expect(formatMahPerHour(null), '—');
    expect(formatMahPerHour(12.54), '12.5 mAh/h');
    expect(formatCpuMsPerHour(null), '—');
    expect(formatCpuMsPerHour(4500.4), '4500 ms/h');
    expect(formatWakeupsPerHour(88.6), '89 /h');
    expect(formatCurrentUa(null), '—');
    expect(formatCurrentUa(150000), '150 mA');
  });
}
