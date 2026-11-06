import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/battery_profile.dart';

/// Live battery + CPU profile card for the Diagnostics screen
/// (plan 4.46). Follows [TransportOverheadCard]'s structure: a
/// titled card of labelled rows, with the honesty note in italic
/// instead of invented numbers.
///
/// The card polls `getBatteryProfile` every 5 s while visible — a
/// display poll only, like the client-logs auto-refresh. Sampling
/// itself happens on the service's existing snapshot tick; this
/// widget adds no wakeups.
///
/// Honesty, shown on the card: the charge counter measures
/// whole-device drain, so the rates are differential and
/// state-segmented, never "Bonded used X mAh". Every rate carries
/// its window and sample count. When the device has no usable
/// charge counter the card says so and shows level % instead.
class BatteryCard extends StatefulWidget {
  const BatteryCard({super.key});

  @override
  State<BatteryCard> createState() => _BatteryCardState();
}

class _BatteryCardState extends State<BatteryCard> {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  BatteryProfile _profile = BatteryProfile.empty;
  Timer? _refreshTimer;
  String? _error;

  @override
  void initState() {
    super.initState();
    _refresh();
    _refreshTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      _refresh();
    });
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    super.dispose();
  }

  Future<void> _refresh() async {
    try {
      final raw = await _channel.invokeMethod<Map<dynamic, dynamic>>(
        'getBatteryProfile',
      );
      if (!mounted) return;
      setState(() {
        _profile = BatteryProfile.fromMap(raw);
        _error = null;
      });
    } on PlatformException catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.message ?? 'Failed to load battery profile';
      });
    }
  }

  Future<void> _copyCsv() async {
    await Clipboard.setData(ClipboardData(text: _profile.toCsv()));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Battery profile copied as CSV')),
    );
  }

  @override
  Widget build(BuildContext context) {
    final p = _profile;
    final rows = <(String, String)>[
      (
        'Drain (last hour)',
        p.chargeCounterAvailable == false
            ? 'charge counter unavailable on this device'
            : formatMahPerHour(p.mahPerHour),
      ),
      ('Process CPU (last hour)', formatCpuMsPerHour(p.cpuMsPerHour)),
      ('Wakeups (last hour)', formatWakeupsPerHour(p.wakeupsPerHour)),
      (
        'Window',
        p.windowSamples == 0
            ? 'no samples yet'
            : '${(p.windowMs / 60000).round()} min, ${p.windowSamples} samples',
      ),
      if (p.currentUa != null) ('Draw now', formatCurrentUa(p.currentUa)),
      if (p.capacityPct != null) ('Battery level', '${p.capacityPct}%'),
      ..._segmentRows(p),
    ];
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    'Battery',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                ),
                OutlinedButton.icon(
                  onPressed: p.hasData ? _copyCsv : null,
                  icon: const Icon(Icons.copy_all_outlined, size: 18),
                  label: const Text('Copy CSV'),
                ),
              ],
            ),
            const SizedBox(height: 8),
            if (_error != null)
              Text(_error!, style: const TextStyle(color: Colors.red))
            else if (!p.hasData)
              const Text(
                'No battery samples yet. Start the VPN to collect them; '
                'sampling rides the existing session-monitor tick and '
                'adds no wakeups of its own.',
                style: TextStyle(fontStyle: FontStyle.italic),
              )
            else ...[
              if (!p.live)
                const Text(
                  'VPN is not running — showing persisted hourly history only.',
                  style: TextStyle(fontStyle: FontStyle.italic),
                ),
              ...rows.map(
                (row) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: 2),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Expanded(
                        flex: 2,
                        child: Text(
                          row.$1,
                          style: const TextStyle(fontWeight: FontWeight.w600),
                        ),
                      ),
                      Expanded(flex: 3, child: Text(row.$2)),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                'These rates measure whole-device drain, segmented by '
                'state — not Bonded\u2019s share alone. Compare the same '
                'state before and after a change (idle vs active, '
                'Wi-Fi vs cellular) rather than reading any one number '
                'as the app\u2019s cost. Sparse samples during Doze are '
                'expected: the profiler never wakes the device to sample.',
                style: TextStyle(fontStyle: FontStyle.italic),
              ),
              if (p.aggregates.isNotEmpty) ...[
                const SizedBox(height: 8),
                Text(
                  'Hourly history (${p.aggregates.length} h kept, 7 days max)',
                  style: const TextStyle(fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 4),
                ...p.aggregates.reversed.take(6).map(
                  (agg) => Padding(
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    child: Text(
                      '${_hourLabel(agg.hourStartMs)}: '
                      '${formatMahPerHour(agg.mahPerHour)} '
                      '(${agg.samples} samples)',
                    ),
                  ),
                ),
              ],
            ],
          ],
        ),
      ),
    );
  }

  /// Segment rows, in dimension order, only for segments that have
  /// a computable rate. The count next to each rate is that
  /// segment's sample count over the window.
  List<(String, String)> _segmentRows(BatteryProfile p) {
    final rows = <(String, String)>[];
    void add(String label, String key) {
      final rate = p.segments[key];
      if (rate == null) return;
      final count = p.segmentSamples[key];
      rows.add((
        label,
        '${formatMahPerHour(rate)}${count == null ? '' : ' ($count samples)'}',
      ));
    }

    add('Idle', 'idle');
    add('Active', 'active');
    add('Wi-Fi', 'wifi');
    add('Cellular', 'cellular');
    add('Ethernet', 'ethernet');
    add('Peer sharing on', 'peerSharingOn');
    add('Peer sharing off', 'peerSharingOff');
    add('Battery saver on', 'batterySaverOn');
    add('Battery saver off', 'batterySaverOff');
    return rows;
  }

  String _hourLabel(int hourStartMs) {
    final dt = DateTime.fromMillisecondsSinceEpoch(hourStartMs);
    final month = dt.month.toString().padLeft(2, '0');
    final day = dt.day.toString().padLeft(2, '0');
    final hour = dt.hour.toString().padLeft(2, '0');
    return '$month-$day $hour:00';
  }
}
