import 'package:flutter/material.dart';

import '../models/transport_overhead.dart';

/// Displays one [TransportOverheadResult] as a labelled card.
///
/// Wire rows show "not measured" when the transport cannot observe
/// socket bytes, and the card says so instead of inventing a number.
/// A [countersReset] result shows the reset note instead of deltas.
class TransportOverheadCard extends StatelessWidget {
  final TransportOverheadResult result;

  const TransportOverheadCard({super.key, required this.result});

  @override
  Widget build(BuildContext context) {
    final r = result;
    final rows = <(String, String)>[
      (
        'Payload',
        r.isLiveWindow
            ? '${formatBytes(r.payloadBytes)} (live traffic — inside bytes stand in for payload)'
            : formatBytes(r.payloadBytes),
      ),
      ('Inside (TUN) sent', formatBytes(r.insideTxBytes)),
      ('Inside (TUN) received', formatBytes(r.insideRxBytes)),
      (
        'Wire sent',
        r.wireTxBytes == null ? 'not measured' : formatBytes(r.wireTxBytes!),
      ),
      (
        'Wire received',
        r.wireRxBytes == null ? 'not measured' : formatBytes(r.wireRxBytes!),
      ),
      (
        'Overhead sent',
        r.overheadTxBytes == null
            ? 'not measured'
            : '${formatBytes(r.overheadTxBytes!)}'
                  ' (${_pct(r.overheadTxRatio)})',
      ),
      (
        'Overhead received',
        r.overheadRxBytes == null
            ? 'not measured'
            : '${formatBytes(r.overheadRxBytes!)}'
                  ' (${_pct(r.overheadRxRatio)})',
      ),
      ('Time', '${r.elapsed.inMilliseconds} ms'),
      ('Inside bandwidth (payload)', formatBandwidth(r.payloadBandwidthBps)),
      ('Inside bandwidth (sent)', formatBandwidth(r.insideTxBandwidthBps)),
      ('Inside bandwidth (received)', formatBandwidth(r.insideRxBandwidthBps)),
      (
        'Wire bandwidth (sent)',
        r.wireTxBandwidthBps == null
            ? 'not measured'
            : formatBandwidth(r.wireTxBandwidthBps!),
      ),
      (
        'Wire bandwidth (received)',
        r.wireRxBandwidthBps == null
            ? 'not measured'
            : formatBandwidth(r.wireRxBandwidthBps!),
      ),
    ];
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '${r.transportLabel}${r.isLiveWindow ? ' — live 10 s window' : ''}',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            if (r.countersReset)
              const Text(
                'Transport was re-dialed during the window, so the '
                'counters restarted; deltas are not meaningful.',
                style: TextStyle(fontStyle: FontStyle.italic),
              )
            else
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
          ],
        ),
      ),
    );
  }

  static String _pct(double? ratio) =>
      ratio == null ? '—' : '${(ratio * 100).toStringAsFixed(1)}%';
}
