import 'package:flutter/material.dart';

import '../models/grade_scoring.dart' show formatSampledFor;
import '../models/transport_grade.dart';

/// Per-transport grade display for the Paths card (plan 4.50):
/// a compact letter + score chip on each path row, and a detail
/// view (bottom sheet) with the four sub-scores and the
/// measurement behind each, so the grade is explainable — a B
/// because Loss is 62, not a black-box number.
///
/// The chip and the detail are separate widgets sharing the
/// letter colour; the sheet is opened by tapping a path row that
/// has a grade. Paths with no grade yet show no chip and do not
/// open a sheet — never a fabricated number.
class TransportGradeChip extends StatelessWidget {
  final TransportGrade grade;

  const TransportGradeChip({super.key, required this.grade});

  @override
  Widget build(BuildContext context) {
    return Text(
      '${grade.letter} · ${grade.total}',
      style: TextStyle(
        fontSize: 13,
        fontWeight: FontWeight.bold,
        color: gradeLetterColor(grade.letter),
      ),
    );
  }
}

/// The detail view for one transport's grade: title + letter and
/// total, the four component sub-scores with their measurements,
/// and a "based on N samples over M" line with the bandwidth rule
/// stated. Shown inside [showTransportGradeSheet].
class TransportGradeDetail extends StatelessWidget {
  /// Human label for the transport, e.g. "Wi-Fi" or "Peer a1b2c3d4".
  final String label;
  final TransportGrade grade;

  const TransportGradeDetail({
    super.key,
    required this.label,
    required this.grade,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  '$label grade',
                  style: const TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  'This transport only',
                  style: TextStyle(fontSize: 12, color: Colors.grey[600]),
                ),
              ],
            ),
            const Spacer(),
            Column(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Text(
                  grade.letter,
                  style: TextStyle(
                    fontSize: 34,
                    fontWeight: FontWeight.bold,
                    color: gradeLetterColor(grade.letter),
                    height: 1.0,
                  ),
                ),
                Text(
                  '${grade.total} / 100',
                  style: TextStyle(fontSize: 13, color: Colors.grey[700]),
                ),
              ],
            ),
          ],
        ),
        const SizedBox(height: 12),
        _componentRow('Latency', grade.latencyScore, grade.latencyDetail),
        _componentRow('Stability', grade.stabilityScore, grade.stabilityDetail),
        _componentRow('Loss', grade.lossScore, grade.lossDetail),
        _componentRow('Bandwidth', grade.bandwidthScore, grade.bandwidthDetail),
        const SizedBox(height: 8),
        Text(
          'Based on ${grade.sampleCount} samples over '
          '${formatSampledFor(grade.sampledFor)}. '
          'Bandwidth is 100 unless saturation is observed — '
          'absolute throughput is not scored.',
          style: TextStyle(
            fontSize: 12,
            fontStyle: FontStyle.italic,
            color: Colors.grey[600],
          ),
        ),
      ],
    );
  }

  Widget _componentRow(String label, double? score, String? detail) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          Expanded(
            flex: 2,
            child: Text(
              label,
              style: const TextStyle(fontWeight: FontWeight.w600),
            ),
          ),
          Expanded(
            flex: 3,
            child: Text(
              score == null
                  ? '— not enough data yet'
                  : '${score.round()}  ·  ${detail ?? ''}',
            ),
          ),
        ],
      ),
    );
  }
}

/// Opens the detail view for one transport's grade as a bottom
/// sheet. Call only when a grade exists.
Future<void> showTransportGradeSheet(
  BuildContext context,
  String label,
  TransportGrade grade,
) {
  return showModalBottomSheet<void>(
    context: context,
    builder: (context) => SafeArea(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: TransportGradeDetail(label: label, grade: grade),
      ),
    ),
  );
}

/// Letter colour, same bands as the shared scoring primitives.
Color gradeLetterColor(String letter) {
  switch (letter) {
    case 'A':
      return Colors.green.shade700;
    case 'B':
      return Colors.teal.shade700;
    case 'C':
      return Colors.amber.shade800;
    case 'D':
      return Colors.orange.shade800;
    default:
      return Colors.red.shade700;
  }
}
