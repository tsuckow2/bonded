import 'package:flutter/material.dart';

import '../models/session_grade.dart';
import 'focusable_row.dart';

/// Session grade card for the home screen (plan 4.47): the letter
/// + score up front, and the four component sub-scores with the
/// measurement behind each, so the grade is explainable — a B
/// because Latency is 62, not a black-box number.
///
/// The card is stateless: the home screen owns the
/// [SessionGradeTracker] and passes the grade to show. One
/// [FocusableRow] stop for the whole card, like the Relayed and
/// graphs cards, so D-pad focus can scroll it into view on a TV.
class SessionGradeCard extends StatelessWidget {
  final SessionGrade grade;

  /// True while the graded session is still running; false for
  /// the retained last-session grade after disconnect.
  final bool isLive;

  const SessionGradeCard({
    super.key,
    required this.grade,
    required this.isLive,
  });

  @override
  Widget build(BuildContext context) {
    return FocusableRow(
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Session grade',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        isLive
                            ? 'Live — this session'
                            : 'Last session',
                        style: TextStyle(
                          fontSize: 12,
                          color: Colors.grey[600],
                        ),
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
                          color: _letterColor(grade.letter),
                          height: 1.0,
                        ),
                      ),
                      Text(
                        '${grade.total} / 100',
                        style: TextStyle(
                          fontSize: 13,
                          color: Colors.grey[700],
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              const SizedBox(height: 12),
              _componentRow(
                'Latency',
                grade.latencyScore,
                grade.latencyDetail,
              ),
              _componentRow(
                'Stability',
                grade.stabilityScore,
                grade.stabilityDetail,
              ),
              _componentRow(
                'Availability',
                grade.availabilityScore,
                grade.availabilityDetail,
              ),
              _componentRow(
                'Bandwidth',
                grade.bandwidthScore,
                grade.bandwidthDetail,
              ),
              const SizedBox(height: 8),
              Text(
                'Based on ${grade.sampleCount} samples over '
                '${formatSampledFor(grade.sampledFor)}. '
                'Bandwidth counts active windows only; battery is '
                'not scored.',
                style: TextStyle(
                  fontSize: 12,
                  fontStyle: FontStyle.italic,
                  color: Colors.grey[600],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Color _letterColor(String letter) {
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
