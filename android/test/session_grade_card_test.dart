import 'package:bonded_app/models/session_grade.dart';
import 'package:bonded_app/widgets/session_grade_card.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

const _fullGrade = SessionGrade(
  total: 92,
  letter: 'A',
  latencyScore: 100,
  stabilityScore: 100,
  availabilityScore: 90,
  bandwidthScore: 75,
  latencyDetail: 'median ≤ 50 ms',
  stabilityDetail: '0 flaps · 0.0/h',
  availabilityDetail: '90% up',
  bandwidthDetail: 'median 5–10 Mbps (active windows)',
  sampledFor: Duration(minutes: 5),
  sampleCount: 300,
);

const _sparseGrade = SessionGrade(
  total: 100,
  letter: 'A',
  latencyScore: 100,
  stabilityScore: null,
  availabilityScore: null,
  bandwidthScore: null,
  latencyDetail: 'median ≤ 50 ms',
  stabilityDetail: null,
  availabilityDetail: null,
  bandwidthDetail: null,
  sampledFor: Duration(seconds: 20),
  sampleCount: 20,
);

void main() {
  testWidgets('shows the letter, score, and all four sub-scores', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: SessionGradeCard(grade: _fullGrade, isLive: true),
        ),
      ),
    );
    await tester.pump();

    expect(find.text('Session grade'), findsOneWidget);
    expect(find.text('Live — this session'), findsOneWidget);
    expect(find.text('A'), findsOneWidget);
    expect(find.text('92 / 100'), findsOneWidget);
    expect(find.textContaining('median ≤ 50 ms'), findsOneWidget);
    expect(find.textContaining('0 flaps'), findsOneWidget);
    expect(find.textContaining('90% up'), findsOneWidget);
    expect(find.textContaining('5–10 Mbps'), findsOneWidget);
    expect(find.textContaining('300 samples'), findsOneWidget);
    expect(find.textContaining('battery is not scored'), findsOneWidget);
  });

  testWidgets('last-session grade is labelled, missing components say so', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: SessionGradeCard(grade: _sparseGrade, isLive: false),
        ),
      ),
    );
    await tester.pump();

    expect(find.text('Last session'), findsOneWidget);
    expect(find.textContaining('median ≤ 50 ms'), findsOneWidget);
    expect(find.text('— not enough data yet'), findsNWidgets(3));
  });
}
