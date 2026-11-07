import 'package:bonded_app/models/transport_grade.dart';
import 'package:bonded_app/widgets/transport_grade_detail.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

const _fullGrade = TransportGrade(
  total: 88,
  letter: 'B',
  latencyScore: 100,
  stabilityScore: 90,
  lossScore: 80,
  bandwidthScore: 75,
  latencyDetail: 'median ≤ 50 ms',
  stabilityDetail: '1 flap · 0.5/h',
  lossDetail: '1.0% lost · 110/11000 packets',
  bandwidthDetail: '2 of 40 active windows saturated',
  sampledFor: Duration(minutes: 5),
  sampleCount: 300,
);

const _sparseGrade = TransportGrade(
  total: 100,
  letter: 'A',
  latencyScore: 100,
  stabilityScore: null,
  lossScore: null,
  bandwidthScore: null,
  latencyDetail: 'median ≤ 50 ms',
  stabilityDetail: null,
  lossDetail: null,
  bandwidthDetail: null,
  sampledFor: Duration(seconds: 20),
  sampleCount: 20,
);

void main() {
  testWidgets('chip shows the letter and score', (WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(body: TransportGradeChip(grade: _fullGrade)),
      ),
    );
    await tester.pump();

    expect(find.text('B · 88'), findsOneWidget);
  });

  testWidgets('detail shows the letter, score, and all four sub-scores', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: TransportGradeDetail(label: 'Wi-Fi', grade: _fullGrade),
        ),
      ),
    );
    await tester.pump();

    expect(find.text('Wi-Fi grade'), findsOneWidget);
    expect(find.text('This transport only'), findsOneWidget);
    expect(find.text('B'), findsOneWidget);
    expect(find.text('88 / 100'), findsOneWidget);
    expect(find.textContaining('median ≤ 50 ms'), findsOneWidget);
    expect(find.textContaining('1 flap'), findsOneWidget);
    expect(find.textContaining('1.0% lost'), findsOneWidget);
    expect(find.textContaining('2 of 40 active windows'), findsOneWidget);
    expect(find.textContaining('300 samples'), findsOneWidget);
    expect(
      find.textContaining('absolute throughput is not scored'),
      findsOneWidget,
    );
  });

  testWidgets('detail with missing components says so', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: TransportGradeDetail(label: 'Cellular', grade: _sparseGrade),
        ),
      ),
    );
    await tester.pump();

    expect(find.text('Cellular grade'), findsOneWidget);
    expect(find.textContaining('median ≤ 50 ms'), findsOneWidget);
    expect(find.text('— not enough data yet'), findsNWidgets(3));
  });
}
