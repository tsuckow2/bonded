import 'package:bonded_app/widgets/focusable_row.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('D-pad down moves focus between focusable rows',
      (WidgetTester tester) async {
    final k1 = GlobalKey<FocusableRowState>();
    final k2 = GlobalKey<FocusableRowState>();

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Column(
            children: [
              FocusableRow(key: k1, child: const Text('row one')),
              FocusableRow(key: k2, child: const Text('row two')),
            ],
          ),
        ),
      ),
    );

    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pump();
    expect(k1.currentState?.isFocused, isTrue);

    await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
    await tester.pump();
    expect(k2.currentState?.isFocused, isTrue);
    expect(k1.currentState?.isFocused, isFalse);
  });

  testWidgets('Focusing a below-fold row scrolls it into view',
      (WidgetTester tester) async {
    final controller = ScrollController();
    final rowKey = GlobalKey<FocusableRowState>();
    addTearDown(controller.dispose);

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            controller: controller,
            child: Column(
              children: [
                // Push the row below the 600px test viewport fold.
                const SizedBox(height: 1000),
                FocusableRow(key: rowKey, child: const Text('peer row')),
              ],
            ),
          ),
        ),
      ),
    );

    expect(controller.offset, 0);
    expect(rowKey.currentState?.isFocused, isFalse);

    // The row is the only focusable widget, so Tab focuses it. Its
    // focus handler scrolls it into view (200ms animation).
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();

    expect(rowKey.currentState?.isFocused, isTrue);
    expect(controller.offset, greaterThan(0),
        reason: 'scroll view must scroll to the focused peer row');
  });
}
