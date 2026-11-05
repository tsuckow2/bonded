import 'package:bonded_app/widgets/remote_text_field.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('Idle field is a row, not a TextField; tap activates editing',
      (WidgetTester tester) async {
    final controller = TextEditingController(text: 'charter.example:443');
    final fieldKey = GlobalKey<RemoteTextFieldState>();
    addTearDown(controller.dispose);

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: RemoteTextField(key: fieldKey, controller: controller),
        ),
      ),
    );

    // Idle: value shown in a row, no editable text in the tree to swallow
    // D-pad arrows, edit icon present.
    expect(find.text('charter.example:443'), findsOneWidget);
    expect(find.byType(TextField), findsNothing);
    expect(find.byIcon(Icons.edit_outlined), findsOneWidget);
    expect(fieldKey.currentState?.isEditing, isFalse);

    // A tap activates editing (the phone path, and the TV path after the
    // row already has D-pad focus).
    await tester.tap(find.byType(GestureDetector));
    await tester.pump();
    expect(fieldKey.currentState?.isEditing, isTrue);
    expect(find.byType(TextField), findsOneWidget);
    expect(find.byIcon(Icons.keyboard), findsOneWidget);
  });

  testWidgets('D-pad down moves focus from one idle row to the next',
      (WidgetTester tester) async {
    final c1 = TextEditingController(text: 'first');
    final c2 = TextEditingController(text: 'second');
    final k1 = GlobalKey<RemoteTextFieldState>();
    final k2 = GlobalKey<RemoteTextFieldState>();
    addTearDown(() {
      c1.dispose();
      c2.dispose();
    });

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Column(
            children: [
              RemoteTextField(key: k1, controller: c1),
              RemoteTextField(key: k2, controller: c2),
            ],
          ),
        ),
      ),
    );

    // Tab to the first row, then D-pad down. This is the regression test
    // for v231: with a TextField in the tree while idle, the arrows were
    // consumed by the editable text and focus never left the first field.
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pump();
    expect(k1.currentState?.isRowFocused, isTrue);

    await tester.sendKeyEvent(LogicalKeyboardKey.arrowDown);
    await tester.pump();
    expect(k2.currentState?.isRowFocused, isTrue);
    expect(k1.currentState?.isRowFocused, isFalse);
  });

  testWidgets('cancelEditing exits editing and returns focus to the row',
      (WidgetTester tester) async {
    final controller = TextEditingController(text: 'value');
    final fieldKey = GlobalKey<RemoteTextFieldState>();
    addTearDown(controller.dispose);

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: RemoteTextField(key: fieldKey, controller: controller),
        ),
      ),
    );

    await tester.tap(find.byType(GestureDetector));
    await tester.pump();
    expect(fieldKey.currentState?.isEditing, isTrue);

    // This is what a page's PopScope calls on Back while editing.
    fieldKey.currentState?.cancelEditing();
    await tester.pump();
    expect(fieldKey.currentState?.isEditing, isFalse);
    expect(find.byType(TextField), findsNothing);
    expect(fieldKey.currentState?.isRowFocused, isTrue);

    // No-op when already not editing.
    fieldKey.currentState?.cancelEditing();
    await tester.pump();
    expect(fieldKey.currentState?.isEditing, isFalse);
  });

  testWidgets('Tapping a second row moves editing without stealing focus',
      (WidgetTester tester) async {
    final c1 = TextEditingController(text: 'first');
    final c2 = TextEditingController(text: 'second');
    final k1 = GlobalKey<RemoteTextFieldState>();
    final k2 = GlobalKey<RemoteTextFieldState>();
    addTearDown(() {
      c1.dispose();
      c2.dispose();
    });

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Column(
            children: [
              RemoteTextField(key: k1, controller: c1),
              RemoteTextField(key: k2, controller: c2),
            ],
          ),
        ),
      ),
    );

    await tester.tap(find.byType(GestureDetector).first);
    await tester.pump();
    expect(k1.currentState?.isEditing, isTrue);

    await tester.tap(find.byType(GestureDetector).last);
    await tester.pump();
    expect(k1.currentState?.isEditing, isFalse);
    expect(k2.currentState?.isEditing, isTrue);
    // Exactly one TextField in the tree: the second field's.
    expect(find.byType(TextField), findsOneWidget);
  });
}
