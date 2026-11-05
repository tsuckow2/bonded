import 'package:bonded_app/widgets/remote_text_field.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('RemoteTextField is read-only until activated, then '
      'read-only again on focus loss', (WidgetTester tester) async {
    final controller = TextEditingController(text: 'charter.example:443');
    final fieldKey = GlobalKey<RemoteTextFieldState>();
    addTearDown(controller.dispose);

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Column(
            children: [
              RemoteTextField(key: fieldKey, controller: controller),
              // A second focusable target, so focus can leave the field.
              const TextField(key: Key('other-field')),
            ],
          ),
        ),
      ),
    );

    TextField findField() =>
        tester.widget<TextField>(find.byType(TextField).first);

    // Focus alone must not open the keyboard: the field starts read-only.
    expect(findField().readOnly, isTrue);
    expect(find.byIcon(Icons.edit_outlined), findsOneWidget);

    // A tap activates editing (the phone path, and the TV path after
    // the field already has D-pad focus).
    await tester.tap(find.byType(TextField).first);
    await tester.pump();
    expect(findField().readOnly, isFalse);
    expect(fieldKey.currentState?.isEditing, isTrue);
    expect(find.byIcon(Icons.keyboard), findsOneWidget);

    // Leaving the field ends editing; the value is preserved.
    await tester.tap(find.byKey(const Key('other-field')));
    await tester.pump();
    expect(findField().readOnly, isTrue);
    expect(fieldKey.currentState?.isEditing, isFalse);
    expect(controller.text, 'charter.example:443');
  });

  testWidgets('cancelEditing exits editing without unfocusing',
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

    await tester.tap(find.byType(TextField));
    await tester.pump();
    expect(fieldKey.currentState?.isEditing, isTrue);

    // This is what a page's PopScope calls on Back while editing.
    fieldKey.currentState?.cancelEditing();
    await tester.pump();
    expect(fieldKey.currentState?.isEditing, isFalse);
    expect(
      tester.widget<TextField>(find.byType(TextField)).readOnly,
      isTrue,
    );
    // No-op when already not editing.
    fieldKey.currentState?.cancelEditing();
    await tester.pump();
    expect(fieldKey.currentState?.isEditing, isFalse);
  });
}
