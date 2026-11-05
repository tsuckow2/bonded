import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// A text field that separates *focus* from *editing*, for D-pad / remote
/// navigation (Android TV) without regressing touch input.
///
/// The problem with a plain [TextField] on a TV: moving focus onto it
/// with the remote immediately opens the on-screen keyboard, which
/// captures the D-pad. The user can no longer navigate past the field,
/// and pressing Back then pops the whole page instead of just closing
/// the keyboard.
///
/// With this widget:
/// - Moving focus onto the field (D-pad up/down, or Tab) does NOT open
///   the keyboard. The field just shows a clear teal focus ring and an
///   edit icon, and it scrolls into view.
/// - Pressing OK / Enter, or tapping the field, *activates* editing:
///   only then does the keyboard open.
/// - Moving focus away while editing ends editing and hides the
///   keyboard; the typed value stays in the controller.
/// - [cancelEditing] exits editing without leaving the page. A page
///   wraps its fields in a [PopScope] that calls this on Back while
///   any field is editing, so Back closes the keyboard first and only
///   pops the page on a second press, when nothing is editing.
///
/// On a phone the behaviour is unchanged in practice: one tap on the
/// field still opens the keyboard, because a tap is also an activation.
class RemoteTextField extends StatefulWidget {
  final TextEditingController controller;
  final InputDecoration? decoration;
  final TextInputType? keyboardType;
  final int? maxLines;

  /// Called with true when editing starts and false when it ends, so a
  /// page can know whether Back should exit editing instead of popping.
  final ValueChanged<bool>? onEditingChanged;

  const RemoteTextField({
    super.key,
    required this.controller,
    this.decoration,
    this.keyboardType,
    this.maxLines,
    this.onEditingChanged,
  });

  @override
  State<RemoteTextField> createState() => RemoteTextFieldState();
}

class RemoteTextFieldState extends State<RemoteTextField> {
  late final FocusNode _focusNode;
  bool _editing = false;
  bool _focused = false;

  /// True while the on-screen keyboard is (or should be) open for this
  /// field. A page uses this via [cancelEditing] on Back.
  bool get isEditing => _editing;

  @override
  void initState() {
    super.initState();
    _focusNode = FocusNode(
      debugLabel: 'RemoteTextField',
      onKeyEvent: _handleKeyEvent,
    );
    _focusNode.addListener(_handleFocusChange);
  }

  @override
  void dispose() {
    _focusNode.removeListener(_handleFocusChange);
    _focusNode.dispose();
    super.dispose();
  }

  KeyEventResult _handleKeyEvent(FocusNode node, KeyEvent event) {
    // OK / Select on a remote, or Enter on a keyboard, activates editing
    // on a field that is only focused. While editing, key events belong
    // to the text field itself (and, on a TV, to the on-screen keyboard).
    if (event is KeyDownEvent &&
        !_editing &&
        (event.logicalKey == LogicalKeyboardKey.select ||
            event.logicalKey == LogicalKeyboardKey.enter ||
            event.logicalKey == LogicalKeyboardKey.numpadEnter)) {
      _activateEditing();
      return KeyEventResult.handled;
    }
    return KeyEventResult.ignored;
  }

  void _handleFocusChange() {
    final focused = _focusNode.hasFocus;
    if (focused != _focused) {
      setState(() => _focused = focused);
      if (focused) {
        // Keep the focused field visible: a TV page is taller than the
        // screen, and the keyboard (once opened) would otherwise cover
        // the field the user just moved to.
        WidgetsBinding.instance.addPostFrameCallback((_) {
          final context = _focusNode.context;
          if (context != null && mounted) {
            Scrollable.ensureVisible(
              context,
              alignment: 0.5,
              duration: const Duration(milliseconds: 200),
            );
          }
        });
      }
    }
    // Leaving the field ends editing (and hides the keyboard). The
    // value is already in the controller, so nothing is lost.
    if (!focused && _editing) {
      _exitEditing();
    }
  }

  void _activateEditing() {
    if (_editing) return;
    setState(() => _editing = true);
    widget.onEditingChanged?.call(true);
    // The field is already focused (that is how activation happened);
    // explicitly showing the keyboard covers the readOnly -> editable
    // transition, which does not always summon it on its own.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      _focusNode.requestFocus();
      SystemChannels.textInput.invokeMethod<void>('TextInput.show');
    });
  }

  void _exitEditing() {
    if (!_editing) return;
    setState(() => _editing = false);
    widget.onEditingChanged?.call(false);
    SystemChannels.textInput.invokeMethod<void>('TextInput.hide');
  }

  /// Exit editing without leaving the page: hide the keyboard and keep
  /// focus on this field, so D-pad navigation can continue from here.
  /// No-op when not editing. Used by a page's [PopScope] on Back.
  void cancelEditing() {
    if (!_editing) return;
    _exitEditing();
    // Keep focus on the field row (read-only now, so the keyboard stays
    // hidden) instead of dropping focus to the top of the page.
    _focusNode.requestFocus();
  }

  @override
  Widget build(BuildContext context) {
    final base = widget.decoration ?? const InputDecoration();
    return TextField(
      controller: widget.controller,
      focusNode: _focusNode,
      autofocus: false,
      // Read-only until activated: this is what stops focus alone from
      // opening the keyboard on a remote, while a tap still activates
      // via [onTap] below.
      readOnly: !_editing,
      showCursor: _editing,
      enableInteractiveSelection: _editing,
      keyboardType: widget.keyboardType,
      maxLines: widget.maxLines,
      onTap: _activateEditing,
      // Single-line Enter finishes editing (like Done on the IME).
      // Multi-line Enter inserts a newline, as usual.
      onSubmitted: (_) => _exitEditing(),
      decoration: base.copyWith(
        suffixIcon: _editing
            ? const Icon(Icons.keyboard, size: 20)
            : const Icon(Icons.edit_outlined, size: 20),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: Colors.teal, width: 2.5),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: Colors.grey[400]!),
        ),
      ),
    );
  }
}
