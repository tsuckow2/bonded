import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// A text field for D-pad / remote navigation (Android TV) that does not
/// trap focus, without regressing touch input.
///
/// Why a plain [TextField] — and the first version of this widget —
/// fails on a TV: once a text field has focus, the D-pad arrows are
/// consumed by the editable text itself (cursor movement), so they never
/// reach focus traversal. Focus lands on the first field and can never
/// leave it, keyboard or not. That is exactly what happened in v231:
/// the keyboard no longer opened on focus, but navigation was still
/// stuck on the first field.
///
/// So this widget has two distinct states, and only one of them contains
/// a [TextField] at all:
///
/// - Idle: a focusable *row* showing the current value (or the hint)
///   with an edit icon. D-pad arrows move focus between rows, switches
///   and buttons normally, because no editable text is in the tree to
///   swallow them. The row shows a teal focus ring and scrolls into
///   view when focused.
/// - Editing: the row is replaced by a real [TextField], which gains
///   focus and opens the keyboard. While editing, the D-pad belongs to
///   the keyboard, as it should — the user exits editing first (Back,
///   or Done on a single-line field), and focus returns to the row, so
///   navigation continues from exactly where it left off.
///
/// Back handling is a page concern: a page wraps its fields in a
/// [PopScope] that calls [cancelEditing] while any field is editing, so
/// Back exits editing (hides the keyboard, focus back on the row)
/// instead of popping the page. A second Back, with nothing editing,
/// pops as usual.
///
/// On a phone the behaviour is unchanged in practice: one tap on the
/// row opens the keyboard, because a tap is also an activation.
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
  // Traversal node: the only focusable node while idle. This is what
  // D-pad navigation moves between, and it never consumes arrows.
  late final FocusNode _rowFocusNode;

  // Editing node: only in the tree while the TextField is shown.
  late final FocusNode _textFocusNode;

  bool _editing = false;
  bool _rowFocused = false;

  /// True while the TextField (and keyboard) is shown for this field.
  bool get isEditing => _editing;

  /// True while the idle row has D-pad focus. Test hook; the row node
  /// itself is deliberately not exposed.
  bool get isRowFocused => _rowFocused;

  @override
  void initState() {
    super.initState();
    _rowFocusNode = FocusNode(
      debugLabel: 'RemoteTextField row',
      onKeyEvent: _handleRowKeyEvent,
    );
    _rowFocusNode.addListener(_handleRowFocusChange);
    _textFocusNode = FocusNode(debugLabel: 'RemoteTextField text');
    _textFocusNode.addListener(_handleTextFocusChange);
    widget.controller.addListener(_handleControllerChanged);
  }

  @override
  void dispose() {
    widget.controller.removeListener(_handleControllerChanged);
    _rowFocusNode.removeListener(_handleRowFocusChange);
    _rowFocusNode.dispose();
    _textFocusNode.removeListener(_handleTextFocusChange);
    _textFocusNode.dispose();
    super.dispose();
  }

  void _handleControllerChanged() {
    // Keep the idle row's displayed value fresh if the controller is
    // changed programmatically. While editing, the TextField itself
    // shows the live value, so no rebuild is needed there.
    if (!_editing && mounted) setState(() {});
  }

  KeyEventResult _handleRowKeyEvent(FocusNode node, KeyEvent event) {
    // OK / Select on a remote, or Enter on a keyboard, activates editing
    // on a row that is only focused. Every other key — including the
    // D-pad arrows — is ignored here so focus traversal handles it.
    if (event is KeyDownEvent &&
        (event.logicalKey == LogicalKeyboardKey.select ||
            event.logicalKey == LogicalKeyboardKey.enter ||
            event.logicalKey == LogicalKeyboardKey.numpadEnter)) {
      _activateEditing();
      return KeyEventResult.handled;
    }
    return KeyEventResult.ignored;
  }

  void _handleRowFocusChange() {
    final focused = _rowFocusNode.hasFocus;
    if (focused != _rowFocused) {
      setState(() => _rowFocused = focused);
      if (focused) {
        // Keep the focused row visible on a page taller than the screen.
        WidgetsBinding.instance.addPostFrameCallback((_) {
          final context = _rowFocusNode.context;
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
  }

  void _handleTextFocusChange() {
    // Focus leaving the TextField ends editing — but only the editing
    // state, not the user's new focus. Returning focus to the row here
    // would steal focus from whatever the user just moved to (e.g. the
    // next field on a phone tap), so explicit exits (Back, Done) are
    // the only ones that restore row focus.
    if (!_textFocusNode.hasFocus && _editing) {
      _exitEditing(restoreRowFocus: false);
    }
  }

  void _activateEditing() {
    if (_editing) return;
    // If another field is editing, end it first: tapping a row does not
    // by itself move focus away from an open TextField, so without this
    // two TextFields would be in the tree at once and typing would still
    // go to the first one. This unfocus triggers that field's focus-loss
    // exit (which deliberately does not steal focus back), and the
    // post-frame focus below then lands on this field's TextField.
    FocusManager.instance.primaryFocus?.unfocus();
    setState(() => _editing = true);
    widget.onEditingChanged?.call(true);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      _textFocusNode.requestFocus();
      SystemChannels.textInput.invokeMethod<void>('TextInput.show');
    });
  }

  void _exitEditing({required bool restoreRowFocus}) {
    if (!_editing) return;
    setState(() => _editing = false);
    widget.onEditingChanged?.call(false);
    SystemChannels.textInput.invokeMethod<void>('TextInput.hide');
    if (restoreRowFocus) {
      // The row is back in the tree after the rebuild above, so request
      // its focus on the next frame. D-pad navigation then continues
      // from this field, instead of dropping focus to the top of the page.
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) _rowFocusNode.requestFocus();
      });
    }
  }

  /// Exit editing without leaving the page: hide the keyboard and put
  /// focus back on the row, so D-pad navigation can continue from here.
  /// No-op when not editing. Used by a page's [PopScope] on Back.
  void cancelEditing() {
    if (!_editing) return;
    _exitEditing(restoreRowFocus: true);
  }

  @override
  Widget build(BuildContext context) {
    if (_editing) return _buildTextField();
    return _buildRow();
  }

  Widget _buildRow() {
    final hint = widget.decoration?.hintText;
    final text = widget.controller.text;
    final showingHint = text.isEmpty && hint != null;
    return Focus(
      focusNode: _rowFocusNode,
      child: GestureDetector(
        onTap: _activateEditing,
        child: Container(
          width: double.infinity,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 14),
          decoration: BoxDecoration(
            color: Colors.grey[100],
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
              color: _rowFocused ? Colors.teal : Colors.grey[400]!,
              width: _rowFocused ? 2.5 : 1,
            ),
          ),
          child: Row(
            children: [
              Expanded(
                child: Text(
                  showingHint ? hint : text,
                  maxLines: widget.maxLines ?? 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    fontSize: 16,
                    color: showingHint ? Colors.grey[600] : null,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              const Icon(Icons.edit_outlined, size: 20, color: Colors.grey),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildTextField() {
    final base = widget.decoration ?? const InputDecoration();
    return TextField(
      controller: widget.controller,
      focusNode: _textFocusNode,
      autofocus: true,
      keyboardType: widget.keyboardType,
      maxLines: widget.maxLines,
      // Single-line Enter finishes editing (like Done on the IME) and
      // returns focus to the row. Multi-line Enter inserts a newline.
      onSubmitted: (_) => _exitEditing(restoreRowFocus: true),
      decoration: base.copyWith(
        suffixIcon: const Icon(Icons.keyboard, size: 20),
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
