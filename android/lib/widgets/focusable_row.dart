import 'package:flutter/material.dart';

/// A row that D-pad / remote navigation can land on, for informational
/// rows that are not buttons and have no action of their own.
///
/// On the main screen, the peer-connection rows were plain [Row]s with
/// no focusable widget inside them, and the graphs card below them has
/// no focusable widget either. So on a TV, D-pad focus stopped at the
/// last path row: pressing down did nothing, the scroll view never
/// scrolled, and the peer rows below the fold stayed invisible — even
/// though touch scrolling on a phone worked fine.
///
/// Wrapping a row in this widget gives it a focus stop: it participates
/// in D-pad traversal, shows a teal ring when focused, and scrolls
/// itself into view on focus, so a below-fold row becomes visible when
/// navigation reaches it. It has no tap or key action — pressing OK on
/// it does nothing — so arrows pass through to traversal normally.
class FocusableRow extends StatefulWidget {
  final Widget child;
  const FocusableRow({super.key, required this.child});

  @override
  State<FocusableRow> createState() => FocusableRowState();
}

class FocusableRowState extends State<FocusableRow> {
  late final FocusNode _focusNode;
  bool _focused = false;

  /// True while this row has D-pad focus. Test hook.
  bool get isFocused => _focused;

  @override
  void initState() {
    super.initState();
    _focusNode = FocusNode(debugLabel: 'FocusableRow');
    _focusNode.addListener(_handleFocusChange);
  }

  @override
  void dispose() {
    _focusNode.removeListener(_handleFocusChange);
    _focusNode.dispose();
    super.dispose();
  }

  void _handleFocusChange() {
    final focused = _focusNode.hasFocus;
    if (focused != _focused) {
      setState(() => _focused = focused);
      if (focused) {
        // Scroll the row into view on focus. The border width is
        // constant (see below) so focusing does not shift layout.
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
  }

  @override
  Widget build(BuildContext context) {
    return Focus(
      focusNode: _focusNode,
      child: Container(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: _focused ? Colors.teal : Colors.transparent,
            width: 2.5,
          ),
        ),
        child: widget.child,
      ),
    );
  }
}
