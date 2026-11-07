import 'dart:convert';

import 'package:flutter/services.dart';

/// Per-transport grades for the Rust worker (4.52).
///
/// The Dart grader (4.50) owns the grades; the Rust worker owns the
/// packet path. This service bridges them: the home screen pushes the
/// current grade totals on its existing 1 s poll tick, and the worker
/// ranks best-transport flows on them. The JSON is a bare array in
/// snapshot paths-list order — one grade total (0–100) per transport
/// vec index, `null` when a path has no grade yet — so the Rust side
/// can index it directly by transport.
///
/// The push is best-effort, like the traffic-rules push: when no
/// session is running the native side has nothing to update, and a
/// failed push just leaves the previous grades in place — best
/// transport then ranks on RTT/loss until the next push. Failures are
/// swallowed — settings must never crash the UI.
class PathGradesService {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  /// Push the current grades to the running Rust session without
  /// restarting it. Returns false when no session is running (or the
  /// push failed).
  static Future<bool> pushLive(List<int?> grades) async {
    try {
      final ok = await _channel.invokeMethod<bool>('updatePathGrades', {
        'pathGradesJson': toJson(grades),
      });
      return ok ?? false;
    } catch (_) {
      return false;
    }
  }

  /// The JSON handed to Rust: a bare array, one entry per path in
  /// snapshot order, `null` for ungraded paths.
  static String toJson(List<int?> grades) => jsonEncode(grades);
}
