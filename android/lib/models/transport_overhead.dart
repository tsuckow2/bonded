import 'session_status.dart';

/// Transport overhead diagnostic result.
///
/// Mirrors `crates/bonded-core/src/overhead.rs` (`OverheadReport`).
/// Definitions, per transport:
/// * [payloadBytes] — application payload bytes in the measured
///   transfer. For the live-window measurement this is not a fixed
///   payload: it is the TUN bytes carried (inside bytes), because live
///   traffic has no known payload; the card says so.
/// * Inside bytes — TUN IP packet bytes (the session snapshot
///   outbound/inbound byte counters, which count TUN packet lengths).
///   Session frame headers are NOT inside bytes; they are wire
///   overhead.
/// * Wire bytes — bytes actually written to / read from the transport
///   socket, including transport framing/encryption, excluding
///   IP/UDP/TCP headers below the socket. Null when the transport
///   cannot observe them (WebSocketTls today).
/// * Overhead bytes = wire minus inside (saturating at zero);
///   overhead ratio = overhead / inside (null when inside is zero).
/// * Bandwidths = bytes * 8 / elapsed seconds; zero elapsed gives 0.
class TransportOverheadResult {
  final String transportLabel;
  final int payloadBytes;
  final int insideTxBytes;
  final int insideRxBytes;
  final int? wireTxBytes;
  final int? wireRxBytes;
  final Duration elapsed;

  /// True when a counter went backwards between the two snapshots,
  /// i.e. the transport was re-dialed mid-window. The deltas are
  /// meaningless in that case; the UI shows this instead of numbers.
  final bool countersReset;

  /// True for the live-window measurement (real traffic, payload is
  /// unknown so inside bytes stand in for it); false for a fixed
  /// payload test run.
  final bool isLiveWindow;

  const TransportOverheadResult({
    required this.transportLabel,
    required this.payloadBytes,
    required this.insideTxBytes,
    required this.insideRxBytes,
    required this.wireTxBytes,
    required this.wireRxBytes,
    required this.elapsed,
    this.countersReset = false,
    this.isLiveWindow = false,
  });

  int? get overheadTxBytes => wireTxBytes == null
      ? null
      : (wireTxBytes! - insideTxBytes).clamp(0, 1 << 62);

  int? get overheadRxBytes => wireRxBytes == null
      ? null
      : (wireRxBytes! - insideRxBytes).clamp(0, 1 << 62);

  double? get overheadTxRatio => overheadTxBytes == null || insideTxBytes == 0
      ? null
      : overheadTxBytes! / insideTxBytes;

  double? get overheadRxRatio => overheadRxBytes == null || insideRxBytes == 0
      ? null
      : overheadRxBytes! / insideRxBytes;

  double get payloadBandwidthBps => _bandwidth(payloadBytes);

  double get insideTxBandwidthBps => _bandwidth(insideTxBytes);

  double get insideRxBandwidthBps => _bandwidth(insideRxBytes);

  double? get wireTxBandwidthBps =>
      wireTxBytes == null ? null : _bandwidth(wireTxBytes!);

  double? get wireRxBandwidthBps =>
      wireRxBytes == null ? null : _bandwidth(wireRxBytes!);

  double _bandwidth(int bytes) {
    if (elapsed.inMicroseconds <= 0) return 0.0;
    return bytes * 8 / (elapsed.inMicroseconds / 1e6);
  }

  /// Builds one result from the before/after snapshots of a single
  /// path. Returns null when the path vanished between snapshots.
  /// When a counter went backwards (transport re-dialed mid-window)
  /// the result is returned with [countersReset] set and zero deltas.
  static TransportOverheadResult? fromSnapshots({
    required String transportLabel,
    required PathStat before,
    required PathStat after,
    required Duration elapsed,
    int? payloadBytes,
    bool isLiveWindow = false,
  }) {
    final insideTx = after.outboundBytes - before.outboundBytes;
    final insideRx = after.inboundBytes - before.inboundBytes;
    final wireTx = _delta(before.wireTxBytes, after.wireTxBytes);
    final wireRx = _delta(before.wireRxBytes, after.wireRxBytes);
    final reset =
        insideTx < 0 ||
        insideRx < 0 ||
        wireTx == _resetSentinel ||
        wireRx == _resetSentinel;
    return TransportOverheadResult(
      transportLabel: transportLabel,
      payloadBytes: payloadBytes ?? insideTx.clamp(0, 1 << 62),
      insideTxBytes: insideTx.clamp(0, 1 << 62),
      insideRxBytes: insideRx.clamp(0, 1 << 62),
      wireTxBytes: wireTx == _resetSentinel ? null : wireTx,
      wireRxBytes: wireRx == _resetSentinel ? null : wireRx,
      elapsed: elapsed,
      countersReset: reset,
      isLiveWindow: isLiveWindow,
    );
  }

  /// Sentinel for "counter went backwards". -2 is outside the range
  /// of a real delta (null is -1's job: unmeasured).
  static const int _resetSentinel = -2;

  /// Delta of two cumulative counters: null when either side is
  /// unmeasured, [_resetSentinel] when the counter went backwards.
  static int? _delta(int? before, int? after) {
    if (before == null || after == null) return null;
    final delta = after - before;
    return delta < 0 ? _resetSentinel : delta;
  }
}

/// Why a transport's wire bytes are (not) measured, for the status
/// table. Mirrors the per-transport documentation in
/// `crates/bonded-core/src/transport.rs` (`WireStats`).
String wireMeasurementStatus(String kind) {
  final lower = kind.toLowerCase();
  if (lower.contains('websocket') || lower.contains('wss')) {
    return 'Not measured — the WebSocket library owns the TCP+TLS '
        'stack and exposes no socket byte counter; reporting WS '
        'message bytes would understate the overhead.';
  }
  if (lower.contains('quic') || lower.contains('h3')) {
    return 'Measured — QUIC connection UDP stats (bytes inside UDP '
        'datagrams; IP/UDP headers excluded).';
  }
  if (lower.contains('wireguard')) {
    return 'Measured — bytes written to / read from the UDP socket '
        '(IP/UDP headers excluded).';
  }
  if (lower.contains('naive') || lower.contains('tcp')) {
    return 'Measured — bytes written to / read from the TCP socket '
        '(4-byte length prefix + session frame bytes; IP/TCP headers '
        'excluded).';
  }
  if (lower.contains('relay') || lower.contains('peer')) {
    return 'Measured — inner QUIC transport UDP stats (same as QUIC).';
  }
  return 'Unknown transport kind; wire bytes may not be measured.';
}

String formatBytes(int bytes) {
  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  if (bytes < 1024 * 1024 * 1024) {
    return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB';
  }
  return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
}

String formatBandwidth(double bps) {
  if (bps < 1024) return '${bps.toStringAsFixed(0)} b/s';
  if (bps < 1024 * 1024) return '${(bps / 1024).toStringAsFixed(1)} Kb/s';
  return '${(bps / (1024 * 1024)).toStringAsFixed(2)} Mb/s';
}
