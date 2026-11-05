import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

/// Thrown when the TCP echo endpoint cannot be reached at all: the
/// connection is refused, times out, or otherwise fails before any
/// payload is sent. On a live device this means the server predates
/// the echo endpoint (10.8.0.1:18099) — the diagnostic reports it
/// instead of hanging.
class EchoUnavailableException implements Exception {
  final String message;
  const EchoUnavailableException(this.message);

  @override
  String toString() => message;
}

/// Thrown when the far end answered but the echoed bytes differ from
/// the bytes sent.
class EchoMismatchException implements Exception {
  final String message;
  const EchoMismatchException(this.message);

  @override
  String toString() => message;
}

/// The outcome of one fixed-payload echo run.
class EchoRunStats {
  /// Application payload bytes sent and verified received.
  final int payloadBytes;

  /// Wall time for the whole run: connect, send, and read-back.
  final Duration elapsed;

  const EchoRunStats({required this.payloadBytes, required this.elapsed});
}

/// Connects a socket; injectable so tests can point the run at a
/// loopback echo server instead of the tunnel gateway.
typedef EchoSocketConnect = Future<Socket> Function(
  InternetAddress address,
  int port, {
  Duration? timeout,
});

/// Runs a fixed-payload TCP echo exchange against the tunnel
/// gateway's echo endpoint (10.8.0.1:18099).
///
/// The socket is an ordinary Dart socket: the app itself is never
/// excluded from the VPN, so an unprotected socket to 10.8.0.1 is
/// routed through the TUN into the tunnel (only the transport
/// sockets use `protect()` to bypass it). The server terminates the
/// connection locally and echoes the payload back verbatim.
///
/// The payload is deterministic — byte i is (i % 251) — so any
/// truncation, reorder, or corruption is caught by the comparison.
///
/// After the full payload is read back, the socket is destroyed
/// (RST) rather than closed (FIN): the echo has already been fully
/// received, and the RST reaps the server-side flow promptly instead
/// of leaving a CloseWait socket behind.
class TcpEchoClient {
  /// The tunnel gateway address (same address the DNS proxy answers on).
  static const String defaultHost = '10.8.0.1';

  /// TCP echo port on the tunnel gateway (see
  /// `crates/bonded-server/src/tunnel_echo.rs`).
  static const int defaultPort = 18099;

  final InternetAddress _host;
  final int _port;
  final EchoSocketConnect _connect;

  TcpEchoClient({
    InternetAddress? host,
    int port = defaultPort,
    EchoSocketConnect? connect,
  })  : _host = host ?? InternetAddress(defaultHost),
        _port = port,
        _connect = connect ?? Socket.connect;

  /// Sends [payloadBytes] and reads the echo back, verifying it
  /// byte-for-byte. Throws [EchoUnavailableException] when the
  /// endpoint cannot be reached, [EchoMismatchException] when the
  /// echo differs, or [TimeoutException] when the transfer stalls.
  Future<EchoRunStats> run({
    required int payloadBytes,
    Duration connectTimeout = const Duration(seconds: 10),
    Duration? totalTimeout,
  }) async {
    final total = totalTimeout ??
        (payloadBytes > 1024 * 1024
            ? const Duration(seconds: 60)
            : const Duration(seconds: 30));
    final stopwatch = Stopwatch()..start();
    late final Socket socket;
    try {
      socket = await _connect(
        _host,
        _port,
        timeout: connectTimeout,
      );
    } on SocketException catch (e) {
      throw EchoUnavailableException(
        'The echo endpoint is not available on this server '
        '(10.8.0.1:$defaultPort did not answer: ${e.message}). '
        'The server may predate the echo endpoint.',
      );
    } on TimeoutException {
      throw EchoUnavailableException(
        'The echo endpoint is not available on this server '
        '(10.8.0.1:$defaultPort did not answer within '
        '${connectTimeout.inSeconds} s). '
        'The server may predate the echo endpoint.',
      );
    }

    try {
      final payload = _patternedPayload(payloadBytes);
      await _exchange(socket, payload).timeout(total);
    } on TimeoutException {
      throw TimeoutException(
        'Echo transfer stalled after ${total.inSeconds} s.',
      );
    } finally {
      // RST: the echo is fully received by now (or the run failed),
      // and the reset reaps the server-side flow promptly.
      socket.destroy();
    }
    stopwatch.stop();
    return EchoRunStats(payloadBytes: payloadBytes, elapsed: stopwatch.elapsed);
  }

  /// Sends [payload] in chunks and reads exactly its length back,
  /// throwing [EchoMismatchException] when the bytes differ.
  Future<void> _exchange(Socket socket, Uint8List payload) async {
    const chunkSize = 64 * 1024;
    final received = BytesBuilder();
    final done = Completer<void>();
    late final StreamSubscription<Uint8List> subscription;
    subscription = socket.listen(
      (chunk) {
        received.add(chunk);
        if (received.length >= payload.length && !done.isCompleted) {
          done.complete();
        }
      },
      onError: (Object error) {
        if (!done.isCompleted) done.completeError(error);
      },
      onDone: () {
        if (!done.isCompleted) done.complete();
      },
    );
    try {
      for (var offset = 0; offset < payload.length; offset += chunkSize) {
        final end = (offset + chunkSize).clamp(0, payload.length);
        socket.add(payload.sublist(offset, end));
      }
      await socket.flush();
      // Bounded by the caller's timeout around this whole exchange.
      await done.future;
      final bytes = received.takeBytes();
      if (bytes.length != payload.length) {
        throw EchoMismatchException(
          'Echo returned ${bytes.length} bytes for a '
          '${payload.length}-byte payload.',
        );
      }
      for (var i = 0; i < payload.length; i++) {
        if (bytes[i] != payload[i]) {
          throw EchoMismatchException(
            'Echo differs at byte $i of ${payload.length}.',
          );
        }
      }
    } finally {
      await subscription.cancel();
    }
  }

  static Uint8List _patternedPayload(int length) {
    final payload = Uint8List(length);
    for (var i = 0; i < length; i++) {
      payload[i] = i % 251;
    }
    return payload;
  }
}
