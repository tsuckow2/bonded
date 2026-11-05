import 'dart:io';

import 'package:bonded_app/services/tcp_echo_client.dart';
import 'package:flutter_test/flutter_test.dart';

/// A loopback echo server: accepts connections and writes every chunk
/// back verbatim. Returns the bound server so the test can read its port.
Future<ServerSocket> startEchoServer() async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((socket) {
    socket.listen(socket.add, onError: (_) {}, onDone: () {});
  });
  return server;
}

void main() {
  test('echo run verifies a fixed payload end to end', () async {
    final server = await startEchoServer();
    addTearDown(server.close);
    final client = TcpEchoClient(
      host: InternetAddress.loopbackIPv4,
      port: server.port,
    );
    final stats = await client.run(payloadBytes: 256 * 1024);
    expect(stats.payloadBytes, 256 * 1024);
    expect(stats.elapsed.inMicroseconds, greaterThan(0));
  });

  test('echo run verifies the largest payload size', () async {
    final server = await startEchoServer();
    addTearDown(server.close);
    final client = TcpEchoClient(
      host: InternetAddress.loopbackIPv4,
      port: server.port,
    );
    final stats = await client.run(payloadBytes: 1024 * 1024);
    expect(stats.payloadBytes, 1024 * 1024);
  });

  test('unreachable echo throws EchoUnavailableException', () async {
    // Bind a port and close it, so nothing listens on it.
    final tmp = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = tmp.port;
    await tmp.close();
    final client = TcpEchoClient(
      host: InternetAddress.loopbackIPv4,
      port: port,
    );
    await expectLater(
      client.run(payloadBytes: 1024),
      throwsA(isA<EchoUnavailableException>()),
    );
  });

  test('mismatched echo throws EchoMismatchException', () async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((socket) {
      socket.listen(
        (data) {
          // Echo zeros instead of the payload: same length, wrong bytes.
          socket.add(List.filled(data.length, 0));
        },
        onError: (_) {},
        onDone: () {},
      );
    });
    addTearDown(server.close);
    final client = TcpEchoClient(
      host: InternetAddress.loopbackIPv4,
      port: server.port,
    );
    await expectLater(
      client.run(payloadBytes: 4096),
      throwsA(isA<EchoMismatchException>()),
    );
  });
}
