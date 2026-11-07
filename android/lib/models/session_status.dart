/// Parsed view of the native session snapshot map
/// (BondedVpnService.getSessionSnapshot), shared by the main screen and
/// the read-only details page.
class PathStat {
  /// Supervisor path index; null for peer-relay transports.
  final int? pathIndex;
  final String kind;
  final bool active;
  final bool paused;
  final int outboundBytes;
  final int inboundBytes;

  /// Socket bytes for the transport overhead diagnostic (see
  /// `TransportOverheadResult`): bytes actually written to / read from
  /// the transport socket, including framing/encryption, excluding
  /// IP/UDP headers below the socket. Null when the transport cannot
  /// observe them (WebSocketTls today). Null is also possible when the
  /// native snapshot predates the wire counters (old app build).
  final int? wireTxBytes;
  final int? wireRxBytes;
  final int lastRttMs;

  /// QUIC PING frames sent on this path's connection (quinn
  /// `frame_tx.ping`, cumulative): the 25 s keepalive PINGs are the
  /// transport's steady wakeup source. Null when the transport cannot
  /// observe them (WebSocketTls) or the native snapshot predates the
  /// counter; a re-dialed path restarts from zero.
  final int? quicPingFrames;

  /// QUIC packets lost / bytes lost / packets sent on this path's
  /// connection (quinn `path.lost_packets` / `path.lost_bytes` /
  /// `path.sent_packets`, cumulative). Null when the transport cannot
  /// observe loss — only QUIC counts it (a lost QUIC packet is
  /// retransmitted by quinn, so `lost_packets` is effectively the
  /// retransmit count). A re-dialed path restarts from zero.
  final int? quicLostPackets;
  final int? quicLostBytes;
  final int? quicSentPackets;

  /// "IP:port" source address the server sees for this path's
  /// connection, reported in its heartbeat pongs; null until reported
  /// (older servers never report one).
  final String? serverSeenAddress;

  /// Provider device key for peer-relay transports; null for direct
  /// transports. Several legs share one peer id when the provider has
  /// several paths.
  final String? peerId;

  const PathStat({
    required this.pathIndex,
    required this.kind,
    required this.active,
    this.paused = false,
    required this.outboundBytes,
    required this.inboundBytes,
    this.wireTxBytes,
    this.wireRxBytes,
    required this.lastRttMs,
    required this.serverSeenAddress,
    this.peerId,
    this.quicPingFrames,
    this.quicLostPackets,
    this.quicLostBytes,
    this.quicSentPackets,
  });

  factory PathStat.fromMap(Map<dynamic, dynamic> map) {
    return PathStat(
      pathIndex: (map['pathIndex'] as num?)?.toInt(),
      kind: map['kind'] as String? ?? 'Unknown',
      active: map['active'] == true,
      paused: map['paused'] == true,
      outboundBytes: (map['outboundBytes'] as num?)?.toInt() ?? 0,
      inboundBytes: (map['inboundBytes'] as num?)?.toInt() ?? 0,
      wireTxBytes: (map['wireTxBytes'] as num?)?.toInt(),
      wireRxBytes: (map['wireRxBytes'] as num?)?.toInt(),
      lastRttMs: (map['lastRttMs'] as num?)?.toInt() ?? 0,
      quicPingFrames: (map['quicPingFrames'] as num?)?.toInt(),
      quicLostPackets: (map['quicLostPackets'] as num?)?.toInt(),
      quicLostBytes: (map['quicLostBytes'] as num?)?.toInt(),
      quicSentPackets: (map['quicSentPackets'] as num?)?.toInt(),
      serverSeenAddress:
          (map['serverSeenAddress'] as String?)?.trim().isNotEmpty == true
          ? map['serverSeenAddress'] as String
          : null,
      peerId: (map['peerId'] as String?)?.trim().isNotEmpty == true
          ? map['peerId'] as String
          : null,
    );
  }

  bool get isDirect => pathIndex != null;

  /// Packet-loss rate for this path (lost / sent), or null when the
  /// transport cannot observe loss (non-QUIC) or nothing has been
  /// sent yet.
  double? get lossRate {
    final lost = quicLostPackets;
    final sent = quicSentPackets;
    if (lost == null || sent == null || sent <= 0) return null;
    return lost / sent;
  }

  /// Display form of [lossRate]: "0.5%" with one decimal, or "—"
  /// when no rate exists. Never a fabricated number.
  String get lossDisplay {
    final rate = lossRate;
    if (rate == null) return '—';
    return '${(rate * 100).toStringAsFixed(1)}%';
  }

  /// Stable key for one transport across snapshots, shared with
  /// the per-transport grader: direct paths by supervisor index,
  /// peer-relay legs by peer id + kind.
  String get gradeKey =>
      isDirect ? 'd$pathIndex' : 'r${peerId ?? '?'}:$kind';

  /// True for peer-relay transports. Relays are full transports for
  /// spreading and failover; they are only listed separately in the
  /// UI, not ranked below direct paths.
  bool get isPeerRelay => peerId != null;

  /// Just the IP of [serverSeenAddress] (the public egress address for
  /// this path), without the ephemeral source port.
  String? get publicIp {
    final address = serverSeenAddress;
    if (address == null) return null;
    if (address.startsWith('[')) {
      final close = address.indexOf(']');
      return close > 0 ? address.substring(1, close) : address;
    }
    final split = address.lastIndexOf(':');
    return split > 0 ? address.substring(0, split) : address;
  }
}

/// A server-identity verification failure (possible interception),
/// attributed to the connection that presented the bad credentials.
class InterceptionInfo {
  /// Path index of the offending connection; null when the failure came
  /// from the pre-session identity gate (before any path existed).
  final int? pathIndex;
  final String detail;
  final int atMs;

  const InterceptionInfo({
    required this.pathIndex,
    required this.detail,
    required this.atMs,
  });

  factory InterceptionInfo.fromMap(Map<dynamic, dynamic> map) {
    return InterceptionInfo(
      pathIndex: (map['pathIndex'] as num?)?.toInt(),
      detail: map['detail'] as String? ?? '',
      atMs: (map['atMs'] as num?)?.toInt() ?? 0,
    );
  }
}

class SessionStatus {
  final String state; // connecting | connected | error | stopped | …
  final String serverAddress;
  final String activeTransport;
  final int transportCount;
  final int peerRelayCount;
  final int outboundBytes;
  final int inboundBytes;
  /// Bytes relayed for others by this session's provider legs:
  /// up = consumer -> server, down = server -> consumer.
  final int relayedUpBytes;
  final int relayedDownBytes;
  /// Session heartbeat PINGs sent by the native worker (all paths,
  /// all ticks). Wakeup accounting for the battery profiler.
  final int heartbeatPingsSent;
  /// Relay pump tasks started / ended (one per accepted leg).
  /// Wakeup accounting for the battery profiler.
  final int relayTasksStarted;
  final int relayTasksEnded;
  final int connectedAtMs;
  final String? lastError;
  final String? peerShareError;
  final int networkPathCount;
  final List<String> networkBindAddresses;
  final List<String> networkPathSummaries;
  final List<PathStat> paths;
  final InterceptionInfo? interception;

  const SessionStatus({
    required this.state,
    required this.serverAddress,
    required this.activeTransport,
    required this.transportCount,
    required this.peerRelayCount,
    required this.outboundBytes,
    required this.inboundBytes,
    required this.relayedUpBytes,
    required this.relayedDownBytes,
    required this.heartbeatPingsSent,
    required this.relayTasksStarted,
    required this.relayTasksEnded,
    required this.connectedAtMs,
    required this.lastError,
    required this.peerShareError,
    required this.networkPathCount,
    required this.networkBindAddresses,
    required this.networkPathSummaries,
    required this.paths,
    required this.interception,
  });

  static const empty = SessionStatus(
    state: '',
    serverAddress: '',
    activeTransport: 'Unknown',
    transportCount: 0,
    peerRelayCount: 0,
    outboundBytes: 0,
    inboundBytes: 0,
    relayedUpBytes: 0,
    relayedDownBytes: 0,
    heartbeatPingsSent: 0,
    relayTasksStarted: 0,
    relayTasksEnded: 0,
    connectedAtMs: 0,
    lastError: null,
    peerShareError: null,
    networkPathCount: 0,
    networkBindAddresses: [],
    networkPathSummaries: [],
    paths: [],
    interception: null,
  );

  factory SessionStatus.fromMap(Map<dynamic, dynamic>? map) {
    if (map == null) return empty;
    String? nonEmpty(dynamic value) {
      final text = (value as String?)?.trim();
      return (text == null || text.isEmpty) ? null : text;
    }

    return SessionStatus(
      state: map['state'] as String? ?? '',
      serverAddress: map['serverAddress'] as String? ?? '',
      activeTransport: map['activeTransport'] as String? ?? 'Unknown',
      transportCount: (map['transportCount'] as num?)?.toInt() ?? 0,
      peerRelayCount: (map['peerRelayCount'] as num?)?.toInt() ?? 0,
      outboundBytes: (map['outboundBytes'] as num?)?.toInt() ?? 0,
      inboundBytes: (map['inboundBytes'] as num?)?.toInt() ?? 0,
      relayedUpBytes: (map['relayedUpBytes'] as num?)?.toInt() ?? 0,
      relayedDownBytes: (map['relayedDownBytes'] as num?)?.toInt() ?? 0,
      heartbeatPingsSent: (map['heartbeatPingsSent'] as num?)?.toInt() ?? 0,
      relayTasksStarted: (map['relayTasksStarted'] as num?)?.toInt() ?? 0,
      relayTasksEnded: (map['relayTasksEnded'] as num?)?.toInt() ?? 0,
      connectedAtMs: (map['connectedAtMs'] as num?)?.toInt() ?? 0,
      lastError: nonEmpty(map['lastError']),
      peerShareError: nonEmpty(map['peerShareError']),
      networkPathCount: (map['networkPathCount'] as num?)?.toInt() ?? 0,
      networkBindAddresses: List<String>.from(
        map['networkBindAddresses'] as List? ?? const [],
      ),
      networkPathSummaries: List<String>.from(
        map['networkPathSummaries'] as List? ?? const [],
      ),
      paths: (map['paths'] as List? ?? const [])
          .map((e) => PathStat.fromMap(Map<dynamic, dynamic>.from(e as Map)))
          .toList(),
      interception: map['interception'] == null
          ? null
          : InterceptionInfo.fromMap(
              Map<dynamic, dynamic>.from(map['interception'] as Map),
            ),
    );
  }

  bool get isConnected => state == 'connected';
  bool get isConnecting => state == 'connecting';
  bool get isError => state == 'error';

  /// Direct paths only; peer relays live in [peerTransports] and get
  /// their own list in the UI.
  List<PathStat> get directPaths => paths.where((p) => p.isDirect).toList();

  /// Peer-relay transports (one per provider path), listed separately
  /// from direct paths in the UI.
  List<PathStat> get peerTransports =>
      paths.where((p) => p.isPeerRelay).toList();

  PathStat? get activePath {
    for (final path in paths) {
      if (path.active) return path;
    }
    return null;
  }

  /// Session-wide packet-loss rate: total lost / total sent over
  /// the paths that observe loss, or null when none do or nothing
  /// has been sent yet.
  double? get lossRate {
    var lost = 0;
    var sent = 0;
    var any = false;
    for (final path in paths) {
      final l = path.quicLostPackets;
      final s = path.quicSentPackets;
      if (l != null && s != null) {
        lost += l;
        sent += s;
        any = true;
      }
    }
    if (!any || sent <= 0) return null;
    return lost / sent;
  }

  /// Display form of [lossRate], same shape as [PathStat.lossDisplay].
  String get lossDisplay {
    final rate = lossRate;
    if (rate == null) return '—';
    return '${(rate * 100).toStringAsFixed(1)}%';
  }

  /// Human (label, address) for a path's network from its summary,
  /// e.g. ("Wi-Fi", "192.168.1.140"). Falls back to "Path N".
  (String, String?) describePath(int? pathIndex) {
    final summary = summaryFor(pathIndex);
    if (summary != null) {
      final split = summary.indexOf(':');
      if (split > 0) {
        final kind = summary.substring(0, split);
        final label = switch (kind.toLowerCase()) {
          'wifi' => 'Wi-Fi',
          'cellular' => 'Cellular',
          'ethernet' => 'Ethernet',
          _ => kind,
        };
        return (label, summary.substring(split + 1));
      }
    }
    return ('Path ${pathIndex ?? '?'}', null);
  }

  /// The "wifi:192.168.1.140"-style summary for a path index, if known.
  String? summaryFor(int? pathIndex) {
    if (pathIndex == null || pathIndex >= networkPathSummaries.length) {
      return null;
    }
    return networkPathSummaries[pathIndex];
  }
}
