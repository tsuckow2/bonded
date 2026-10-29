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
  final int lastRttMs;

  /// "IP:port" source address the server sees for this path's
  /// connection, reported in its heartbeat pongs; null until reported
  /// (older servers never report one).
  final String? serverSeenAddress;

  const PathStat({
    required this.pathIndex,
    required this.kind,
    required this.active,
    this.paused = false,
    required this.outboundBytes,
    required this.inboundBytes,
    required this.lastRttMs,
    required this.serverSeenAddress,
  });

  factory PathStat.fromMap(Map<dynamic, dynamic> map) {
    return PathStat(
      pathIndex: (map['pathIndex'] as num?)?.toInt(),
      kind: map['kind'] as String? ?? 'Unknown',
      active: map['active'] == true,
      paused: map['paused'] == true,
      outboundBytes: (map['outboundBytes'] as num?)?.toInt() ?? 0,
      inboundBytes: (map['inboundBytes'] as num?)?.toInt() ?? 0,
      lastRttMs: (map['lastRttMs'] as num?)?.toInt() ?? 0,
      serverSeenAddress:
          (map['serverSeenAddress'] as String?)?.trim().isNotEmpty == true
          ? map['serverSeenAddress'] as String
          : null,
    );
  }

  bool get isDirect => pathIndex != null;

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

  /// Direct paths only (peer relays are not user-facing paths).
  List<PathStat> get directPaths => paths.where((p) => p.isDirect).toList();

  PathStat? get activePath {
    for (final path in paths) {
      if (path.active) return path;
    }
    return null;
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
