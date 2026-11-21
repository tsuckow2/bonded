// SessionSnapshot.swift — Swift model of the bonded-ffi session
// snapshot JSON (slice 4.98).
//
// Mirrors android/lib/models/session_status.dart (PathStat,
// RelayedPeer, SessionStatus) field for field, so the macOS cards
// show the same numbers Android shows. Parsing is tolerant, like
// Dart's fromMap: missing keys fall back to defaults, empty peer
// ids are dropped, numbers arrive as NSNumber.
//
// Snapshot keys (bonded_ffi_desktop.h / snapshot_json in
// crates/bonded-ffi/src/lib.rs): state, serverAddress,
// activeTransport, transportCount, peerRelayCount, outboundPackets,
// inboundPackets, outboundBytes, inboundBytes, relayedUpBytes,
// relayedDownBytes, relayedPeers [{peerId, upBytes, downBytes}],
// heartbeatPingsSent, supervisorRedialAttempts, relayTasksStarted,
// relayTasksEnded, connectedAtMs, lastError, peerShareError,
// interception {pathIndex, detail, atMs}, paths [{pathIndex, kind,
// active, paused, outboundBytes, inboundBytes, wireTxBytes,
// wireRxBytes, quicPingFrames, quicLostPackets, quicLostBytes,
// quicSentPackets, lastRttMs, serverSeenAddress, peerId}].
//
// NOT in the snapshot (Android adds these itself from the VPN
// service, so the macOS UI cannot show them): networkPathCount,
// networkBindAddresses, networkPathSummaries — the "Wi-Fi" /
// "Cellular" label and the bind address for a path. macOS rows
// therefore label direct paths "Path N" plus the transport kind.
// Filling that gap needs a snapshot change in the FFI (follow-up,
// not this slice).

import Foundation

/// One transport's counters in a snapshot.
struct PathStat: Equatable {
    /// Supervisor path index; nil for peer-relay transports.
    let pathIndex: Int?
    let kind: String
    let active: Bool
    let paused: Bool
    let outboundBytes: Int
    let inboundBytes: Int
    let wireTxBytes: Int?
    let wireRxBytes: Int?
    let lastRttMs: Int
    let serverSeenAddress: String?
    /// Provider device key for peer-relay transports; nil for direct.
    let peerId: String?
    let quicPingFrames: Int?
    let quicLostPackets: Int?
    let quicLostBytes: Int?
    let quicSentPackets: Int?

    var isDirect: Bool { pathIndex != nil }

    /// True for peer-relay transports. Relays are full transports
    /// for spreading and failover; they are only listed separately
    /// in the UI, not ranked below direct paths.
    var isPeerRelay: Bool { peerId != nil }

    /// Packet-loss rate for this path (lost / sent), or nil when
    /// the transport cannot observe loss (non-QUIC) or nothing has
    /// been sent yet.
    var lossRate: Double? {
        guard
            let lost = quicLostPackets,
            let sent = quicSentPackets,
            sent > 0
        else { return nil }
        return Double(lost) / Double(sent)
    }

    /// Display form of lossRate: "0.5%" with one decimal, or "—"
    /// when no rate exists. Never a fabricated number.
    var lossDisplay: String {
        guard let rate = lossRate else { return "—" }
        return String(format: "%.1f%%", rate * 100)
    }

    /// Stable key for one transport across snapshots, shared with
    /// the per-transport grader: direct paths by supervisor index,
    /// peer-relay legs by peer id + kind.
    var gradeKey: String {
        if isDirect {
            return "d\(pathIndex ?? -1)"
        }
        return "r\(peerId ?? "?"):\(kind)"
    }

    /// Just the IP of serverSeenAddress (the public egress address
    /// for this path), without the ephemeral source port.
    var publicIp: String? {
        guard let address = serverSeenAddress else { return nil }
        if address.hasPrefix("[") {
            if let close = address.firstIndex(of: "]") {
                return String(address[address.index(after: address.startIndex)..<close])
            }
            return address
        }
        if let split = address.lastIndex(of: ":") {
            return String(address[..<split])
        }
        return address
    }

    static func from(_ dict: [String: Any]) -> PathStat {
        let peerIdRaw = (dict["peerId"] as? String)?.trimmingCharacters(
            in: .whitespaces)
        let serverSeenRaw = (dict["serverSeenAddress"] as? String)?
            .trimmingCharacters(in: .whitespaces)
        return PathStat(
            pathIndex: (dict["pathIndex"] as? NSNumber)?.intValue,
            kind: dict["kind"] as? String ?? "Unknown",
            active: dict["active"] as? Bool ?? false,
            paused: dict["paused"] as? Bool ?? false,
            outboundBytes: (dict["outboundBytes"] as? NSNumber)?.intValue ?? 0,
            inboundBytes: (dict["inboundBytes"] as? NSNumber)?.intValue ?? 0,
            wireTxBytes: (dict["wireTxBytes"] as? NSNumber)?.intValue,
            wireRxBytes: (dict["wireRxBytes"] as? NSNumber)?.intValue,
            lastRttMs: (dict["lastRttMs"] as? NSNumber)?.intValue ?? 0,
            serverSeenAddress: (serverSeenRaw != nil && !serverSeenRaw!.isEmpty)
                ? serverSeenRaw : nil,
            peerId: (peerIdRaw != nil && !peerIdRaw!.isEmpty) ? peerIdRaw : nil,
            quicPingFrames: (dict["quicPingFrames"] as? NSNumber)?.intValue,
            quicLostPackets: (dict["quicLostPackets"] as? NSNumber)?.intValue,
            quicLostBytes: (dict["quicLostBytes"] as? NSNumber)?.intValue,
            quicSentPackets: (dict["quicSentPackets"] as? NSNumber)?.intValue)
    }
}

/// A server-identity verification failure (possible interception),
/// attributed to the connection that presented the bad credentials.
struct InterceptionInfo: Equatable {
    let pathIndex: Int?
    let detail: String
    let atMs: Int

    static func from(_ dict: [String: Any]) -> InterceptionInfo {
        InterceptionInfo(
            pathIndex: (dict["pathIndex"] as? NSNumber)?.intValue,
            detail: dict["detail"] as? String ?? "",
            atMs: (dict["atMs"] as? NSNumber)?.intValue ?? 0)
    }
}

/// One peer this device is serving as a peer-share provider for
/// (4.91): consumer device key + relayed byte totals (up = consumer
/// -> server, down = server -> consumer). One entry per served peer;
/// a consumer with several provider paths holds one entry with its
/// combined traffic. The provider side of a leg is never a
/// transport, so these peers never appear in
/// SessionSnapshot.peerTransports — this list is how they show on
/// the Relayed card.
struct RelayedPeer: Equatable {
    /// Consumer device key (base64).
    let peerId: String
    let upBytes: Int
    let downBytes: Int

    /// Short id for display: the first 8 chars, like Android's
    /// RelayedPeerRow.
    var shortId: String { String(peerId.prefix(8)) }

    static func from(_ dict: [String: Any]) -> RelayedPeer? {
        let peerId = dict["peerId"] as? String ?? ""
        guard !peerId.isEmpty else { return nil }
        return RelayedPeer(
            peerId: peerId,
            upBytes: (dict["upBytes"] as? NSNumber)?.intValue ?? 0,
            downBytes: (dict["downBytes"] as? NSNumber)?.intValue ?? 0)
    }
}

/// Parsed view of the session snapshot JSON, shared by the main
/// screen and the pairing view.
struct SessionSnapshot: Equatable {
    let state: String // connecting | connected | error | stopped | …
    let serverAddress: String
    let activeTransport: String
    let transportCount: Int
    let peerRelayCount: Int
    let outboundBytes: Int
    let inboundBytes: Int
    /// Bytes relayed for others by this session's provider legs:
    /// up = consumer -> server, down = server -> consumer.
    let relayedUpBytes: Int
    let relayedDownBytes: Int
    /// Peers this device is currently providing for (4.91): one
    /// entry per served consumer. Empty when peer-share never
    /// provided.
    let relayedPeers: [RelayedPeer]
    let heartbeatPingsSent: Int
    let relayTasksStarted: Int
    let relayTasksEnded: Int
    let connectedAtMs: Int
    let lastError: String?
    let peerShareError: String?
    let paths: [PathStat]
    let interception: InterceptionInfo?

    static let empty = SessionSnapshot(
        state: "",
        serverAddress: "",
        activeTransport: "Unknown",
        transportCount: 0,
        peerRelayCount: 0,
        outboundBytes: 0,
        inboundBytes: 0,
        relayedUpBytes: 0,
        relayedDownBytes: 0,
        relayedPeers: [],
        heartbeatPingsSent: 0,
        relayTasksStarted: 0,
        relayTasksEnded: 0,
        connectedAtMs: 0,
        lastError: nil,
        peerShareError: nil,
        paths: [],
        interception: nil)

    var isConnected: Bool { state == "connected" }
    var isConnecting: Bool { state == "connecting" }
    var isError: Bool { state == "error" }

    /// Direct paths only; peer relays live in peerTransports and
    /// get their own list in the UI.
    var directPaths: [PathStat] { paths.filter { $0.isDirect } }

    /// Peer-relay transports (one per provider path), listed
    /// separately from direct paths in the UI.
    var peerTransports: [PathStat] { paths.filter { $0.isPeerRelay } }

    var activePath: PathStat? { paths.first { $0.active } }

    /// Session-wide packet-loss rate: total lost / total sent over
    /// the paths that observe loss, or nil when none do or nothing
    /// has been sent yet.
    var lossRate: Double? {
        var lost = 0
        var sent = 0
        var any = false
        for path in paths {
            if let l = path.quicLostPackets, let s = path.quicSentPackets {
                lost += l
                sent += s
                any = true
            }
        }
        guard any && sent > 0 else { return nil }
        return Double(lost) / Double(sent)
    }

    /// Display form of lossRate, same shape as
    /// PathStat.lossDisplay.
    var lossDisplay: String {
        guard let rate = lossRate else { return "—" }
        return String(format: "%.1f%%", rate * 100)
    }

    /// Parse the snapshot JSON the provider returns via
    /// handleAppMessage("snapshot"). Returns nil when the JSON is
    /// not a dictionary at all; a dictionary with missing keys
    /// parses with defaults.
    static func parse(_ json: String) -> SessionSnapshot? {
        guard
            let data = json.data(using: .utf8),
            let object = try? JSONSerialization.jsonObject(with: data),
            let map = object as? [String: Any]
        else { return nil }
        return from(map)
    }

    static func from(_ map: [String: Any]) -> SessionSnapshot {
        func nonEmpty(_ value: Any?) -> String? {
            guard
                let text = (value as? String)?.trimmingCharacters(
                    in: .whitespaces),
                !text.isEmpty
            else { return nil }
            return text
        }
        let relayedPeers = (map["relayedPeers"] as? [[String: Any]] ?? [])
            .compactMap { RelayedPeer.from($0) }
        let paths = (map["paths"] as? [[String: Any]] ?? [])
            .map { PathStat.from($0) }
        let interception: InterceptionInfo?
        if let dict = map["interception"] as? [String: Any] {
            interception = InterceptionInfo.from(dict)
        } else {
            interception = nil
        }
        return SessionSnapshot(
            state: map["state"] as? String ?? "",
            serverAddress: map["serverAddress"] as? String ?? "",
            activeTransport: map["activeTransport"] as? String ?? "Unknown",
            transportCount: (map["transportCount"] as? NSNumber)?.intValue ?? 0,
            peerRelayCount: (map["peerRelayCount"] as? NSNumber)?.intValue ?? 0,
            outboundBytes: (map["outboundBytes"] as? NSNumber)?.intValue ?? 0,
            inboundBytes: (map["inboundBytes"] as? NSNumber)?.intValue ?? 0,
            relayedUpBytes: (map["relayedUpBytes"] as? NSNumber)?.intValue ?? 0,
            relayedDownBytes: (map["relayedDownBytes"] as? NSNumber)?.intValue ?? 0,
            relayedPeers: relayedPeers,
            heartbeatPingsSent: (map["heartbeatPingsSent"] as? NSNumber)?.intValue ?? 0,
            relayTasksStarted: (map["relayTasksStarted"] as? NSNumber)?.intValue ?? 0,
            relayTasksEnded: (map["relayTasksEnded"] as? NSNumber)?.intValue ?? 0,
            connectedAtMs: (map["connectedAtMs"] as? NSNumber)?.intValue ?? 0,
            lastError: nonEmpty(map["lastError"]),
            peerShareError: nonEmpty(map["peerShareError"]),
            paths: paths,
            interception: interception)
    }
}

// MARK: - Formatting

/// Byte counts and live rates, same shapes as Android's home screen.
enum ByteFormat {
    static func bytes(_ bytes: Int) -> String {
        if bytes < 1024 { return "\(bytes) B" }
        if bytes < 1024 * 1024 {
            return String(format: "%.1f KB", Double(bytes) / 1024)
        }
        return String(
            format: "%.2f MB", Double(bytes) / (1024 * 1024))
    }

    static func rate(_ bytesPerSecond: Double) -> String {
        if bytesPerSecond < 1024 {
            return String(format: "%.0f B/s", bytesPerSecond)
        }
        if bytesPerSecond < 1024 * 1024 {
            return String(
                format: "%.1f KB/s", bytesPerSecond / 1024)
        }
        return String(
            format: "%.2f MB/s", bytesPerSecond / (1024 * 1024))
    }
}
