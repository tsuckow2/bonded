// ContentView.swift — the macOS app's main window (slice 4.98).
//
// Mirrors android/lib/screens/home_screen.dart's core flows: a
// connect/disconnect control, session status, the Paths card
// (direct transports with grades), the Peer connections card
// (peer-relay legs, listed separately), and the Relayed for
// others card (aggregate + one row per served peer). The two
// panels stay separate — Tom decided 2026-11-20 not to merge
// them, because the rows carry different data (transports with
// grades vs provider-side byte counters, never graded).
//
// Data comes from the snapshot JSON the provider returns via
// handleAppMessage("snapshot"), polled once a second while
// connected. Grades come from TransportGradeTracker, the Swift
// port of Android's per-transport grader (plan 4.50).
//
// NOT in v1: the path debug menu (pause/reset). Android reaches
// it by long-pressing a path row, but pause/reset act on the
// session, which lives in the extension process — the app's copy
// of the FFI has no session, so those calls would fail with
// NO_SESSION. Wiring them needs the provider's handleAppMessage
// to accept pause/reset messages (follow-up, not this slice).
// The grade chip tap shows the grade detail instead.

import SwiftUI

struct ContentView: View {
    @EnvironmentObject var tunnel: TunnelManager
    @State private var showingPairing = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            statusHeader
            if !tunnel.appGroupAvailable {
                appGroupWarning
            }
            if let error = tunnel.lastError {
                errorBanner(error)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    PathsCard()
                    PeerConnectionsCard()
                    RelayedCard()
                }
            }
        }
        .padding(16)
        .frame(minWidth: 480, minHeight: 420)
        .sheet(isPresented: $showingPairing) {
            PairingView()
                .environmentObject(tunnel)
        }
        .onAppear {
            // Open pairing automatically when the device is not
            // paired yet, so first launch lands on the one thing
            // it needs.
            if !tunnel.isPaired {
                showingPairing = true
            }
        }
    }

    // MARK: - Header

    private var statusHeader: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Bonded").font(.title2).bold()
                Spacer()
                Button(tunnel.vpnStatus == .connected ? "Disconnect" : "Connect") {
                    if tunnel.vpnStatus == .connected {
                        tunnel.disconnect()
                    } else {
                        tunnel.connect()
                    }
                }
                .disabled(
                    tunnel.vpnStatus == .connecting
                        || tunnel.vpnStatus == .disconnecting
                        || tunnel.vpnStatus == .reasserting)
                .keyboardShortcut(.defaultAction)
            }
            Text(statusText)
                .foregroundStyle(.secondary)
            HStack(spacing: 4) {
                Text(serverLine)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Pairing…") { showingPairing = true }
            }
            if let key = tunnel.devicePublicKey {
                Text("Device key: \(String(key.prefix(8)))…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
    }

    private var statusText: String {
        switch tunnel.vpnStatus {
        case .invalid:
            return "Not configured"
        case .disconnected:
            return "Disconnected"
        case .connecting:
            return "Connecting…"
        case .connected:
            if let snapshot = tunnel.snapshot {
                return "Connected to \(snapshot.serverAddress) via \(snapshot.activeTransport)"
            }
            return "Connected"
        case .reasserting:
            return "Reconnecting…"
        case .disconnecting:
            return "Disconnecting…"
        @unknown default:
            return "Unknown state"
        }
    }

    private var serverLine: String {
        let address = tunnel.serverConfig.serverAddress
        let server = address.isEmpty ? "No server set" : address
        return "\(server) · \(tunnel.isPaired ? "Paired" : "Not paired")"
    }

    private var appGroupWarning: some View {
        Text(
            "App group not provisioned (unsigned build): the app and " +
            "the tunnel use separate storage, so pairing state is not " +
            "shared with the tunnel. A signed build with the app group " +
            "provisioned fixes this.")
            .font(.callout)
            .padding(8)
            .background(Color.yellow.opacity(0.15))
            .cornerRadius(6)
    }

    private func errorBanner(_ error: String) -> some View {
        Text(error)
            .font(.callout)
            .foregroundStyle(.red)
            .padding(8)
            .background(Color.red.opacity(0.08))
            .cornerRadius(6)
    }
}

// MARK: - Paths card

/// Direct transports, one row each: label, kind, RTT, loss,
/// bytes, grade chip, Active/Paused chips. Mirrors Android's
/// _PathRow. The network label is "Path N": the C-ABI snapshot
/// has no network summaries, so the Wi-Fi/Cellular label Android
/// shows is not available here (follow-up in the FFI).
struct PathsCard: View {
    @EnvironmentObject var tunnel: TunnelManager

    var body: some View {
        GroupBox(label: Text("Paths").font(.headline)) {
            VStack(alignment: .leading, spacing: 8) {
                if let snapshot = tunnel.snapshot {
                    if let loss = snapshot.lossRate {
                        Text("loss \(String(format: "%.1f%%", loss * 100))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if snapshot.directPaths.isEmpty {
                        Text("No direct paths")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(snapshot.directPaths, id: \.gradeKey) { path in
                        PathRow(
                            path: path,
                            grade: tunnel.gradeTracker.gradeFor(path.gradeKey))
                    }
                } else {
                    Text("No session — connect to see paths.")
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct PathRow: View {
    let path: PathStat
    let grade: TransportGrade?
    @State private var showingGradeDetail = false

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "arrow.triangle.2.circlepath")
                .foregroundStyle(path.active ? .teal : .gray)
            VStack(alignment: .leading, spacing: 2) {
                Text("Path \(path.pathIndex ?? -1)")
                    .fontWeight(.semibold)
                Text(detailLine)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let publicIp = path.publicIp {
                    Text("Public IP \(publicIp)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if let grade = grade {
                GradeChip(grade: grade, showingDetail: $showingGradeDetail)
            }
            if path.active {
                Text("Active")
                    .font(.caption)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.teal.opacity(0.15))
                    .cornerRadius(4)
            }
            if path.paused {
                Text("Paused")
                    .font(.caption)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.orange.opacity(0.15))
                    .cornerRadius(4)
            }
        }
        .padding(.vertical, 4)
    }

    private var detailLine: String {
        var parts: [String] = [path.kind]
        if path.lastRttMs > 0 {
            parts.append("\(path.lastRttMs) ms")
        }
        parts.append("loss \(path.lossDisplay)")
        parts.append(
            "↓ \(ByteFormat.bytes(path.inboundBytes)) · " +
            "↑ \(ByteFormat.bytes(path.outboundBytes))")
        return parts.joined(separator: " · ")
    }
}

// MARK: - Peer connections card

/// Peer-relay legs, listed separately from direct paths: one row
/// per leg (a provider with several paths yields several legs,
/// numbered within their peer). Legs are full transports for
/// spreading and failover; this list is only a presentation split.
/// Hidden when there are no peer transports.
struct PeerConnectionsCard: View {
    @EnvironmentObject var tunnel: TunnelManager

    var body: some View {
        if let snapshot = tunnel.snapshot, !snapshot.peerTransports.isEmpty {
            GroupBox(label: Text("Peer connections").font(.headline)) {
                VStack(alignment: .leading, spacing: 8) {
                    let legNumbers = legNumbersFor(snapshot.peerTransports)
                    ForEach(
                        Array(snapshot.peerTransports.enumerated()),
                        id: \.offset)
                    { index, path in
                        PeerRow(
                            path: path,
                            leg: legNumbers[index] ?? 1,
                            grade: tunnel.gradeTracker.gradeFor(path.gradeKey))
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private func legNumbersFor(_ paths: [PathStat]) -> [Int: Int] {
        var counts: [String: Int] = [:]
        var out: [Int: Int] = [:]
        for (index, path) in paths.enumerated() {
            let key = path.peerId ?? ""
            counts[key, default: 0] += 1
            out[index] = counts[key]
        }
        return out
    }
}

struct PeerRow: View {
    let path: PathStat
    let leg: Int
    let grade: TransportGrade?
    @State private var showingGradeDetail = false

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "person.2")
                .foregroundStyle(path.active ? .teal : .gray)
            VStack(alignment: .leading, spacing: 2) {
                Text("Peer \(shortId) · leg \(leg)")
                    .fontWeight(.semibold)
                Text(detailLine)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if let grade = grade {
                GradeChip(grade: grade, showingDetail: $showingGradeDetail)
            }
            if path.active {
                Text("Active")
                    .font(.caption)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.teal.opacity(0.15))
                    .cornerRadius(4)
            }
        }
        .padding(.vertical, 4)
    }

    private var shortId: String {
        String((path.peerId ?? "?").prefix(8))
    }

    private var detailLine: String {
        var parts: [String] = [path.kind]
        if path.lastRttMs > 0 {
            parts.append("\(path.lastRttMs) ms")
        }
        parts.append("loss \(path.lossDisplay)")
        parts.append(
            "↓ \(ByteFormat.bytes(path.inboundBytes)) · " +
            "↑ \(ByteFormat.bytes(path.outboundBytes))")
        return parts.joined(separator: " · ")
    }
}

// MARK: - Relayed card

/// Aggregate bandwidth others used through this device's paths
/// while it acted as a peer-share provider: totals plus the live
/// rate, same ↓/↑ orientation as Android (up = toward the
/// server, down = toward the peer). Shown once anything has been
/// relayed this session, or while a peer is being served (a
/// freshly accepted leg with no traffic yet still names its
/// peer). Below the totals, one row per served peer with its
/// identity and its own totals + live rate. No grade: provider-side
/// legs are not transports and are never graded.
struct RelayedCard: View {
    @EnvironmentObject var tunnel: TunnelManager

    var body: some View {
        if let snapshot = tunnel.snapshot,
           snapshot.relayedUpBytes > 0 || snapshot.relayedDownBytes > 0
            || !snapshot.relayedPeers.isEmpty
        {
            GroupBox(label: Text("Relayed for others").font(.headline)) {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Spacer()
                        Text(
                            "↓ \(ByteFormat.rate(tunnel.relayedDownRateBps))  " +
                            "↑ \(ByteFormat.rate(tunnel.relayedUpRateBps))")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    HStack(spacing: 16) {
                        RelayedTotal(
                            label: "To peers",
                            bytes: snapshot.relayedDownBytes)
                        RelayedTotal(
                            label: "To server",
                            bytes: snapshot.relayedUpBytes)
                    }
                    ForEach(snapshot.relayedPeers, id: \.peerId) { peer in
                        RelayedPeerRow(
                            peer: peer,
                            rate: tunnel.relayedPeerRates[peer.peerId])
                    }
                    Text("Provider legs are not transports and are never graded.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

struct RelayedTotal: View {
    let label: String
    let bytes: Int

    var body: some View {
        VStack {
            Text(ByteFormat.bytes(bytes))
                .font(.headline)
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}

struct RelayedPeerRow: View {
    let peer: RelayedPeer
    let rate: (up: Double, down: Double)?

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "person")
                .foregroundStyle(.teal)
            VStack(alignment: .leading, spacing: 2) {
                Text(peer.shortId)
                    .fontWeight(.semibold)
                Text(
                    "↓ \(ByteFormat.bytes(peer.downBytes)) · " +
                    "↑ \(ByteFormat.bytes(peer.upBytes))" +
                    rateLine)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.vertical, 4)
    }

    private var rateLine: String {
        guard let rate = rate else { return "" }
        return " · \(ByteFormat.rate(rate.down))/\(ByteFormat.rate(rate.up))"
    }
}

// MARK: - Grade chip

/// The grade chip (letter + total), tap for the explainable
/// detail: the sub-scores and their measurements, the sample
/// window, and whether the total is the exploration prior (99).
struct GradeChip: View {
    let grade: TransportGrade
    @Binding var showingDetail: Bool

    var body: some View {
        Button("\(grade.letter) · \(grade.total)\(grade.isPrior ? "*" : "")") {
            showingDetail = true
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
        .popover(isPresented: $showingDetail) {
            GradeDetailView(grade: grade)
                .padding(12)
                .frame(minWidth: 280)
        }
    }
}

struct GradeDetailView: View {
    let grade: TransportGrade

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("\(grade.letter) · \(grade.total)")
                .font(.headline)
            if grade.isPrior {
                Text(
                    "Exploration prior (99): not enough traffic yet to " +
                    "measure loss or bandwidth, so this transport is " +
                    "graded just below perfect until it gathers data.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            gradeLine(
                label: "Latency",
                score: grade.latencyScore,
                detail: grade.latencyDetail)
            gradeLine(
                label: "Stability",
                score: grade.stabilityScore,
                detail: grade.stabilityDetail)
            gradeLine(
                label: "Loss",
                score: grade.lossScore,
                detail: grade.lossDetail)
            gradeLine(
                label: "Bandwidth",
                score: grade.bandwidthScore,
                detail: grade.bandwidthDetail)
            Text(
                "Sampled \(formatSampledFor(grade.sampledForMs)) · " +
                "\(grade.sampleCount) samples")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func gradeLine(
        label: String, score: Double?, detail: String?
    ) -> some View {
        HStack {
            Text(label)
                .frame(width: 80, alignment: .leading)
            if let score = score {
                Text(String(format: "%.0f", score))
                    .frame(width: 36, alignment: .trailing)
                Text(detail ?? "")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("—")
                    .frame(width: 36, alignment: .trailing)
                Text("no data yet")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .font(.callout)
    }
}
