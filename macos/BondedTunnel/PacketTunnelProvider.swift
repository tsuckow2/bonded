// PacketTunnelProvider.swift — the NetworkExtension tunnel for the
// Bonded macOS client (slice 4.97).
//
// Shape (decided Tom, 2026-11-20): PacketTunnelProvider, App Store
// path. The tunnel lives in this system extension; the app (4.98)
// talks to it via NETunnelProviderManager and reads status through
// handleAppMessage below.
//
// Packet flow: on macOS there is NO raw TUN fd — packets move through
// NEPacketTunnelFlow. Outbound packets (device -> core) are read with
// readPackets and fed to the core with bonded_tun_handle_outbound;
// inbound packets (core -> device) are drained with
// bonded_tun_poll_inbound and written back with writePackets. The
// provider never calls bonded_tun_set_fd: that installs a TUN fd the
// worker writes to directly, and this platform has no such fd (the
// FFI's set_tun_fd is Unix-only and is NOT the macOS packet path).
//
// The extension runs as its own sandboxed process with a memory
// ceiling, so the packet path stays lean: one 64 KiB inbound buffer
// allocated once and reused, packets batched (up to 32) per
// writePackets call, no per-packet allocations beyond the packet Data
// itself. The Rust core's packet path takes the same care (the queue
// functions copy once, into the session's channel).
//
// Control-plane traffic (the session's own TLS connections to the
// server) does NOT go through the tunnel: the system never routes an
// extension process's own sockets through the tunnel it manages, so
// no per-socket protect() equivalent is needed (unlike Android,
// where the app process is explicitly excluded).
//
// Peer sharing is day one (Tom, 2026-11-20): the provider passes the
// peerShare* keys through the session start (below) and the snapshot
// exposes relayedPeers per-peer counters plus paths[].peerId for peer
// transports — the app reads both through handleAppMessage for the
// Relayed card in 4.98. No UI lives here.

import Foundation
import NetworkExtension
import os

/// The PacketTunnelProvider: lifecycle (start/stop) + packet plumbing
/// + tunnel settings, wired to the bonded-ffi C-ABI (4.95).
final class PacketTunnelProvider: NEPacketTunnelProvider {

    // MARK: - Tunnel constants
    //
    // Mirror the Android client (BondedVpnService): the tunnel
    // address is the same on every client — the server's gateway is
    // 10.8.0.1 and this client is 10.8.0.2 (the server assigns .2 to
    // every client; see peer_runtime.rs). The session config has no
    // tunnel-address key, so the Android convention is the source.
    // MTU 1420 matches Android as well.
    private enum Tunnel {
        static let ipv4Address = "10.8.0.2"
        static let ipv4Netmask = "255.255.255.255"
        static let ipv6Address = "fd00:10:8::2"
        static let ipv6Prefix: NSNumber = 128
        /// In-tunnel DNS gateway. The server blind-forwards 10.8.0.1:53
        /// to its single required dns_server (192.168.1.1) — that
        /// address is the server-side forward target, NOT the
        /// client-side DNS address. Android uses 10.8.0.1 too.
        static let dnsServer = "10.8.0.1"
        static let mtu: NSNumber = 1420
        /// Largest an IP packet can be. The inbound buffer is sized to
        /// this so bonded_tun_poll_inbound can never report
        /// BUFFER_TOO_SMALL (which would leave the packet queued and
        /// stall the drain loop on it forever).
        static let maxPacketSize = 65_535
        /// Inbound packets drained per writePackets call.
        static let inboundBatchSize = 32
    }

    /// Keys the app (4.98) puts in the provider protocol's
    /// providerConfiguration dictionary. Only serverAddress and
    /// serverPublicKey are required; the rest have the defaults shown.
    private enum ConfigKey {
        static let serverAddress = "serverAddress"
        static let resolvedServerAddress = "resolvedServerAddress"
        static let serverPublicKey = "serverPublicKey"
        static let protocols = "protocols"
        static let pathCount = "pathCount"
        static let bindAddresses = "bindAddresses"
        static let cellularBindAddresses = "cellularBindAddresses"
        static let peerShareEnabled = "peerShareEnabled"
        static let peerShareBindAddress = "peerShareBindAddress"
        static let peerShareAdvertiseIp = "peerShareAdvertiseIp"
        static let peerShareMaxConsumers = "peerShareMaxConsumers"
        static let peerShareRelayBandwidthKbps = "peerShareRelayBandwidthKbps"
        static let diagnosticsUploadEnabled = "diagnosticsUploadEnabled"
        static let diagnosticsUploadPeriodSecs = "diagnosticsUploadPeriodSecs"
        static let appVersionCode = "appVersionCode"
        static let batterySaver = "batterySaver"
        static let trafficRules = "trafficRules"
    }

    /// App group shared between the app and this extension. Keys and
    /// session state live under it, so the two sides see one device
    /// identity. The group must be registered under the Apple Developer
    /// account that signs the app; without provisioning the lookup
    /// returns nil and storageDirectory() falls back (see there).
    private static let appGroupIdentifier = "group.com.bonded.bonded-app"

    /// Inbound poll interval. The FFI has no blocking wait primitive,
    /// so the drain is a timer. 1 ms adds at most 1 ms of latency on
    /// the inbound path; each tick is a mutex lock plus an empty-queue
    /// check when idle, so the cost is a fraction of a percent of one
    /// core. Tunable if it ever shows up in profiles.
    private static let inboundPollInterval: DispatchTimeInterval = .milliseconds(1)

    private let log = Logger(
        subsystem: "com.bonded.bonded-app", category: "tunnel")

    /// Serializes the session calls (start/stop/snapshot), per the
    /// FFI header's contract.
    private let sessionQueue = DispatchQueue(
        label: "net.codingwell.bonded.session")

    /// Serializes the packet pumps (readPackets callbacks + the
    /// inbound drain timer). Packet I/O may run on a different thread
    /// from the session controls — this is that thread.
    private let pumpQueue = DispatchQueue(
        label: "net.codingwell.bonded.pump")

    /// Inbound drain timer, live while the tunnel is up. Owned by the
    /// pump queue (created, fired, and cancelled there).
    private var inboundTimer: DispatchSourceTimer?

    /// True while the pumps run. Touched only on the pump queue.
    private var running = false

    /// Inbound buffer, allocated once at provider creation and reused
    /// for every poll — never reallocated in the packet loop.
    private var inboundBuffer = [UInt8](
        repeating: 0, count: Tunnel.maxPacketSize)

    // MARK: - Lifecycle

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        log.info("starting tunnel")
        let configJSON: String
        do {
            let config = try readProviderConfiguration()
            let data = try JSONSerialization.data(
                withJSONObject: config, options: [])
            guard let json = String(data: data, encoding: .utf8) else {
                throw BondedError.invalidConfiguration(
                    "session config is not UTF-8")
            }
            configJSON = json
        } catch {
            log.error("invalid provider configuration: \(error)")
            completionHandler(error)
            return
        }

        let settings = networkSettings()
        sessionQueue.async { [weak self] in
            guard let self = self else {
                completionHandler(BondedError.providerDeallocated)
                return
            }
            switch BondedFFI.startSession(configJSON: configJSON) {
            case .failure(let error):
                self.log.error("session start failed: \(error)")
                completionHandler(error)
            case .success:
                // Settings first: the system creates the tunnel
                // interface, then the pumps start moving packets.
                // On failure the system tears the tunnel down; stop
                // the half-started session for hygiene.
                self.setTunnelNetworkSettings(settings) { error in
                    if let error = error {
                        self.log.error(
                            "tunnel network settings failed: \(error)")
                        self.sessionQueue.async { BondedFFI.stopSession() }
                        completionHandler(error)
                        return
                    }
                    self.pumpQueue.async { self.startPumps() }
                    self.log.info("tunnel up")
                    completionHandler(nil)
                }
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        log.info("stopping tunnel (reason: \(reason.rawValue))")
        // Pumps first (no more FFI packet calls), then the session.
        // The nested hop keeps the order across the two queues.
        pumpQueue.async { [weak self] in
            guard let self = self else {
                completionHandler()
                return
            }
            self.stopPumps()
            self.sessionQueue.async {
                BondedFFI.stopSession()
                completionHandler()
            }
        }
    }

    /// App messages (NETunnelProviderSession.sendProviderMessage).
    /// The app asks for the session snapshot with the UTF-8 message
    /// "snapshot"; the reply is the snapshot JSON. Anything else gets
    /// a nil reply. 4.98 uses this for the Paths and Relayed cards.
    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        guard
            let message = String(data: messageData, encoding: .utf8),
            message == "snapshot"
        else {
            completionHandler?(nil)
            return
        }
        sessionQueue.async {
            completionHandler?(BondedFFI.snapshot()?.data(using: .utf8))
        }
    }

    // MARK: - Configuration

    /// Build the session-start config JSON from the provider protocol
    /// the app installed (NETunnelProviderManager). Throws when a
    /// required key is missing.
    private func readProviderConfiguration() throws -> [String: Any] {
        guard
            let proto = protocolConfiguration as? NETunnelProviderProtocol
        else {
            throw BondedError.invalidConfiguration(
                "protocolConfiguration is not a NETunnelProviderProtocol")
        }
        let providerConfig = proto.providerConfiguration ?? [:]
        guard
            let serverAddress = providerConfig[ConfigKey.serverAddress]
                as? String,
            !serverAddress.isEmpty
        else {
            throw BondedError.invalidConfiguration(
                "providerConfiguration is missing serverAddress")
        }
        guard
            let serverPublicKey = providerConfig[ConfigKey.serverPublicKey]
                as? String,
            !serverPublicKey.isEmpty
        else {
            throw BondedError.invalidConfiguration(
                "providerConfiguration is missing serverPublicKey")
        }

        let storageDir = Self.storageDirectory()
        // Create it up front: the FFI writes keys/state there and
        // only creates it on some paths (the log ring, Android-only).
        try FileManager.default.createDirectory(
            atPath: storageDir, withIntermediateDirectories: true)

        // Peer sharing is day one: peerShareEnabled defaults to true
        // unless the app explicitly turns it off for this server.
        return [
            ConfigKey.serverAddress: serverAddress,
            ConfigKey.resolvedServerAddress:
                providerConfig[ConfigKey.resolvedServerAddress] as? String
                    ?? "",
            ConfigKey.serverPublicKey: serverPublicKey,
            ConfigKey.protocols:
                providerConfig[ConfigKey.protocols] as? String
                    ?? "h3,wireguard,wss",
            ConfigKey.pathCount:
                providerConfig[ConfigKey.pathCount] as? Int ?? 1,
            ConfigKey.bindAddresses:
                providerConfig[ConfigKey.bindAddresses] as? [String] ?? [],
            ConfigKey.cellularBindAddresses:
                providerConfig[ConfigKey.cellularBindAddresses] as? [String]
                    ?? [],
            ConfigKey.peerShareEnabled:
                providerConfig[ConfigKey.peerShareEnabled] as? Bool ?? true,
            ConfigKey.peerShareBindAddress:
                providerConfig[ConfigKey.peerShareBindAddress] as? String
                    ?? "",
            ConfigKey.peerShareAdvertiseIp:
                providerConfig[ConfigKey.peerShareAdvertiseIp] as? String
                    ?? "",
            ConfigKey.peerShareMaxConsumers:
                providerConfig[ConfigKey.peerShareMaxConsumers] as? Int ?? 4,
            ConfigKey.peerShareRelayBandwidthKbps:
                providerConfig[ConfigKey.peerShareRelayBandwidthKbps] as? Int
                    ?? 0,
            ConfigKey.diagnosticsUploadEnabled:
                providerConfig[ConfigKey.diagnosticsUploadEnabled] as? Bool
                    ?? false,
            ConfigKey.diagnosticsUploadPeriodSecs:
                providerConfig[ConfigKey.diagnosticsUploadPeriodSecs] as? Int
                    ?? 900,
            ConfigKey.appVersionCode:
                providerConfig[ConfigKey.appVersionCode] as? Int ?? 0,
            "storageDir": storageDir,
            ConfigKey.batterySaver:
                providerConfig[ConfigKey.batterySaver] as? Bool ?? false,
            ConfigKey.trafficRules:
                providerConfig[ConfigKey.trafficRules] as? [String: Any]
                    ?? [:],
        ]
    }

    /// The tunnel's network settings: this client's address, the
    /// default routes (everything through the tunnel, like Android's
    /// default mode — the local-traffic exclusion mode is an app-level
    /// setting for 4.98), and DNS via the in-tunnel gateway.
    private func networkSettings() -> NETunnelNetworkSettings {
        let settings = NETunnelNetworkSettings(
            tunnelRemoteAddress: Tunnel.dnsServer)
        settings.mtu = Tunnel.mtu
        let ipv4 = NEIPv4Settings(
            addresses: [Tunnel.ipv4Address],
            subnetMasks: [Tunnel.ipv4Netmask])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        // IPv6 capture, fail-closed, like Android: an IPv6 address on
        // the tunnel plus IPv6 routes, so IPv6 traffic enters the
        // tunnel instead of bypassing the VPN. The server does not
        // forward IPv6 today — captured v6 packets are dropped at the
        // server ingest gate — so captured v6 fails rather than leaks.
        let ipv6 = NEIPv6Settings(
            addresses: [Tunnel.ipv6Address],
            networkPrefixLengths: [Tunnel.ipv6Prefix])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6
        settings.dnsSettings = NEDNSSettings(servers: [Tunnel.dnsServer])
        return settings
    }

    /// Writable dir for device keys and session state. The app-group
    /// container is the real path (shared with the app, so the two
    /// sides see one device identity). Unsigned/dev builds have no
    /// provisioned group, so the lookup returns nil — the fallback is
    /// this process's own Application Support directory. The fallback
    /// paths differ per side (each process has its own container), so
    /// pairing state is NOT shared without a provisioned group; the
    /// fallback exists only so an unsigned build can start a session
    /// at all.
    private static func storageDirectory() -> String {
        if let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupIdentifier)
        {
            return container
                .appendingPathComponent("bonded", isDirectory: true).path
        }
        let support = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask).first
        let dir = support?.appendingPathComponent(
            "net.codingwell.bonded", isDirectory: true)
        return dir?.path ?? NSTemporaryDirectory()
    }

    // MARK: - Packet pumps

    /// Start the two pumps. Runs on the pump queue.
    private func startPumps() {
        running = true
        scheduleReadPacketBatch()
        let timer = DispatchSource.makeTimerSource(queue: pumpQueue)
        timer.schedule(
            deadline: .now(),
            repeating: Self.inboundPollInterval,
            leeway: .microseconds(500))
        timer.setEventHandler { [weak self] in
            guard let self = self, self.running else { return }
            self.drainInbound()
        }
        timer.resume()
        inboundTimer = timer
    }

    /// Stop the pumps. Runs on the pump queue.
    private func stopPumps() {
        running = false
        inboundTimer?.cancel()
        inboundTimer = nil
    }

    /// Outbound pump (device -> core): read a batch from the flow,
    /// feed each packet to the core, then read again. The completion
    /// hops onto the pump queue so the batch and the inbound drain
    /// never interleave.
    private func scheduleReadPacketBatch() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self else { return }
            self.pumpQueue.async {
                guard self.running else { return }
                for packet in packets where !packet.isEmpty {
                    if !BondedFFI.handleOutbound(packet) {
                        // No session (or its channel closed): drop the
                        // packet. This is expected during teardown.
                        self.log.debug(
                            "dropping outbound packet: no session")
                    }
                }
                self.scheduleReadPacketBatch()
            }
        }
    }

    /// Inbound pump (core -> device): drain the FFI queue into the
    /// reused buffer and write batches back to the flow. Runs on the
    /// pump queue, on the drain timer.
    private func drainInbound() {
        var packets = [Data]()
        packets.reserveCapacity(Tunnel.inboundBatchSize)
        var protocols = [NSNumber]()
        protocols.reserveCapacity(Tunnel.inboundBatchSize)
        while packets.count < Tunnel.inboundBatchSize {
            let count = inboundBuffer.withUnsafeMutableBytes { raw -> Int32 in
                guard let base = raw.baseAddress else { return 0 }
                return BondedFFI.pollInbound(
                    into: base.assumingMemoryBound(to: UInt8.self),
                    capacity: raw.count)
            }
            if count < 0 {
                // No session (expected during teardown) or, in theory,
                // buffer too small — impossible with a 65,535-byte
                // buffer, so any negative code just ends this tick.
                log.debug("inbound poll ended tick (code: \(count))")
                break
            }
            if count == 0 { break }
            let packet = Data(inboundBuffer[0..<Int(count)])
            // The flow needs the address family per packet; the IP
            // version nibble carries it.
            let isV6 = (packet[0] >> 4) == 6
            packets.append(packet)
            protocols.append(
                NSNumber(value: isV6 ? AF_INET6 : AF_INET))
        }
        if !packets.isEmpty {
            _ = packetFlow.writePackets(packets, withProtocols: protocols)
        }
    }
}
