// TunnelManager.swift — the macOS app's side of the tunnel
// (slice 4.98).
//
// Owns the NETunnelProviderManager (installs the provider
// configuration the extension reads in startTunnel), the
// connect/disconnect control, the snapshot poll (the "snapshot"
// app message), and pairing (redeem / mint invite through the
// FFI). The app never starts a session itself — the session lives
// in the extension process; the app only calls the FFI pairing
// functions, which read/write the device keypair in the shared
// storage directory.
//
// Pairing state: the FFI has no "is paired" query, so the app
// records a successful redeem in UserDefaults (paired flag) —
// the same shape as Android, which stores pairing state in app
// settings after a successful redeem. The device keypair itself
// lives in the shared storage dir; the flag is only the UI's
// record that a redeem succeeded for the current server.

import Foundation
import NetworkExtension

/// The server this device pairs to, plus the peer-share switches
/// the provider passes through at session start. Persisted in
/// UserDefaults; the provider configuration is (re)installed from
/// these values whenever they change.
struct ServerConfig: Equatable {
    var serverAddress: String = ""
    var serverPublicKey: String = ""
    var peerShareEnabled: Bool = true
    var peerShareMaxConsumers: Int = 4
    var diagnosticsUploadEnabled: Bool = false

    static let defaultsKey = "bonded.serverConfig"
}

/// The tunnel manager: ObservableObject for the SwiftUI views.
final class TunnelManager: ObservableObject {
    /// Bundle id of the PacketTunnelProvider extension.
    static let tunnelBundleId = "com.bonded.bonded-app.tunnel"
    /// App group shared between the app and the extension.
    static let appGroupIdentifier = "group.com.bonded.bonded-app"
    /// How often the snapshot is polled while connected.
    static let pollInterval: TimeInterval = 1.0

    @Published private(set) var vpnStatus: NEVPNStatus = .invalid
    @Published private(set) var snapshot: SessionSnapshot?
    @Published private(set) var isPaired = false
    @Published private(set) var devicePublicKey: String?
    @Published private(set) var lastError: String?
    @Published private(set) var managerInstalled = false
    /// False on unsigned builds: the app group is not provisioned,
    /// so the app and the extension fall back to different
    /// per-process directories and pairing state is NOT shared.
    /// The UI says so plainly when this is false.
    @Published private(set) var appGroupAvailable = false
    /// Live session rates (bytes/s), from snapshot deltas.
    @Published private(set) var downRateBps: Double = 0
    @Published private(set) var upRateBps: Double = 0
    @Published private(set) var relayedDownRateBps: Double = 0
    @Published private(set) var relayedUpRateBps: Double = 0
    /// Live per-peer relay rates, keyed by consumer device key.
    @Published private(set) var relayedPeerRates: [String: (up: Double, down: Double)] = [:]

    @Published var serverConfig: ServerConfig {
        didSet { saveServerConfig() }
    }

    /// Per-transport grades, sampled from the poll tick.
    let gradeTracker = TransportGradeTracker()

    private var manager: NETunnelProviderManager?
    private var pollTimer: Timer?
    private var lastPollAt: Date?
    private var lastOutboundBytes: Int?
    private var lastInboundBytes: Int?
    private var lastRelayedUpBytes: Int?
    private var lastRelayedDownBytes: Int?
    private var lastRelayedPeerBytes: [String: (up: Int, down: Int)] = [:]

    /// Serializes the FFI pairing calls (the header requires
    /// session calls to be serialized; the app makes no session
    /// calls, but pairing calls share the same native state).
    private let ffiQueue = DispatchQueue(label: "net.codingwell.bonded.ffi")

    init() {
        self.serverConfig = Self.loadServerConfig()
        self.appGroupAvailable = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: Self.appGroupIdentifier) != nil
        self.isPaired = UserDefaults.standard.bool(forKey: "bonded.paired")
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(vpnStatusChanged),
            name: .NEVPNStatusDidChange,
            object: nil)
        loadManager()
        refreshDeviceKey()
    }

    // MARK: - Storage

    /// Writable dir for device keys and session state. Mirrors the
    /// provider's storageDirectory(): the app-group container when
    /// provisioned, else this process's Application Support dir.
    /// The fallback paths differ per process, so pairing state is
    /// NOT shared without a provisioned group.
    static func storageDirectory() -> String {
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

    private static func loadServerConfig() -> ServerConfig {
        guard
            let data = UserDefaults.standard.data(
                forKey: ServerConfig.defaultsKey),
            let dict = try? JSONSerialization.jsonObject(with: data)
                as? [String: Any]
        else { return ServerConfig() }
        return ServerConfig(
            serverAddress: dict["serverAddress"] as? String ?? "",
            serverPublicKey: dict["serverPublicKey"] as? String ?? "",
            peerShareEnabled: dict["peerShareEnabled"] as? Bool ?? true,
            peerShareMaxConsumers:
                (dict["peerShareMaxConsumers"] as? NSNumber)?.intValue ?? 4,
            diagnosticsUploadEnabled:
                dict["diagnosticsUploadEnabled"] as? Bool ?? false)
    }

    private func saveServerConfig() {
        let dict: [String: Any] = [
            "serverAddress": serverConfig.serverAddress,
            "serverPublicKey": serverConfig.serverPublicKey,
            "peerShareEnabled": serverConfig.peerShareEnabled,
            "peerShareMaxConsumers": serverConfig.peerShareMaxConsumers,
            "diagnosticsUploadEnabled": serverConfig.diagnosticsUploadEnabled,
        ]
        if let data = try? JSONSerialization.data(
            withJSONObject: dict, options: [])
        {
            UserDefaults.standard.set(data, forKey: ServerConfig.defaultsKey)
        }
    }

    // MARK: - Manager plumbing

    /// Load the saved manager, or create one. The manager is what
    /// the system shows in System Settings > VPN; installing it
    /// does not start the tunnel.
    func loadManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            // The completion can arrive off-main; all @Published
            // writes below happen on the main queue.
            DispatchQueue.main.async {
                guard let self = self else { return }
                if let error = error {
                    self.setError("loading VPN configuration: \(error)")
                    return
                }
                let existing = managers?.first { manager in
                    (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier == Self.tunnelBundleId
                }
                if let existing = existing {
                    self.manager = existing
                    self.managerInstalled = true
                    self.refreshStatus()
                } else {
                    self.installConfiguration()
                }
            }
        }
    }

    /// (Re)install the provider configuration from the current
    /// server config. Called when the server settings change and
    /// before the first connect.
    func installConfiguration(completion: ((Bool) -> Void)? = nil) {
        let protocolConfig = NETunnelProviderProtocol()
        protocolConfig.providerBundleIdentifier = Self.tunnelBundleId
        protocolConfig.serverAddress = serverConfig.serverAddress
        protocolConfig.providerConfiguration = [
            "serverAddress": serverConfig.serverAddress,
            "resolvedServerAddress": "",
            "serverPublicKey": serverConfig.serverPublicKey,
            "protocols": "h3,wireguard,wss",
            "pathCount": 1,
            "bindAddresses": [] as [String],
            "cellularBindAddresses": [] as [String],
            "peerShareEnabled": serverConfig.peerShareEnabled,
            "peerShareBindAddress": "",
            "peerShareAdvertiseIp": "",
            "peerShareMaxConsumers": serverConfig.peerShareMaxConsumers,
            "peerShareRelayBandwidthKbps": 0,
            "diagnosticsUploadEnabled": serverConfig.diagnosticsUploadEnabled,
            "diagnosticsUploadPeriodSecs": 900,
            "appVersionCode": 1,
            "batterySaver": false,
            "trafficRules": [:] as [String: Any],
        ]
        let manager = self.manager ?? NETunnelProviderManager()
        manager.protocolConfiguration = protocolConfig
        manager.isEnabled = true
        manager.localizedDescription = "Bonded"
        manager.saveToPreferences { [weak self] error in
            // The completion can arrive off-main; all @Published
            // writes below happen on the main queue.
            DispatchQueue.main.async {
                guard let self = self else { return }
                if let error = error {
                    self.setError("saving VPN configuration: \(error)")
                    completion?(false)
                    return
                }
                manager.loadFromPreferences { error in
                    if let error = error {
                        self.setError("reloading VPN configuration: \(error)")
                        completion?(false)
                        return
                    }
                    self.manager = manager
                    self.managerInstalled = true
                    self.refreshStatus()
                    completion?(true)
                }
            }
        }
    }

    // MARK: - Connect / disconnect

    /// Start the tunnel. Installs the current server configuration
    /// first when the manager is missing or stale. The system asks
    /// the user to approve the VPN configuration on first use.
    func connect() {
        guard !serverConfig.serverAddress.isEmpty,
              !serverConfig.serverPublicKey.isEmpty
        else {
            setError("Set the server address and public key first (Pairing).")
            return
        }
        guard isPaired else {
            setError("Pair this device first (Pairing).")
            return
        }
        lastError = nil
        installConfiguration { [weak self] ok in
            guard let self = self, ok else { return }
            guard let session = self.manager?.connection as? NETunnelProviderSession else {
                self.setError("No VPN session (manager not installed?).")
                return
            }
            do {
                try session.startVPNTunnel()
            } catch {
                self.setError("starting the tunnel: \(error)")
            }
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    @objc private func vpnStatusChanged() {
        refreshStatus()
    }

    private func refreshStatus() {
        let status = manager?.connection.status ?? .invalid
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let wasConnected = self.vpnStatus == .connected
            self.vpnStatus = status
            if status == .connected && !wasConnected {
                self.startPolling()
            } else if status != .connected && wasConnected {
                self.stopPolling()
            }
            if status == .disconnected || status == .invalid {
                self.snapshot = nil
            }
        }
    }

    // MARK: - Snapshot poll

    private func startPolling() {
        stopPolling()
        resetRateBaselines()
        pollTimer = Timer.scheduledTimer(withTimeInterval: Self.pollInterval, repeats: true) { [weak self] _ in
            self?.pollSnapshot()
        }
        pollSnapshot()
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
        resetRateBaselines()
    }

    private func resetRateBaselines() {
        lastPollAt = nil
        lastOutboundBytes = nil
        lastInboundBytes = nil
        lastRelayedUpBytes = nil
        lastRelayedDownBytes = nil
        lastRelayedPeerBytes.removeAll()
        downRateBps = 0
        upRateBps = 0
        relayedDownRateBps = 0
        relayedUpRateBps = 0
        relayedPeerRates.removeAll()
    }

    /// Ask the provider for the snapshot JSON ("snapshot" app
    /// message) and publish it. The provider replies nil when no
    /// session is running; a nil reply while connected leaves the
    /// previous snapshot in place.
    private func pollSnapshot() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        session.sendProviderMessage(Data("snapshot".utf8)) { [weak self] data in
            guard
                let self = self,
                let data = data,
                let json = String(data: data, encoding: .utf8),
                let snapshot = SessionSnapshot.parse(json)
            else { return }
            DispatchQueue.main.async {
                self.applySnapshot(snapshot)
            }
        }
    }

    private func applySnapshot(_ snapshot: SessionSnapshot) {
        let now = Date()
        if snapshot.connectedAtMs != self.snapshot?.connectedAtMs {
            gradeTracker.beginSession(snapshot.connectedAtMs)
        }
        gradeTracker.record(snapshot, now: now)

        // Live rates from byte deltas, like Android's _sampleGraphs.
        if let prevAt = lastPollAt {
            let dt = now.timeIntervalSince(prevAt)
            if dt > 0 {
                if let prev = lastOutboundBytes {
                    upRateBps = Double(snapshot.outboundBytes - prev) / dt
                }
                if let prev = lastInboundBytes {
                    downRateBps = Double(snapshot.inboundBytes - prev) / dt
                }
                if let prev = lastRelayedUpBytes {
                    relayedUpRateBps =
                        Double(snapshot.relayedUpBytes - prev) / dt
                }
                if let prev = lastRelayedDownBytes {
                    relayedDownRateBps =
                        Double(snapshot.relayedDownBytes - prev) / dt
                }
                var rates: [String: (up: Double, down: Double)] = [:]
                for peer in snapshot.relayedPeers {
                    if let prev = lastRelayedPeerBytes[peer.peerId] {
                        rates[peer.peerId] = (
                            up: Double(peer.upBytes - prev.up) / dt,
                            down: Double(peer.downBytes - prev.down) / dt)
                    }
                }
                relayedPeerRates = rates
            }
        }
        lastPollAt = now
        lastOutboundBytes = snapshot.outboundBytes
        lastInboundBytes = snapshot.inboundBytes
        lastRelayedUpBytes = snapshot.relayedUpBytes
        lastRelayedDownBytes = snapshot.relayedDownBytes
        lastRelayedPeerBytes = Dictionary(
            uniqueKeysWithValues: snapshot.relayedPeers.map {
                ($0.peerId, (up: $0.upBytes, down: $0.downBytes))
            })
        self.snapshot = snapshot
        if let error = snapshot.lastError {
            lastError = error
        }
    }

    // MARK: - Pairing (FFI, off the main thread)

    /// This device's public key, creating the keypair on first run.
    /// The keypair lives in the shared storage dir, so the
    /// extension sees the same identity.
    func refreshDeviceKey() {
        ffiQueue.async { [weak self] in
            let result = BondedFFI.devicePublicKey(
                storageDir: Self.storageDirectory())
            DispatchQueue.main.async {
                switch result {
                case .success(let key):
                    self?.devicePublicKey = key
                case .failure:
                    self?.devicePublicKey = nil
                }
            }
        }
    }

    /// Redeem an invite token against the server (pairing), the
    /// same flow Android uses: server address + server public key
    /// + token, keypair in the shared storage dir. On success the
    /// device is paired and the manager configuration is installed.
    func redeemInvite(
        token: String,
        completion: @escaping (Bool, String?) -> Void
    ) {
        let config = serverConfig
        let token = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !config.serverAddress.isEmpty,
              !config.serverPublicKey.isEmpty,
              !token.isEmpty
        else {
            completion(false, "Server address, public key, and invite token are all required.")
            return
        }
        ffiQueue.async { [weak self] in
            let result = BondedFFI.redeemInvite(
                serverAddress: config.serverAddress,
                serverPublicKey: config.serverPublicKey,
                inviteToken: token,
                storageDir: Self.storageDirectory())
            DispatchQueue.main.async {
                switch result {
                case .success:
                    self?.isPaired = true
                    UserDefaults.standard.set(true, forKey: "bonded.paired")
                    self?.refreshDeviceKey()
                    self?.installConfiguration()
                    completion(true, nil)
                case .failure(let error):
                    completion(false, error.description)
                }
            }
        }
    }

    /// Mint a bound invite for another device (QR-pairing flow),
    /// authenticated by this device's existing pairing. The token
    /// is single-use; hand it to the other device.
    func mintInvite(
        targetDeviceKey: String,
        completion: @escaping (String?) -> Void
    ) {
        let config = serverConfig
        let target = targetDeviceKey.trimmingCharacters(
            in: .whitespacesAndNewlines)
        guard !target.isEmpty else {
            setError("A target device key is required to mint an invite.")
            completion(nil)
            return
        }
        ffiQueue.async { [weak self] in
            let result = BondedFFI.mintInvite(
                serverAddress: config.serverAddress,
                serverPublicKey: config.serverPublicKey,
                storageDir: Self.storageDirectory(),
                targetDeviceKey: target)
            DispatchQueue.main.async {
                switch result {
                case .success(let token):
                    completion(token)
                case .failure(let error):
                    self?.setError("minting an invite: \(error)")
                    completion(nil)
                }
            }
        }
    }

    /// Forget the pairing record on this device. The keypair files
    /// stay (the server still has the registration); re-pairing
    /// with a fresh invite reuses the same device identity.
    func forgetPairing() {
        isPaired = false
        UserDefaults.standard.set(false, forKey: "bonded.paired")
    }

    private func setError(_ message: String) {
        DispatchQueue.main.async { [weak self] in
            self?.lastError = message
        }
    }
}
