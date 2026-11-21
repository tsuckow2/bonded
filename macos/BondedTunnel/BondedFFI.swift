// BondedFFI.swift — thin Swift wrapper over the bonded-ffi C-ABI (4.95).
//
// The C functions are visible through the target's bridging header
// (Shared/Bonded-Bridging-Header.h, which includes
// crates/bonded-ffi/include/bonded_ffi_desktop.h). This file is the
// Swift mirror of that header: same functions, same error convention
// (0 is success, negative is a BONDED_ERR_* code, detail in the
// last-error string).
//
// Threading: the header requires the session calls to be serialized
// against each other; packet I/O may run on a different thread. The
// provider keeps that contract by calling session functions
// (start/stop/snapshot/lastError) only from its serial session queue
// and packet functions (handleOutbound/pollInbound) only from its
// serial pump queue. This wrapper does no locking of its own.

import Foundation

/// Errors from the bonded-ffi C-ABI.
enum BondedError: Error, CustomStringConvertible {
    /// `bonded_session_start` failed (code + the last-error string).
    case sessionStart(code: Int32, detail: String)
    /// A pairing call failed (code + the last-error string).
    case pairingFailed(code: Int32, detail: String)
    /// The provider configuration is missing or malformed.
    case invalidConfiguration(String)
    /// The provider was deallocated mid-start.
    case providerDeallocated

    var description: String {
        switch self {
        case .sessionStart(let code, let detail):
            "bonded_session_start failed (code \(code)): \(detail)"
        case .pairingFailed(let code, let detail):
            "pairing failed (code \(code)): \(detail)"
        case .invalidConfiguration(let detail):
            "invalid provider configuration: \(detail)"
        case .providerDeallocated:
            "PacketTunnelProvider was deallocated during start"
        }
    }
}

/// Thin wrappers over the bonded-ffi C functions (4.95). Every
/// function here is a direct translation of the C call; the session
/// is process-global and single, so callers serialize the session
/// calls (see the file header).
enum BondedFFI {
    // MARK: - Session lifecycle

    /// Start a session from one JSON config object (see
    /// bonded_ffi_desktop.h for the key table). Stops any running
    /// session first.
    static func startSession(configJSON: String) -> Result<Void, BondedError> {
        let rc = configJSON.withCString { bonded_session_start($0) }
        guard rc == 0 else {
            return .failure(.sessionStart(code: rc, detail: lastError()))
        }
        return .success(())
    }

    /// Stop the running session, if any. No-op when there is none.
    static func stopSession() {
        _ = bonded_session_stop()
    }

    /// The session snapshot JSON, or nil when no session is running.
    /// Keys include state, paths, relayedPeers (one row per peer this
    /// device is providing for — the Relayed card in 4.98 reads it
    /// here), and the per-path peerId for peer transports.
    static func snapshot() -> String? {
        let needed = bonded_session_snapshot(nil, 0)
        guard needed >= 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(needed) + 1)
        let written = bonded_session_snapshot(&buffer, buffer.count)
        guard written >= 0 else { return nil }
        return String(cString: buffer)
    }

    /// The last error string, or "" when there is no recorded error.
    static func lastError() -> String {
        let needed = bonded_session_last_error(nil, 0)
        guard needed > 0 else { return "" }
        var buffer = [CChar](repeating: 0, count: Int(needed) + 1)
        let written = bonded_session_last_error(&buffer, buffer.count)
        guard written > 0 else { return "" }
        return String(cString: buffer)
    }

    // MARK: - Packet I/O
    //
    // Direction, from the core's perspective: "outbound" is a packet
    // read from the platform tunnel (device -> core); "inbound" is a
    // packet the core hands back to be written to the tunnel
    // (core -> device). The provider never calls bonded_tun_set_fd:
    // on macOS there is no raw TUN fd — packets move through
    // NEPacketTunnelFlow, so the queue functions below are the whole
    // packet path.

    /// Feed one outbound packet (as read from the tunnel) into the
    /// session. Returns false when no session is running (or its
    /// channel is closed) — the caller drops the packet.
    static func handleOutbound(_ packet: Data) -> Bool {
        guard !packet.isEmpty else { return false }
        let rc = packet.withUnsafeBytes { raw -> Int32 in
            guard let base = raw.baseAddress else { return -1 }
            return bonded_tun_handle_outbound(
                base.assumingMemoryBound(to: UInt8.self), raw.count)
        }
        return rc == 0
    }

    /// Drain one inbound packet into the caller's buffer. Returns the
    /// bytes written, 0 when the inbound queue is empty, or a negative
    /// BONDED_ERR_* code (no session / buffer too small — in the
    /// too-small case the packet stays queued). The provider passes a
    /// 65,535-byte buffer, the largest an IP packet can be, so
    /// too-small cannot happen.
    static func pollInbound(
        into buffer: UnsafeMutablePointer<UInt8>, capacity: Int
    ) -> Int32 {
        bonded_tun_poll_inbound(buffer, capacity)
    }

    // MARK: - Pairing
    //
    // Used by the app (4.98), not the provider: the app pairs the
    // device, the provider only runs the session. Included here so
    // this file is the complete Swift mirror of the header.

    /// Redeem an invite token against the server (pairing).
    static func redeemInvite(
        serverAddress: String,
        serverPublicKey: String,
        inviteToken: String,
        storageDir: String
    ) -> Result<Void, BondedError> {
        let rc = serverAddress.withCString { server in
            serverPublicKey.withCString { key in
                inviteToken.withCString { token in
                    storageDir.withCString { dir in
                        bonded_redeem_invite_token(server, key, token, dir)
                    }
                }
            }
        }
        guard rc == 0 else {
            return .failure(.pairingFailed(code: rc, detail: lastError()))
        }
        return .success(())
    }

    /// Mint a bound invite for another device (QR-pairing flow).
    static func mintInvite(
        serverAddress: String,
        serverPublicKey: String,
        storageDir: String,
        targetDeviceKey: String
    ) -> Result<String, BondedError> {
        let needed = serverAddress.withCString { server in
            serverPublicKey.withCString { key in
                storageDir.withCString { dir in
                    targetDeviceKey.withCString { target in
                        bonded_mint_invite_token(server, key, dir, target, nil, 0)
                    }
                }
            }
        }
        guard needed > 0 else {
            return .failure(.pairingFailed(code: needed, detail: lastError()))
        }
        var buffer = [CChar](repeating: 0, count: Int(needed) + 1)
        let written = serverAddress.withCString { server in
            serverPublicKey.withCString { key in
                storageDir.withCString { dir in
                    targetDeviceKey.withCString { target in
                        bonded_mint_invite_token(
                            server, key, dir, target, &buffer, buffer.count)
                    }
                }
            }
        }
        guard written > 0 else {
            return .failure(.pairingFailed(code: written, detail: lastError()))
        }
        return .success(String(cString: buffer))
    }

    /// This device's public key, creating the keypair on first run.
    static func devicePublicKey(storageDir: String) -> Result<String, BondedError> {
        let needed = storageDir.withCString {
            bonded_device_public_key($0, nil, 0)
        }
        guard needed > 0 else {
            return .failure(.pairingFailed(code: needed, detail: lastError()))
        }
        var buffer = [CChar](repeating: 0, count: Int(needed) + 1)
        let written = storageDir.withCString {
            bonded_device_public_key($0, &buffer, buffer.count)
        }
        guard written > 0 else {
            return .failure(.pairingFailed(code: written, detail: lastError()))
        }
        return .success(String(cString: buffer))
    }

    // MARK: - Path controls

    /// Pause (or resume) one direct path.
    static func pausePath(_ index: UInt32, paused: Bool) -> Bool {
        bonded_path_pause(index, paused ? 1 : 0) == 0
    }

    /// Tear one direct path's transport down; the path supervisor
    /// re-dials it in place.
    static func resetPath(_ index: UInt32) -> Bool {
        bonded_path_reset(index) == 0
    }

    /// Hand the live worker a new bind-address list (an interface
    /// appeared or vanished) without restarting the session.
    static func updatePaths(
        bindAddresses: [String], cellularBindAddresses: [String]
    ) -> Bool {
        let bindJSON = jsonArray(bindAddresses)
        let cellularJSON = jsonArray(cellularBindAddresses)
        let rc = bindJSON.withCString { bind in
            cellularJSON.withCString { cellular in
                bonded_paths_update(bind, cellular)
            }
        }
        return rc == 0
    }

    /// Hand the running worker a new traffic-rules table (JSON).
    /// Never fails — a malformed table falls back to the default
    /// engine.
    static func updateTrafficRules(_ trafficRulesJSON: String) {
        _ = trafficRulesJSON.withCString { bonded_traffic_rules_update($0) }
    }

    /// Hand the running worker the current per-transport grades
    /// (JSON array, one entry per transport vec index). Never fails.
    static func updatePathGrades(_ pathGradesJSON: String) {
        _ = pathGradesJSON.withCString { bonded_path_grades_update($0) }
    }

    /// Tell the worker whether the display is interactive.
    static func setDisplayInteractive(_ interactive: Bool) -> Bool {
        bonded_display_interactive(interactive ? 1 : 0) == 0
    }

    /// Tell the worker whether the device is in idle mode.
    static func setDeviceIdleMode(_ idle: Bool) -> Bool {
        bonded_device_idle_mode(idle ? 1 : 0) == 0
    }

    // MARK: - Helpers

    private static func jsonArray(_ strings: [String]) -> String {
        guard
            let data = try? JSONSerialization.data(
                withJSONObject: strings, options: []),
            let json = String(data: data, encoding: .utf8)
        else { return "[]" }
        return json
    }
}
