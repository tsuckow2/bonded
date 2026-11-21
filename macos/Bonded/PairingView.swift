// PairingView.swift — server config + device pairing (slice 4.98).
//
// The same flow Android uses: the server address + server public
// key identify the server, and an invite token (minted by an
// already-paired device, or handed out by the server operator)
// redeems this device into it. The redeem runs through the FFI
// (BondedFFI.redeemInvite) against the shared storage dir, so the
// extension sees the same device identity. Minting an invite for
// another device is the reverse direction, authenticated by this
// device's existing pairing.

import SwiftUI
import AppKit

struct PairingView: View {
    @EnvironmentObject var tunnel: TunnelManager
    @Environment(\.dismiss) private var dismiss

    @State private var serverAddress = ""
    @State private var serverPublicKey = ""
    @State private var peerShareEnabled = true
    @State private var peerShareMaxConsumers = 4
    @State private var inviteToken = ""
    @State private var targetDeviceKey = ""
    @State private var mintedToken: String?
    @State private var message: String?
    @State private var isPairing = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Pairing").font(.title2).bold()
            Form {
                Section("Server") {
                    TextField("Server address (host:port)", text: $serverAddress)
                    TextField("Server public key (base64)", text: $serverPublicKey)
                        .font(.system(.body, design: .monospaced))
                    Toggle("Provide uplinks to peers (peer sharing)", isOn: $peerShareEnabled)
                    Stepper(
                        "Max consumers: \(peerShareMaxConsumers)",
                        value: $peerShareMaxConsumers, in: 1...16)
                }
                Section("Pair this device") {
                    TextField("Invite token", text: $inviteToken)
                        .font(.system(.body, design: .monospaced))
                    HStack {
                        Button("Pair") { pair() }
                            .disabled(isPairing || inviteToken.isEmpty)
                            .keyboardShortcut(.defaultAction)
                        if isPairing { ProgressView().controlSize(.small) }
                        Spacer()
                        if tunnel.isPaired {
                            Text("Paired")
                                .foregroundStyle(.teal)
                                .fontWeight(.semibold)
                        } else {
                            Text("Not paired")
                                .foregroundStyle(.secondary)
                        }
                    }
                    if let key = tunnel.devicePublicKey {
                        HStack {
                            Text("Device key:")
                                .foregroundStyle(.secondary)
                            Text(String(key.prefix(16)) + "…")
                                .font(.system(.body, design: .monospaced))
                                .textSelection(.enabled)
                            Button("Copy") {
                                copyToClipboard(key)
                            }
                        }
                    }
                }
                Section("Invite another device") {
                    Text(
                        "Mint a bound invite for another device. Give " +
                        "the token to that device; it is single-use.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    TextField("Target device key (base64)", text: $targetDeviceKey)
                        .font(.system(.body, design: .monospaced))
                    HStack {
                        Button("Mint invite") { mint() }
                            .disabled(targetDeviceKey.isEmpty || !tunnel.isPaired)
                        if let token = mintedToken {
                            Text(token)
                                .font(.system(.body, design: .monospaced))
                                .textSelection(.enabled)
                            Button("Copy") { copyToClipboard(token) }
                        }
                    }
                }
            }
            .formStyle(.grouped)
            if let message = message {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            HStack {
                if tunnel.isPaired {
                    Button("Forget pairing", role: .destructive) {
                        tunnel.forgetPairing()
                        message = "Pairing forgotten on this device. " +
                            "Re-pair with a fresh invite to reconnect."
                    }
                }
                Spacer()
                Button("Save") { save() }
                Button("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(16)
        .frame(minWidth: 480, minHeight: 480)
        .onAppear {
            serverAddress = tunnel.serverConfig.serverAddress
            serverPublicKey = tunnel.serverConfig.serverPublicKey
            peerShareEnabled = tunnel.serverConfig.peerShareEnabled
            peerShareMaxConsumers = tunnel.serverConfig.peerShareMaxConsumers
        }
    }

    private func save() {
        tunnel.serverConfig = ServerConfig(
            serverAddress: serverAddress.trimmingCharacters(in: .whitespacesAndNewlines),
            serverPublicKey: serverPublicKey.trimmingCharacters(in: .whitespacesAndNewlines),
            peerShareEnabled: peerShareEnabled,
            peerShareMaxConsumers: peerShareMaxConsumers,
            diagnosticsUploadEnabled: tunnel.serverConfig.diagnosticsUploadEnabled)
        tunnel.installConfiguration { ok in
            message = ok
                ? "Server settings saved."
                : "Saving the VPN configuration failed — see the main window."
        }
    }

    private func pair() {
        save()
        isPairing = true
        message = nil
        tunnel.redeemInvite(token: inviteToken) { ok, detail in
            isPairing = false
            if ok {
                message = "Paired. You can connect now."
                inviteToken = ""
            } else {
                message = "Pairing failed: \(detail ?? "unknown error")"
            }
        }
    }

    private func mint() {
        tunnel.mintInvite(targetDeviceKey: targetDeviceKey) { token in
            mintedToken = token
            if token == nil {
                message = "Minting failed — see the main window."
            } else {
                message = "Invite minted. Give the token to the other device."
            }
        }
    }

    private func copyToClipboard(_ string: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }
}
