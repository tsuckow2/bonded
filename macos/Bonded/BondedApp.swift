// BondedApp.swift — macOS app entry (slice 4.98).
//
// The app owns one TunnelManager (the NETunnelProviderManager
// plumbing + snapshot poll + pairing) and hands it to the content
// view. The tunnel itself lives in the PacketTunnelProvider
// extension; the app never starts a session — it installs the
// provider configuration and asks the system to start the tunnel.

import SwiftUI

@main
struct BondedApp: App {
    @StateObject private var tunnel = TunnelManager()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(tunnel)
        }
    }
}
