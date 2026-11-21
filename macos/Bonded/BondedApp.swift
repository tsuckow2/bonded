// BondedApp.swift — minimal macOS app shell (slice 4.97).
//
// The real UI — pairing, server config, status/paths, Relayed card —
// lands in slice 4.98. This stub exists so the Xcode project has an
// app target that embeds the PacketTunnelProvider extension and so CI
// can prove the project builds end to end. The app does not link the
// Rust FFI in this slice: it talks to the extension through
// NETunnelProviderManager, and pairing (which needs the FFI) is a
// 4.98 concern — that slice shares BondedFFI.swift into the app
// target and links the staticlib there.

import SwiftUI

@main
struct BondedApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    var body: some View {
        VStack(spacing: 8) {
            Text("Bonded").font(.title)
            Text("macOS client — the app UI lands in slice 4.98.")
                .foregroundStyle(.secondary)
        }
        .frame(minWidth: 320, minHeight: 200)
    }
}
