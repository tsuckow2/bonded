# Bonded macOS client

Xcode project for the macOS client (plan rows 4.94–4.98). Two targets:

- **Bonded** — the macOS app. In this slice (4.97) it is a minimal
  SwiftUI stub; the real UI (pairing, server config, status/paths,
  Relayed card) lands in slice 4.98. It embeds the extension below.
- **BondedTunnel** — the NetworkExtension PacketTunnelProvider. This
  is the tunnel: lifecycle (`startTunnel`/`stopTunnel`) + packet
  plumbing + tunnel settings, wired to the bonded-ffi C-ABI (4.95).

## Layout

```
macos/
  Bonded.xcodeproj/              Xcode project (app + extension targets)
  Bonded/
    BondedApp.swift              minimal app shell (stub; UI is 4.98)
    Bonded.entitlements          app sandbox + app group
    Info.plist
  BondedTunnel/
    PacketTunnelProvider.swift   start/stop, NEPacketTunnelFlow pumps,
                                 NETunnelNetworkSettings, app messages
    BondedFFI.swift              thin Swift wrapper over the C-ABI
    BondedTunnel.entitlements    networkextension + app group
    Info.plist                   NSExtension packet-tunnel entry
  Shared/
    Bonded-Bridging-Header.h     includes bonded_ffi_desktop.h
```

## How the provider works

- **Session**: `startTunnel` reads the provider configuration the
  app installed (`NETunnelProviderProtocol.providerConfiguration`:
  serverAddress, serverPublicKey, peerShare* keys, …), builds the
  one-JSON session config, and calls `bonded_session_start`. The
  session is process-global and single; session calls are serialized
  on a dedicated queue, per the FFI header's contract.
- **Packets**: there is no raw TUN fd on macOS — packets move through
  `NEPacketTunnelFlow`. Outbound (device → core): `readPackets` →
  `bonded_tun_handle_outbound`. Inbound (core → device): a 1 ms timer
  drains `bonded_tun_poll_inbound` into a single 64 KiB buffer
  allocated once and reused, and `writePackets` sends batches of up
  to 32 back to the flow. The provider never calls
  `bonded_tun_set_fd` (Unix-only, and not the macOS packet path).
- **Settings**: tunnel address 10.8.0.2/32 + fd00:10:8::2/128, MTU
  1420, default routes 0.0.0.0/0 + ::/0, DNS 10.8.0.1 — mirroring the
  Android client exactly. The DNS address is the in-tunnel gateway:
  the server blind-forwards 10.8.0.1:53 to its single required
  `dns_server` (192.168.1.1); that address is the server-side forward
  target, not the client-side DNS address.
- **Status**: the app asks for the snapshot with the `sendProviderMessage`
  message `"snapshot"`; the reply is the snapshot JSON (`relayedPeers`
  per-peer counters for the Relayed card, `paths[].peerId` for peer
  transports). Peer sharing is day one: the provider passes the
  peerShare* keys through the session start.
- **State**: device keys and session state live under the app group
  (`group.com.bonded.bonded-app`), so the app and the extension see
  one device identity. Unsigned/dev builds have no provisioned group
  and fall back to the extension's own Application Support directory
  (pairing state is then NOT shared — see the comment in
  PacketTunnelProvider.swift).

## Building

The extension links the Rust FFI staticlib, which cargo builds first:

```sh
cargo build -p bonded-ffi          # produces target/debug/libbonded_ffi.a
xcodebuild -project macos/Bonded.xcodeproj -target Bonded \
  -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

The project finds the staticlib via `LIBRARY_SEARCH_PATHS`
(`$(SRCROOT)/../target/debug` for Debug, `../target/release` for
Release) plus `-lbonded_ffi`, and the header via
`HEADER_SEARCH_PATHS` (`$(SRCROOT)/../crates/bonded-ffi/include`).
CI does exactly this (see the `macos-core` job in
`.github/workflows/build-artifacts.yml`).

The staticlib is self-contained apart from system libraries: rustc's
staticlib step merges the aws-lc and ring C objects into the archive
(verified by inspecting the archive's symbols: the only non-system
undefined symbol lives in an unreferenced object and never reaches
the link). The extension also links `NetworkExtension.framework` and
`libpcap.tbd` (for `pnet_datalink`'s macOS backend).

## Signing (not yet)

No Apple Developer account is available here, so nothing here can be
signed or submitted. The entitlements files are present for a real
build later; a signed build needs:

- `DEVELOPMENT_TEAM` set (currently empty) and the bundle IDs
  registered: app `com.bonded.bonded-app`, extension
  `com.bonded.bonded-app.tunnel`, app group
  `group.com.bonded.bonded-app`. These are unregistered placeholders
  today — confirm or change them when the Developer account is set up.
- The NetworkExtension entitlement approved by Apple for the team.
- The app group enabled for both the app and the extension App IDs.

CI builds unsigned (`CODE_SIGNING_ALLOWED=NO`) and never runs the
tunnel: a CI runner cannot load a NetworkExtension tunnel, so the
build is a compile + link check only. A live tunnel needs a real Mac.

## What is NOT here yet (slice 4.98)

App UI (pairing, server config, status/paths, Relayed card), the
`NETunnelProviderManager` plumbing that installs the provider
configuration, and App Store packaging. 4.98 will also share
`BondedFFI.swift` into the app target (it needs the FFI for pairing)
and link the staticlib there.
