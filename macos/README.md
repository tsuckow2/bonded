# Bonded macOS client

Xcode project for the macOS client (plan rows 4.94–4.98). Two targets:

- **Bonded** — the macOS app (slice 4.98): SwiftUI UI — connect/
  disconnect, status, Paths / Peer connections / Relayed cards
  (mirroring Android), pairing (server config + redeem/mint
  invite through the FFI). It embeds the extension below and
  talks to it via `NETunnelProviderManager`.
- **BondedTunnel** — the NetworkExtension PacketTunnelProvider. This
  is the tunnel: lifecycle (`startTunnel`/`stopTunnel`) + packet
  plumbing + tunnel settings, wired to the bonded-ffi C-ABI (4.95).

## Layout

```
macos/
  Bonded.xcodeproj/              Xcode project (app + extension targets)
  Bonded/
    BondedApp.swift              app entry (owns the TunnelManager)
    ContentView.swift            main window: status, connect, Paths /
                                 Peer connections / Relayed cards
    SessionSnapshot.swift        snapshot JSON model (mirrors Android)
    TransportGrade.swift         per-transport grade tracker (port of
                                 Android's 4.50 grader)
    TunnelManager.swift          NETunnelProviderManager plumbing,
                                 snapshot poll, pairing (FFI)
    PairingView.swift            server config + pair/mint invite sheet
    Bonded.entitlements          app sandbox + app group
    Info.plist                   incl. ITSAppUsesNonExemptEncryption
    PrivacyInfo.xcprivacy        UserDefaults reason (CA92.1)
    Assets.xcassets/             AppIcon (fat-converge mark)
  BondedTunnel/
    PacketTunnelProvider.swift   start/stop, NEPacketTunnelFlow pumps,
                                 NETunnelNetworkSettings, app messages
    BondedFFI.swift              thin Swift wrapper over the C-ABI
    BondedTunnel.entitlements    networkextension + app group
    Info.plist                   NSExtension packet-tunnel entry
  Shared/
    Bonded-Bridging-Header.h     includes bonded_ffi_desktop.h
```

## How the app works

- **Connect**: the app installs the provider configuration from
  the saved server settings (`NETunnelProviderManager`) and asks
  the system to start the tunnel. The system asks the user to
  approve the VPN configuration on first use. The session itself
  runs in the extension process — the app never starts one.
- **Status**: the app polls the snapshot once a second while
  connected (`sendProviderMessage("snapshot")`) and feeds it to
  the grade tracker. Live rates come from snapshot byte deltas,
  like Android's `_sampleGraphs`.
- **Paths card**: direct transports with the grade chip (tap for
  the explainable detail: latency / stability / loss / bandwidth
  sub-scores, sample window, prior flag). Rows are labeled
  "Path N" plus the transport kind: the C-ABI snapshot has no
  network summaries, so the Wi-Fi/Cellular label Android shows
  is not available here (follow-up in the FFI).
- **Peer connections card**: peer-relay legs, listed separately,
  one row per leg (numbered within their peer), with the same
  grade chip. Hidden when there are no peer transports.
- **Relayed card**: aggregate relayed totals + live rates, then
  one row per served peer (short id, totals, live rate). No
  grade: provider legs are not transports and are never graded.
- **Pairing**: server address + server public key + invite token
  → `BondedFFI.redeemInvite` (same flow as Android). The device
  keypair lives in the shared storage dir, so the extension sees
  the same identity. Minting an invite for another device is the
  reverse direction (target device key → token). Pairing state
  is the app's record of a successful redeem (UserDefaults flag);
  the FFI has no "is paired" query.
- **Grades**: `TransportGradeTracker` is a faithful port of
  Android's per-transport grader (weights latency 30 /
  stability 30 / loss 20 / bandwidth 20; the 99 exploration
  prior for unmeasured legs; the same sampling rules). A macOS
  grade means the same thing as an Android grade.
- **Not in v1**: the path debug menu (pause/reset). Those act on
  the session, which lives in the extension process — the app's
  copy of the FFI has no session, so the calls would fail with
  NO_SESSION. Wiring them needs the provider's handleAppMessage
  to accept pause/reset messages (follow-up).

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

No Apple Developer account is available here, so nothing here can
be signed or submitted. What is in place for a real submission:

- Entitlements: app sandbox + app group (`Bonded.entitlements`),
  NetworkExtension packet-tunnel-provider + app group
  (`BondedTunnel.entitlements`). Bundle IDs: app
  `com.bonded.bonded-app`, extension `com.bonded.bonded-app.tunnel`,
  app group `group.com.bonded.bonded-app` — unregistered
  placeholders until the Developer account is set up.
- Privacy manifest (`Bonded/PrivacyInfo.xcprivacy`): the app uses
  UserDefaults for the server config, a required-reason API —
  declared with reason CA92.1 (app's own preferences). No other
  required-reason API is used.
- Export compliance (`ITSAppUsesNonExemptEncryption = true` in the
  app Info.plist): the tunnel uses non-exempt encryption
  (WireGuard, QUIC/TLS via the Rust core). App Store Connect will
  ask for export-compliance documentation on submission
  (self-classification for mass-market encryption).
- App icon (`Bonded/Assets.xcassets`, AppIcon): the adopted
  fat-trunk Converge mark, rendered at all macOS sizes from the
  512 px source. The 1024 px slot is a Lanczos upscale of the
  512 px PNG — replace it with a render of
  `bonded-logo-concepts/concept1b-converge-fat.svg` at 1024 px
  before submission for a crisp Retina icon.
- Version: marketing 1.0, build 1 (matching the first release).

What still needs Tom's Developer account:

- `DEVELOPMENT_TEAM` set (currently empty) and the bundle IDs +
  app group registered under that team.
- The NetworkExtension entitlement approved by Apple for the team.
- App Store Connect metadata (name, description, screenshots,
  privacy policy URL, support URL) and the export-compliance
  answers; TestFlight for the first external testers.
- A universal FFI (arm64 + x86_64 via lipo) if the app must run
  on Intel Macs — CI builds the Xcode project `-arch arm64`
  only, because the Rust FFI is built for the host arch.

CI builds unsigned (`CODE_SIGNING_ALLOWED=NO`) and never runs the
tunnel: a CI runner cannot load a NetworkExtension tunnel, so the
build is a compile + link check only. A live tunnel needs a real Mac.

## What is NOT here yet

- Path pause/reset from the app (needs a provider message;
  see ContentView.swift).
- Wi-Fi/Cellular labels on Paths rows (needs network summaries
  in the snapshot JSON; see SessionSnapshot.swift).
- A live tunnel test on a real Mac, and the App Store submission
  itself (both need Tom: a Mac, and the Developer account).
