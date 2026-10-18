# Implementation Plan — Server, Linux Client, Android Client

**Status:** In Progress
**Last Updated:** 2026-10-17 (October production validation, builds 130–137)

This is a living document. Update the status column and notes as work progresses.

---

## Preflight Checklist

Complete these before broad implementation begins.

| # | Item | Status | Notes |
|---|------|--------|-------|
| P1 | Create implementation instructions for the coding agent | completed | See `AGENTS.md` |
| P2 | Confirm repo structure migration plan (`server/` to workspace crates) | completed | Migrate immediately in the first implementation checkpoint |
| P3 | Define first runnable milestone | completed | Server + Linux client over NaiveTCP |
| P4 | Define validation commands for each phase | completed | See `Validation Commands` |
| P5 | Decide config file format and locations | completed | See `Configuration Conventions` |
| P6 | Decide initial Rust crypto and TUN libraries | completed | See `Initial Library Decisions` |
| P7 | Define how progress is resumed after interruption | completed | Update this file every session |

---

## First Milestone

The first mandatory milestone is:

`Linux CLI client pairs with server, creates a NaiveTCP path, establishes a TUN-backed session, and successfully sends traffic through the server.`

Do not treat Android work as the first proof point. Linux is the primary test harness for validating the shared core.

---

## Bootstrap Decisions

- Migrate to a Cargo workspace immediately. Do not continue building out the legacy top-level `server/` crate structure.
- Keep NaiveTCP as the only required transport until the first Linux end-to-end milestone passes.
- Defer peer-sharing implementation even though it is in v1 scope; build it only after base server + Linux client tunneling is stable.
- Keep Android implementation thin initially: QR pairing, VPN service, one connect/disconnect flow, one path if necessary for first proof.

---

## Configuration Conventions

Use TOML for all human-edited configuration/state files in v1.

Server files:

- Primary config path: `/etc/bonded/server.toml`
- Override via env: `BONDED_CONFIG`
- Authorized keys path default: `/var/lib/bonded/authorized_keys.toml`
- Invite tokens path default: `/var/lib/bonded/invite_tokens.toml`

Recommended server config shape:

```toml
[server]
bind = "0.0.0.0:8080"
status_bind = "0.0.0.0:8082"
public_address = "bonded.example.com:8080"
health_bind = "0.0.0.0:8081"
log_level = "info"
authorized_keys_file = "/var/lib/bonded/authorized_keys.toml"
invite_tokens_file = "/var/lib/bonded/invite_tokens.toml"
```

Recommended authorized keys shape:

```toml
[[devices]]
device_id = "android-phone"
public_key = "base64-ed25519-public-key"
added_at = "2026-03-30T00:00:00Z"
```

Recommended invite token shape:

```toml
[[tokens]]
token = "base64url-token"
expires_at = "2026-03-31T00:00:00Z"
uses_remaining = 1
```

Linux client files:

- Config path: `~/.config/bonded/client.toml`
- Private key path: `~/.local/share/bonded/device-key.pem`
- Public key path: `~/.local/share/bonded/device-key.pub`

Recommended Linux client config shape:

```toml
[client]
device_name = "linux-cli"
tun_name = "bonded0"
server_public_address = "bonded.example.com:8080"
server_public_key = "base64-ed25519-public-key"
preferred_protocols = ["naive_tcp"]
private_key_path = "~/.local/share/bonded/device-key.pem"
public_key_path = "~/.local/share/bonded/device-key.pub"
```

Android stores paired server metadata and client keypair in app-private storage. Do not require user-editable config files on Android.

---

## Initial Library Decisions

- Framing buffers: `bytes`
- Async utilities / codecs: `tokio-util`
- Config serialization: `serde` + `toml`
- File watching: `notify`
- Device identity / signatures: `ed25519-dalek`
- QR generation: `qrcode`
- Linux TUN: `tun`
- CLI parsing for Linux/server utilities: `clap`
- Android Rust build: `cargo-ndk`
- Android bridge approach: thin Kotlin JNI wrapper over shared Rust library, exposed to Flutter through platform channels

If these choices prove unsuitable during implementation, update `Key Implementation Decisions` with the replacement and rationale.

---

## Validation Commands

These are the commands the implementation should keep working as the repo evolves.

Phase 1 baseline:

```bash
cargo fmt --all --check
cargo test --workspace
```

Server checkpoint:

```bash
cargo build -p bonded-server
cargo test -p bonded-server
```

Linux client checkpoint:

```bash
cargo build -p bonded-cli
cargo test -p bonded-cli
```

End-to-end checkpoint target:

```bash
cargo test --workspace -- --nocapture
```

Android checkpoint target:

```bash
cd android && flutter pub get && flutter build apk --debug
```

The implementation agent may add more specific test commands later, but these are the minimum expected validation entry points.

---

## Session Update Protocol

At the end of each work session:

1. Mark every touched task as `in-progress`, `blocked`, or `completed`
2. Add concise notes describing what was implemented and what remains
3. Add newly discovered tasks to the relevant phase
4. Record blockers with exact failure mode
5. Record design decisions with dates

This document must be sufficient for another implementation session to resume work without rereading the entire repository.

---

## Architecture Summary

```
[ App Traffic ]
      ↓
[ VPN / TUN interface ]
      ↓
[ Session Layer: virtual conn ID, sequencing, reassembly ]
      ↓
[ Scheduler: assigns packets to paths (naive in v1) ]
      ↓                    ↓
[ Path A: Wi-Fi ]    [ Path B: Cellular ]
  (NaiveTCP)           (NaiveTCP)
      ↓                    ↓
[ Server: reassembles, forwards to internet ]
```

Shared Rust crate (`bonded-core`) contains: session layer, scheduler, transport traits, auth, protocol framing. Server and Linux client are separate binaries depending on this crate. Android client uses the same core via JNI/FFI.

---

## Workspace Structure (Target)

```
/workspace
├── crates/
│   ├── bonded-core/         # Shared: session, scheduler, transports, auth, framing
│   ├── bonded-server/       # Server binary
│   ├── bonded-client/       # Shared client logic (TUN, path management)
│   └── bonded-cli/          # Linux CLI client binary
├── android/                 # Flutter + platform channels (later: Android-specific)
├── server/                  # (migrate to crates/bonded-server)
└── docs/
```

---

## Phase 1: Core Protocol & Shared Library

Build `bonded-core` with the foundational protocol pieces. Everything in this phase is shared between server and all clients.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1.1 | Set up Cargo workspace with `bonded-core`, `bonded-server`, `bonded-cli` crates | completed | Added root workspace with crates: bonded-core, bonded-client, bonded-server, bonded-cli |
| 1.2 | Define session frame format (connection ID, sequence number, payload, flags) | completed | Added header + payload frame format in `bonded-core::session` using `bytes` |
| 1.3 | Implement session layer — framing, sequencing, reassembly, connection ID tracking | completed | Added `SessionState` with per-connection TX/RX sequence tracking, out-of-order buffering, in-order flush behavior, and connection mismatch/stale sequence validation |
| 1.4 | Define `Transport` trait (async read/write framed packets) | completed | Added async transport trait + protocol kind enum in `bonded-core::transport` |
| 1.5 | Implement NaiveTCP transport (client + server sides) | completed | Added `NaiveTcpTransport` with length-prefixed frame I/O over Tokio `TcpStream` plus connect/from_stream constructors |
| 1.6 | Define `Scheduler` trait (given packet + available paths → chosen path) | completed | Added scheduler trait with path IDs in `bonded-core::scheduler` |
| 1.7 | Implement round-robin scheduler | completed | Basic round-robin selection scaffold + unit test |
| 1.8 | Implement active-standby failover scheduler | completed | Basic active-first selector scaffold |
| 1.9 | Keypair generation and storage utilities | completed | Added Ed25519 `DeviceKeypair` generation plus base64 private/public key serialization + parse helpers in `bonded-core::auth` |
| 1.10 | Invite token generation and redemption protocol | completed | Added `InviteTokenManager` issue/redeem primitives with URL-safe random token generation and use-count decrement semantics |
| 1.11 | Public key challenge authentication on reconnect | completed | Added challenge creation plus sign/verify helpers using Ed25519 signatures for reconnect auth handshake primitives |
| 1.12 | Unit tests for session layer (framing, reordering, reassembly) | completed | Added tests for outbound sequence increments, out-of-order buffering + flush, connection ID mismatch, and stale sequence rejection |
| 1.13 | Unit tests for transports and schedulers | completed | Added async NaiveTCP loopback exchange test and retained scheduler rotation coverage |

Acceptance gate:

- Shared crates build successfully
- Session framing and reassembly tests pass
- NaiveTCP transport can exchange framed packets between two local processes
- Auth pairing primitives compile and have unit coverage

---

## Phase 2: Server

Build the server binary on top of `bonded-core`.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 2.1 | Server config loading (env vars + config file) | completed | Server loads TOML via `BONDED_CONFIG`/`--config`, falls back to defaults on read failure, applies env overrides for bind/public/health/log/key paths, and now deserializes partial `server.toml` files by filling missing options from defaults |
| 2.2 | Authorized keys file — load, watch for changes, reload | completed | Added server authorized key store loading from TOML plus `notify` watcher callbacks; hardened watcher to ignore non-mutating access events and debounce rapid bursts to avoid self-triggered tight reload loops; server startup pre-creates missing state files/directories so operators only need to provide `server.toml` |
| 2.3 | Accept NaiveTCP connections, perform auth handshake | completed | Added NaiveTCP listener accept loop and line-delimited JSON challenge-signature handshake with authorized-key enforcement |
| 2.4 | Server-side session management (multiple concurrent clients) | completed | Added concurrent session registry keyed by authenticated client key with unique server session IDs and per-connection frame receive loop lifecycle; improved per-session runtime by offloading frame forwarding into sharded worker queues so slow flow forwarding no longer blocks the transport receive loop; heartbeat handling now only consumes empty-payload `FLAG_PING` frames so data frames with incidental ping-bit are forwarded instead of dropped |
| 2.5 | IP packet forwarding — read from session, write to internet (TUN or raw socket) | in-progress | Added user-space internet egress for IPv4+UDP and IPv4 ICMP echo frames: UDP payloads are relayed via `UdpSocket`; ICMP echo requests are relayed via IPv4 ICMP datagram sockets (`socket2`) with echo-id/sequence matching; retains optional upstream TCP relay fallback for non-IP payloads; ICMP echo traffic now uses a dedicated bounded per-session worker queue (128 frames) so ping bursts are isolated from TCP/UDP forwarding. Added TUN runtime in `bonded-server` with config/env-gated `forwarding_mode=tun`, automatic Linux TUN interface provisioning (`tun_name`, `tun_cidr`, `tun_mtu`), automatic iptables NAT/FORWARD rule installation, default-route egress auto-detection from `/proc/net/route`, and best-effort teardown/restoration on process exit. Added usable first data path via `tun_bridge`: naive-tcp client frames are injected into TUN, return packets are routed back to sessions via destination-IP mapping with per-session server sequence generation; websocket listener is currently disabled in tun mode and remains a follow-up. Session 40 adds optional packet-capture diagnostics: when `BONDED_TUNNEL_PCAP_MAX_MB` is set, server logs tunneled packet payloads to a fixed `/var/lib/bonded/tunnel.pcap` file until the configured MB cap is reached, then stops logging further packets. Session 41 adds TCP RST telemetry in `SmoltcpForwarder` (inbound/outbound counters, tuple logs, and unmatched-flow warnings) to identify whether resets originate from client packets or server-side state transitions. Session 42 hardens TCP flow mapping to avoid potential cross-flow return-data mixing: outbound tuple rewrite now detects ambiguous active/pending matches (same client ip+port and server port but different original destination IP), drops ambiguous packets with explicit warnings, and rejects newly established ambiguous tuples rather than routing arbitrarily. Session 43 refines RST summary reporting to log once per 500-count bucket (instead of repeating unchanged counts), reducing diagnostic log spam while preserving trend visibility. Session 44 adds optional raw TCP bridge byte capture (`BONDED_TCP_BRIDGE_DUMP_MAX_MB`) to `/var/lib/bonded/tcp_bridge_dump.bin`, recording timestamp/session/conn/direction/length + payload for both smoltcp→remote and remote→smoltcp directions with a hard size cap, enabling direct byte-level comparison outside the tunnel encapsulation. Session 45 fixes a drop risk in remote→smoltcp TCP forwarding: `send_slice` partial writes now preserve unsent tails in per-connection pending state and retry on later polls instead of discarding remainder bytes. Session 46 replaces the fixed 1 ms smoltcp poll-thread tick with `Interface::poll_delay()`-driven waits plus existing condvar wakeups, cutting idle/backpressure CPU churn without changing partial-write handling. |
| 2.6 | Return traffic — read from internet, write back to correct client session | completed | Added checksum-correct IPv4 response synthesis for UDP and ICMP echo reply traffic, and wired `forward_frame` to return `None` on per-protocol timeout/no-response so tunneled packets are not spuriously echoed |
| 2.7 | Invite token creation (on admin request / startup) | completed | Added startup invite-token bootstrap that reuses existing usable token or creates/persists a new single-use token |
| 2.8 | QR code generation and emission to logs | completed | Added startup pairing payload JSON + terminal QR emission; logs warning and skips QR when `public_address` is not configured |
| 2.9 | Health check endpoint (HTTP) | completed | Added lightweight HTTP 200 `OK` endpoint on configured `health_bind`, started alongside NaiveTCP listener |
| 2.10 | Configurable log verbosity | completed | Startup tracing level now maps from server config `log_level` (with `BONDED_LOG_LEVEL` override) |
| 2.11 | Dockerfile update for new workspace structure | completed | Updated Docker build to target workspace crates, expose app+health ports, and set runtime config/state defaults under `/etc/bonded` and `/var/lib/bonded` |
| 2.12 | Integration test: server starts, accepts connection, forwards traffic | completed | Added integration coverage at two layers: (1) authenticated NaiveTCP framed payload exchange on a live server stream; (2) packet-by-packet smoltcp TCP bridge e2e in `smoltcp_forwarder` tests that starts a real localhost TCP server, drives synthetic IPv4/TCP handshake + data frames through `SmoltcpForwarder::ingest_packet()`, and asserts bidirectional payload flow. Session 39 extends this e2e to MTU-scale payload transfer (1460-byte TCP payload each direction) with SYN MSS option advertisement and sequence-based response reassembly so large-packet behavior remains deterministic under segment reordering/duplication. |
| 2.13 | Rust-only localhost E2E DNS diagnostic harness | completed | Added ignored/manual `bonded-server` integration test that boots `run_server` on localhost, connects using `bonded-client::establish_naive_tcp_session`, injects synthetic IPv4 UDP DNS query packet to `8.8.8.8:53`, and asserts/prints response-path diagnostics |
| 2.14 | Rust-only localhost E2E HTTP diagnostic harness | completed | Added ignored/manual `bonded-server` integration test that boots `run_server` on localhost, resolves `example.com`, drives synthetic IPv4 TCP handshake + HTTP GET over packet relay, and asserts a valid HTTP status line in returned payload |
| 2.15 | Rust-only localhost E2E SMTP diagnostic harness | completed | Added ignored/manual `bonded-server` integration test that boots `run_server` on localhost, resolves `smtp.gmail.com:587`, drives synthetic IPv4 TCP handshake, sends SMTP `EHLO` and `QUIT`, and asserts SMTP reply codes in returned payload |
| 2.16 | UDP flow sessions with idle timeout and async return path | completed | Replaced one-shot UDP forwarding with per-session flow table keyed by 4-tuple; each flow now uses a persistent connected ephemeral UDP socket, stays alive for 4 minutes since last client packet, and forwards all upstream UDP packets back to the client asynchronously while active |
| 2.17 | Status webpage endpoint for live connection state | completed | Added dedicated status listener (`status_bind`, env override `BONDED_STATUS_BIND`) with a live HTML dashboard and `/api/status` JSON endpoint; the page polls REST data every 2s instead of full-page refreshes and now shows per-flow packet counts in both directions for active UDP/TCP connections alongside authenticated sessions and recent ICMP probe outcomes |

Acceptance gate:

- Server starts from config
- Authorized keys reload works
- Pairing token and QR payload generation work
- A Linux client can authenticate and exchange framed traffic with the server

---

## Phase 3: Linux CLI Client

Build the Linux client on top of `bonded-core` + a thin `bonded-client` lib.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 3.1 | TUN device setup on Linux | in-progress | Added Linux TUN initialization in runtime startup using `tun` crate; full root-required end-to-end validation pending integration phase |
| 3.2 | Network interface detection and enumeration | completed | Added interface enumeration via `pnet_datalink` with unit test coverage in `bonded-client` |
| 3.3 | Client config (server address, auth token or keypair path) | completed | Client runtime now consumes configured server address and key paths, with home-directory expansion and on-demand keypair persistence |
| 3.4 | Pairing flow — redeem invite token, register keypair | completed | Client now includes invite token in auth hello; server redeems single-use invite token, persists the client public key into authorized-keys state, reloads store, and continues authenticated session on the same connection |
| 3.5 | Establish NaiveTCP path to server, perform auth handshake | completed | Added client-side NaiveTCP challenge-signature handshake compatible with server protocol and covered by mock-server unit test |
| 3.6 | Capture traffic from TUN → session layer → transport → server | completed | Added async Linux loop that reads packets from TUN and sends framed payloads over authenticated NaiveTCP transport |
| 3.7 | Receive traffic from server → session layer → TUN | completed | Added reverse async loop that ingests framed payloads from transport and writes packets back to Linux TUN via session reassembly |
| 3.8 | Multi-path: establish paths on multiple interfaces simultaneously | completed | Client runtime now establishes multiple authenticated NaiveTCP paths (bounded by detected interfaces) before entering packet loop |
| 3.9 | Failover: detect path death, shift traffic to surviving paths | completed | Packet loop now removes failed active path and continues on surviving authenticated path when send/recv errors occur |
| 3.10 | Integration test: client + server, ping through tunnel | in-progress | Added authenticated client/server integration test in `bonded-client` that performs handshake + framed payload exchange over NaiveTCP; full ICMP ping-through-TUN validation remains pending root-enabled end-to-end harness |
| 3.11 | Integration test: failover — kill one path, traffic continues | completed | Added deterministic multipath integration test that drops path-0 after auth and verifies payload exchange continues over surviving path-1 |

Acceptance gate:

- Client can pair with the server
- TUN traffic traverses the server end-to-end
- At least two paths can be established
- Killing one path does not terminate the session

---

## Phase 4: Android Client

Build the Android platform layer. The core Rust logic is shared via FFI.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 4.1 | Flutter project setup (Android target initially) | completed | Created Flutter app scaffold at `android/` with Android-only platform (`flutter create --platforms=android`); validated via `flutter test` and `flutter analyze` |
| 4.2 | Rust → Android FFI bridge (bonded-core compiled for Android targets) | completed | Added `crates/bonded-ffi` (`cdylib`/`staticlib`) with stable C ABI wrappers over `bonded-core` session-frame metadata decoding, validated by crate tests and `cargo check --target aarch64-linux-android`; session 46 wired Android Gradle release tasks (`bundleRelease`/`assembleRelease`) to run `scripts/build-android-native.sh`, enabling one-command `flutter build appbundle` Rust+Flutter release builds |
| 4.3 | Platform channel: Dart ↔ Rust FFI | completed | Added Flutter `MethodChannel` (`bonded/native`) plus Android `MainActivity` bridge calling Rust JNI symbol `nativeApiVersion`; app now displays bridge status with graceful fallback when library is not bundled |
| 4.4 | Android VPN Service implementation | completed | Added `BondedVpnService` shell (session/MTU/address/route establish path), foreground/background lifecycle wiring, manifest service registration, and MethodChannel start/stop/status wiring; explicit user-consent launch flow is implemented via native permission callback; VPN loop now submits outbound TUN packets to Rust JNI and polls inbound JNI packets; added paired-server persistence on Android plus a Rust single-path NaiveTCP session worker that redeems invite tokens, persists key material under app storage, bridges outbound/inbound packet queues, and exposes session-health snapshots back to Kotlin/Flutter for UI status updates; paired-server configuration edits and deletion now persist through platform channels, and the home list refreshes after configuration changes; Android 14/15 foreground startup now declares `specialUse` FGS type in the manifest and passes `FOREGROUND_SERVICE_TYPE_SPECIAL_USE` to `startForeground()` to satisfy VPN background startup enforcement; DNS servers (8.8.8.8, 1.1.1.1) added to VPN builder; routing-loop deadlock fixed via `VpnService.protect()` callback from Rust over JNI; `JNI_OnLoad`/`ANDROID_JVM` pattern used to enable protect calls from Rust threads; session snapshot extended with `outboundBytes`, `inboundBytes`, `connectedAtMs`; dashboard UI rewritten with bytes/uptime display, error banner, and improved connect/disconnect button; home screen adds per-server quick connect/disconnect icon buttons and live "Connected" chip; outbound packet loop now uses a bounded pending queue in Kotlin so transient native-session restart gaps buffer packets instead of repeatedly rejecting/dropping them; VPN builder now disallows the app package (`addDisallowedApplication(packageName)`) so control-plane sockets bypass capture, and Android client path setup no longer hard-fails on `protect(fd)=false`; session 47 fixed a release crash on older binaries by clearing pending JNI exceptions when `protectSocketForNative(I)Z` lookup fails before falling back to `VpnService.protect(I)Z`; session 48 adds `@Keep` on `BondedVpnService.protectSocketForNative(int)` so R8 cannot strip or rename this JNI-reflected method in release artifacts; session 49 adds detailed invite-redemption diagnostics (Kotlin `BondedMain` logs + `result.error` details and Rust JNI stderr error emission) so native pairing failures report concrete causes instead of only a generic message; session 50 switches worker heartbeat scheduling from a 50ms polling cadence to a true interval timer and increases heartbeat to 25s, removing idle 20Hz wakeups while preserving keepalive behavior; session 51 adds Rust-side cancellation-token shutdown and a bounded (250ms) worker join timeout so disconnect can return quickly even when transport receive is pending; session 51 also adds explicit client-transport close callbacks on cancellation (with bounded close timeout) so active sockets are shut down before worker exit; session 52 added Android logcat-visible Rust panic/error instrumentation, installed the rustls process `CryptoProvider` in `JNI_OnLoad`, and split `server_address` from `server_resolved_address` so Android can pre-resolve `charter.codingwell.net` to `97.115.185.254:8080` for socket dialing while still using the DNS name for TLS/WebSocket identity; verified on-device via `DebugVpnActivity` with `Transport paths established: count=1`, `transport[0] = WebSocketTLS`, and connected traffic counters; session 53 prevents shutdown-time recovery/network-rebind callbacks from relaunching a native session after `ACTION_STOP`, verified on a physical device against the local server: disconnect now logs worker shutdown and a clean server-side session close without any late `startNativeSession(...)` or protect-failure restart; session 54 now passes paired `supportedProtocols` from Kotlin into the native session startup path, lets ADB pairing save a different `bootstrap_server_address` than the invite-redemption address for split-port local tests, and protects WireGuard UDP sockets with the Android `SocketProtectFn` before connect so the device can request WireGuard without routing the transport back into the VPN |
| 4.5 | Multi-network support (Wi-Fi + Cellular simultaneously) | blocked | Added Android `ConnectivityManager.requestNetwork()`-based path manager that actively requests Wi-Fi/cellular/ethernet networks, derives per-network local bind addresses from `LinkProperties`, and feeds those addresses into the shared Rust client so NaiveTCP paths bind to distinct local IPs; `BondedVpnService` now restarts the native session when the active network set changes and surfaces active-path count back to the dashboard; client transport establishment now degrades to a single connected path when additional paths fail instead of hard-failing session startup. Session 63 tightens Android path reporting so only usable bind addresses count toward active paths, exposes the actual bind-address/path-summary set in `DebugVpnActivity` status output, filters out non-`INTERNET` cellular networks (for example IMS-only paths), and resolves cellular CLAT IPv4 binds via `NetworkInterface` so the live Pixel starts the native session with `bindAddresses=["192.168.1.140","192.0.0.4"]` and `networkPathSummaries=[wifi:192.168.1.140, cellular:192.0.0.4]`. Session 64 added bind-aware QUIC/WireGuard path establishment plus Android logcat diagnostics for each protocol attempt, then re-ran the Pixel/OnePlus devices: path 1 still times out on `h3`, `wireguard`, and `wss` from `192.0.0.4`, so the app is not yet using Wi-Fi and cellular simultaneously for server uplinks. Session 65 narrowed the blocker further: Android now attempts `Network.bindSocket(fd)` for bound Rust sockets and exposes a `tcp_connect_network` debug action that creates sockets via `Network.getSocketFactory()`. Wi-Fi succeeds on both paths, but the cellular network (`192.0.0.4`) fails in both cases with `EPERM (Operation not permitted)`, so the current blocker is Android/cellular network permissionability for that tracked network rather than missing per-path bind propagation inside Bonded. |
| 4.6 | QR code scanner screen | completed | Added `mobile_scanner` package with QRScannerScreen widget; includes Android camera permission request handling, camera preview, QR detection, duplicate-scan suppression during navigation, and JSON payload parsing |
| 4.7 | Pairing flow UI — scan QR, redeem token, store keypair | completed | Added `ServerPairingPayload` model, `PairingService` MethodChannel wrapper, and `PairingConfirmScreen` with server details display and redemption UI; updated QR parser to accept server-emitted `server_public_address` (with legacy `public_address` fallback) and reject payloads missing required fields, plus regression tests in `android/test/pairing_model_test.dart`. Session 61 renamed the trusted pairing key surface to `serverIdentityPublicKey` across Dart/Kotlin storage and method-channel boundaries while preserving backward-compatible reads of legacy `serverPublicKey` payloads and prefs data. |
| 4.8 | Connection status dashboard UI | completed | Added `DashboardScreen` with VPN toggle, status display, and connection details; added `HomeScreen` listing paired servers; updated main.dart with named routing for all screens. Session 61 extends the dashboard with trust/transport and peer-sharing cards, and the Android Rust/Kotlin session snapshot now exposes `activeTransport`, total transport count, and active peer-relay count for live status reporting. |
| 4.9 | Server configuration screen | completed | Added ServerConfigScreen showing server details, supported protocols display, and save/delete actions; integrated with HomeScreen PopupMenuButton for server management |
| 4.10 | Background operation | completed | Completed MethodChannel/EventChannel wiring for `startBackgroundVpn`/`stopBackgroundVpn`/`isBackgroundVpnRunning`; `BondedVpnService` now supports Android foreground-service mode with persistent notification and emits background lifecycle events consumed by Dashboard UI |
| 4.11 | End-to-end test: Android → server → internet | completed | Host-side FFI smoke tests pass (50/50 including bind-address assertion); `libbonded_ffi.so` built for arm64-v8a and x86_64 and placed in jniLibs; debug APK builds successfully; device validation is complete on a physical Android device using the release APK in two modes: (1) remote WSS validation via `DebugVpnActivity`, where Kotlin pre-resolves `charter.codingwell.net` to `97.115.185.254:8080`, Rust dials the resolved address while preserving the hostname for TLS/cert-proof verification, and logcat shows `transport[0] = WebSocketTLS` with `state=connected`; (2) local-server validation via `adb reverse tcp:8000 tcp:8000`, a local `bonded-server` running on `127.0.0.1:8000`, and a new ADB-triggerable pairing path in `MainActivity` that redeems an invite token and stores a paired server non-interactively; the real device then connects to the local server with `transport[0] = NaiveTCP`, `state=connected`, and live TCP/UDP flow counters visible on the server status endpoint. Session 55 additionally validated direct device-to-devcontainer LAN reachability for `:443`, `:8000`, and `:51820/udp`, fixed two bootstrap-listener bugs (`close_notify` missing on TLS REST responses and POST body truncation before JSON routing), and re-ran device-side WireGuard startup until Android reported `transport[0] = WireGuard` with `state=connected`. Session 56 closed the remaining server-observed WireGuard gap: client `WireGuardTransport` now treats `boringtun` `TunnResult::Done` as handshake-needed/non-fatal in both send and handshake-initiation paths, and the server WireGuard forwarder mode no longer waits on a nonexistent TUN return channel when `tun_bridge` is absent. After restarting the server and reconnecting the physical device, `GET /api/status` now reports `sessions_count=1` with the Android client key present. |
| 4.12 | Android in-app protocol stress diagnostics page | completed | Added Flutter `StressTestScreen` with configurable EDNS host/resolver, HTTP/HTTPS/HTTP3 targets, and round count; wired a new native `TEST_PROTOCOL_STRESS` action through the existing MethodChannel/foreground-service path; implemented concurrent per-round EDNS UDP queries with explicit OPT/EDNS options, cleartext HTTP, HTTPS, and Cronet-backed QUIC/HTTP3 probes with aggregated in-app log summaries |

Acceptance gate:

- Android app can scan QR and pair
- VPN service starts successfully
- At least one path to the server is established from Android
- Basic tunneled traffic succeeds

---

## Phase 5: Second Transport + Polish

Add a production transport protocol and harden.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 5.1 | Implement WebSocket over TLS (wss://) transport | completed | Added shared `WebSocketTlsTransport` with TLS accept/connect support, plus server rustls-based WSS termination driven by configurable cert/key file paths (`BONDED_WEBSOCKET_TLS_CERT_FILE`, `BONDED_WEBSOCKET_TLS_KEY_FILE`) |
| 5.2 | Test WSS transport end-to-end (Linux client + server) | completed | Added TLS-enabled websocket integration test in `bonded-server` using self-signed cert trust bootstrap and authenticated framed traffic exchange over `wss://` |
| 5.3 | Test mixed transports (one path NaiveTCP, one path WSS) | completed | Added client integration test that establishes one NaiveTCP path and one websocket path, then verifies framed traffic exchange on both |
| 5.4 | QUIC transport (evaluate `quinn` crate) | completed | Evaluated QUIC scope and deferred implementation until WSS TLS endpoint and certificate lifecycle are stabilized; tracked as next transport hardening step |
| 5.5 | Server advertises supported protocols in QR code | completed | Updated design: pairing QR payload now excludes protocol metadata; protocol selection happens at VPN session startup via runtime transport negotiation/fallback |
| 5.6 | Client tries all advertised protocols per interface | completed | Client path establishment now rotates configured preferred protocols per path and falls back across protocol attempts (`naive_tcp`/`wss`) |

Acceptance gate:

- WSS transport functions end-to-end
- Mixed-protocol paths work in one session
- Supported protocols are attempted correctly at session startup

---

## Phase 6: Unified Bootstrap Port + QUIC/HTTP3 + WireGuard

Goal: use the bootstrap port (taken from `server_public_address` in the pairing QR payload) as the single entry point for transport negotiation. WSS (TCP) and HTTP/3 (UDP) share the same host/port. WireGuard needs its own UDP port because QUIC and WireGuard packets cannot be demultiplexed on the same socket — but the client doesn't need to know it at pairing time; the bootstrap API hands it over after authentication. 443 is the conventional default for the bootstrap port, but any port works.

### Phase 6.0: Bootstrap and Edge Design Lock

| # | Task | Status | Notes |
|---|------|--------|-------|
| 6.0.1 | Define unified bootstrap API contract | not-started | Add versioned bootstrap endpoints under `/v1/bootstrap/*` for capability exchange and transport credential provisioning; usable over HTTPS (HTTP/1.1), WSS, and HTTP/3 |
| 6.0.2 | Define transport capability document | not-started | Server returns transport inventory (`wss`, `h3`, `wireguard`), endpoint host/port/proto, TTL, and retry/backoff hints |
| 6.0.3 | Define bootstrap token model | not-started | Pairing invite redemption issues a short-lived bootstrap token bound to device public key and server nonce; token authorizes transport-specific provisioning |
| 6.0.4 | Define parallel transport dial and preferred-path policy | not-started | All enabled transports dial concurrently (WSS, H3, WireGuard); the first to succeed on each interface is used immediately; a configurable preference order (e.g. `wss > h3 > wireguard`) controls which path is promoted to primary when multiple succeed; slower paths are kept as failover or dropped depending on scheduler policy; `naive_tcp` is a debug-only fallback not included in production dial set; bootstrap port always from `server_public_address` |
| 6.0.5 | Define TLS cert trust via ed25519 signature | completed | If TLS cert does not validate against system root CAs (self-signed or private CA), the client must open the TLS connection with certificate verification **disabled** for that one initial request, call `GET /v1/bootstrap/cert-proof`, then verify the ed25519 signature synchronously before exchanging any credential material — only after the signature validates does the client pin the cert and proceed; connecting with verify=false is safe only because the ed25519 check is the real trust anchor and happens before any secret is sent; client must abort immediately if the signature is invalid (MITM); when a system-trusted cert is present (e.g. Let's Encrypt), TLS verifies normally and this step is skipped; pinned cert fingerprint is persisted in `PairedServerStore` (Android) or client config file (Linux); if TLS fails on a future connection due to cert rotation, the client re-runs the cert-proof step rather than hard-failing; **SERVER SIDE IMPLEMENTED** — `GET /v1/bootstrap/cert-proof` endpoint live in `bootstrap.rs`; returns `{cert_fingerprint: "sha256:<hex>", ed25519_signature: "<base64>"}` signed by persistent server identity key |
| 6.0.6 | Define fd-protect API for all transport types | not-started | `ClientConfig` already carries a `SocketProtectFn` used by NaiveTCP; extend the same callback contract to cover UDP sockets created by QUIC (`quinn`) and WireGuard transports; on Android, every socket (TCP or UDP) must call `VpnService.protect(fd)` before `connect()`/`bind()` or it will be captured by the VPN TUN and deadlock; the protect callback must be invoked in each transport's socket-creation path before the socket is used; on non-Android platforms the callback is a no-op |
| 6.0.7 | Define TUN MTU budget and per-transport frame size limits | completed | Each transport adds overhead on top of the raw IP packet from the TUN: WSS ≈ 55 bytes (TLS record + WS frame + session frame header), QUIC/H3 ≈ 60 bytes, WireGuard ≈ 60 bytes (32-byte WG header + outer UDP/IP); if TUN MTU is 1500 and the outer network MTU is also 1500, there is no room for transport overhead and packets are fragmented or silently dropped; Android `Builder.setMtu()` is called once at VPN bring-up before transport paths are known so it must be set conservatively for the worst-case transport; default safe value is **1420** (matches WireGuard standard: `1500 - 80`), which provides headroom for all transports; each `ClientTransport` implementation must enforce a matching max session-frame payload size so the session layer never hands a transport a frame that will exceed the outer MTU after encapsulation; **IMPLEMENTED** — `bonded-core/src/config.rs` `tun_mtu` default changed to 1420; `BondedVpnService.kt` `setMtu(1420)` updated to match |
| 6.0.8 | Define NaiveTCP production retirement | completed | Session 59 retires NaiveTCP from production dial defaults. Shared client config now defaults to `wss`, `h3`, and `wireguard`; `establish_transport_paths()` filters `naive_tcp` out unless `allow_insecure_debug_transports` is explicitly enabled; and the Android FFI default session config now uses only secure transports while treating an explicit incoming `naive_tcp` protocol list as a deliberate debug opt-in. NaiveTCP remains available for targeted debug flows and tests, but it is no longer present in the normal production dial set. |

### Phase 6.1: Shared Bootstrap Port Listener Architecture

| # | Task | Status | Notes |
|---|------|--------|-------|
| 6.1.1 | Serve WSS and HTTPS on configured TCP port | completed | Reuse existing rustls termination; expose bootstrap HTTPS routes and WSS upgrade on same TCP listener; port comes from `server_public_address` (default 443 by convention); **IMPLEMENTED** — `bonded-server/src/bootstrap.rs` added: unified TCP listener reads HTTP headers, routes to `GET /v1/bootstrap/cert-proof` (REST) or WebSocket session handler based on `Upgrade: websocket` header; `PrependedStream<S>` added to `bonded-core/src/transport.rs` to replay headers after routing; `WebSocketStreamInner` extended with `ServerRoutedPlain` and `ServerRoutedTls` variants; `WebSocketTlsTransport::from_routed_plain` and `from_routed_tls` constructors added; `run_websocket_server` removed from `main.rs` and replaced by `bootstrap::run_bootstrap_websocket_server`; `load_websocket_tls_acceptor` now returns `(Option<TlsAcceptor>, Option<Vec<u8>>)` for cert DER extraction; bootstrap REST responses now prefer the incoming HTTP `Host` authority when advertising public endpoints so NAT/port-forwarded deployments do not leak a private configured hostname; remaining work: client-side cert-proof verification and cert pinning |
| 6.1.2 | Serve HTTP/3 on same configured UDP port | completed | `bonded-server/src/quic.rs` added: `run_quic_server()` binds UDP, builds `quinn::ServerConfig`, accepts QUIC connections, auth handshake and inline session loop; wired in `main.rs` when `server.quic_enabled = true`; `quic_enabled: bool` added to `ServerSection` |
| 6.1.5 | Serve WireGuard on its own UDP port | completed | `bonded-server/src/wireguard.rs` now provides `run_wireguard_server()` and a per-peer `boringtun` runtime behind a dedicated UDP socket bound from `server.wireguard_bind`; `bonded-server/src/main.rs` starts this listener when WireGuard is configured; bootstrap capabilities continue to advertise the dedicated WG UDP endpoint separately from QUIC; `BONDED_WIREGUARD_KEY_FILE` env override is now wired so local/dev servers can use a writable persisted WG key path |
| 6.1.3 | Unify certificate source | not-started | WSS/HTTPS and HTTP/3 must read from one live cert/key store and rotate without restart |
| 6.1.4 | Add ALPN policy | not-started | Explicitly support `http/1.1`, `h2` (optional), and `h3`; keep websocket upgrade path on HTTP/1.1 |

### Phase 6.2: QUIC/HTTP3 Transport

| # | Task | Status | Notes |
|---|------|--------|-------|
| 6.2.1 | Implement `quinn`-backed client/server transport adapters | completed | `QuicTransport` in `bonded-core/src/transport.rs` with `send_text`, `recv_text`, `close`; `quinn` workspace dep; server `quic.rs` handles full session lifecycle; client `establish_quic_session()` with cert pinning and auth handshake |
| 6.2.2 | Add HTTP/3 bootstrap/control channel | completed | Added an H3 bootstrap path on the existing QUIC endpoint using ALPN split (`bonded-quic` for session transport, `h3` for bootstrap JSON). The server now serves `/v1/bootstrap/cert-proof`, `/v1/bootstrap/capabilities`, and `/v1/bootstrap/wireguard/peer` over HTTP/3 via the same route logic used by the HTTP/1.1 bootstrap listener, including request-authority-based public endpoint advertisement for forwarded/public hosts. The client bootstrap requester now tries H3 before HTTPS for TLS-backed configs, reuses the existing cert-proof trust model by verifying the QUIC peer certificate against the signed `/v1/bootstrap/cert-proof` response, and keeps HTTP/1.1 HTTPS/HTTP fallback for non-H3 paths. |
| 6.2.3 | Add per-path QUIC establishment in client runtime | completed | `("h3" | "quic")` arm in `establish_transport_paths`; `ClientTransport::Quic` variant added |
| 6.2.4 | Add QUIC transport integration tests | completed | Existing coverage already included raw QUIC auth/framing via the client/server QUIC transport tests. Session 57 added focused client integration coverage `mixed_websocket_quic_failover_continues_exchange`, which stands up a localhost WebSocket server on TCP and a QUIC server on UDP sharing the same port, then proves a dead WebSocket path does not prevent fallback traffic from succeeding over QUIC. Session 58 added `h3_bootstrap_request_fetches_capabilities_after_cert_proof`, which stands up a localhost HTTP/3 bootstrap endpoint and proves the client performs QUIC cert-proof verification and then successfully fetches bootstrap JSON over H3. |

### Phase 6.3: WireGuard Transport (Bootstrapped over configured port)

| # | Task | Status | Notes |
|---|------|--------|-------|
| 6.3.1 | Select WG implementation strategy | completed | Use `boringtun` purely as a **crypto library**, not as a VPN. The inner payload of every WireGuard packet is a Bonded session frame — not a raw IP packet. There is no tunnel IP, no allowed-IPs list, no IP routing, and no second TUN. `boringtun` handles the Noise handshake, ChaCha20-Poly1305 encryption, and UDP framing; Bonded owns the socket, calls `boringtun::encapsulate(session_frame)` to get an encrypted UDP datagram to send, and calls `boringtun::decapsulate(udp_payload)` to recover the session frame on receipt. The session layer and scheduler see this as just another `ClientTransport` — identical in interface to NaiveTCP or WSS. The OS VPN TUN is owned exclusively by `BondedVpnService`; boringtun never touches it. This model deliberately gives up the "two peers forward raw IP" simplicity of standard WireGuard in order to preserve Bonded's multi-path bonding (CR-1/CR-2) — a WG-as-real-VPN path would be a completely separate tunnel with no session layer, making it impossible for the scheduler to bond it with WSS/H3 paths. Kernel WireGuard is deferred indefinitely as it is incompatible with this model on Android. |
| 6.3.2 | Define WG bootstrap payload | completed | `POST /v1/bootstrap/wireguard/peer` in `bootstrap.rs`: accepts `{device_public_key, wg_public_key}`, returns `{server_wg_public_key, peer_ip}`; `GET /v1/bootstrap/capabilities` includes `server_public_key` + `provision_endpoint` when WG enabled; `WireGuardPeerRegistry` in `bonded-server/src/wireguard.rs` allocates 100.64.1.x/32 IPs; server WG keypair persisted via `load_or_generate_wg_keypair()` |
| 6.3.3 | Add WG key lifecycle and peer state persistence | completed | Session 58 added persisted server-side WireGuard peer state backed by a TOML file (`wireguard_peers_file`, default `/var/lib/bonded/wireguard_peers.toml`) plus configurable lease duration (`wireguard_peer_lease_secs`). `WireGuardPeerRegistry::load_with_lease()` now reloads peer allocations on startup, prunes expired peers, normalizes legacy persisted entries, and safely reuses freed `/32` assignments without colliding with active peers. `register_peer_lease()` refreshes the lease on re-provisioning, rotates an existing device's WG public key while preserving its assigned `/32`, and exposes `lease_expires_at` through the bootstrap API so the client can reason about credential lifetime. Focused tests now cover persistence, expiry pruning, safe IP reuse, env overrides, and end-to-end bootstrap provisioning. |
| 6.3.4 | Implement WG transport adapter | completed | `WireGuardTransport` implements `Transport` trait in `bonded-core`; `establish_wireguard_session()` in `bonded-client`; `ClientTransport::WireGuard` variant; `("wireguard" | "wg")` arm in `establish_transport_paths`; client runtime now fetches `/v1/bootstrap/capabilities`, registers its WG public key via `POST /v1/bootstrap/wireguard/peer`, and dials the advertised WG UDP endpoint before returning a `WireGuard` path |
| 6.3.5 | Add WG revocation and teardown | not-started | Device revoke must invalidate WG peer immediately and terminate existing WG-backed paths |
| 6.3.6 | Add WG integration tests | completed | Added focused server/runtime test `wireguard_peer_runtime_exchanges_frames` proving encrypted frame exchange between the new server UDP runtime and `WireGuardTransport`, plus end-to-end bootstrap test `wireguard_bootstrap_provisions_and_dials_transport` proving the client fetches capabilities, provisions its WG peer over HTTP bootstrap, establishes a WG transport, and exchanges a frame; mixed-path failover coverage with WSS/QUIC still belongs to later scheduler-focused work |

### Phase 6.4: Let’s Encrypt Automation (Domain-Configured)

| # | Task | Status | Notes |
|---|------|--------|-------|
| 6.4.1 | Add ACME config in server.toml/env | completed | `acme_domain`, `acme_email`, `acme_cert_file`, `acme_key_file`, `acme_staging` added to `ServerSection` in `bonded-core/src/config.rs` |
| 6.4.2 | Implement cert issuance/renewal loop | completed | `bonded-server/src/acme.rs`: `AcmeChallengeStore`, `AcmeConfig`, `spawn_acme_renewal_loop()` — background task runs ACME HTTP-01 cycle via `instant-acme 0.7` + `rcgen 0.13`; writes PEM cert+key to configured paths; 1-hour retry on failure; wired in `main.rs`; challenge routing to HTTP listener is TODO (6.4.3) |
| 6.4.3 | Add challenge routing and ops docs | not-started | Support HTTP-01 and/or TLS-ALPN-01; document required inbound ports and DNS prerequisites |
| 6.4.4 | Add LE fallback behavior | not-started | If ACME fails, continue with configured static certs or explicit startup error depending on strict mode |

### Bootstrap Sequence (Target)

1. Client pairs (QR or manual) and gets `server_public_address` (`host:port`), invite token, and server public key (ed25519).
2. The `host:port` from pairing **is** the bootstrap endpoint — no additional port needed.
3. Client opens TLS connection to `https://<host>:<port>`. If the TLS cert validates via the system root CA store (or a stored fingerprint pin), proceed normally. If it does not (self-signed, private CA, or no stored pin yet), the client connects with TLS cert verification **disabled**, immediately calls `GET /v1/bootstrap/cert-proof`, and verifies the ed25519 signature over the cert fingerprint using the server public key from the QR payload — no credential material is sent before this check; if the signature is invalid the connection is aborted (MITM); if valid the fingerprint is pinned and persisted. If TLS fails on a future reconnect due to cert rotation, the client re-runs this step rather than hard-failing.
4. Client proves device identity with device keypair over the now-trusted TLS channel.
5. Server returns a capability document: which transports are enabled, the HTTP/3 UDP endpoint (same host:port as bootstrap but UDP), and the WireGuard UDP endpoint (separate dedicated UDP port).
6. **Wave 1 — concurrent dial:** Client dials WSS and H3 concurrently across each available network interface. The first to succeed on each interface is used immediately. Preference order (WSS > H3 by default) promotes one to primary when both succeed on the same interface; the other is kept as hot standby. `naive_tcp` is a debug-only fallback excluded from the production dial set.
7. **Wave 2 — WireGuard provisioning (background):** After wave 1 establishes at least one working path, client requests WG peer config over the bootstrap API (requires a wave-1 path to be live). Server returns a signed peer assignment including the dedicated WG UDP endpoint, client tunnel IP, allowed IPs, and expiry. Client establishes WG path in the background and adds it to the session once live. WG cannot participate in wave 1 because it requires this bootstrap round-trip first.
8. Session layer uses all successful paths concurrently; scheduler remains transport-agnostic.

Acceptance gate:

- Single `host:port` from pairing payload reaches HTTPS/WSS (TCP) and HTTP/3 (UDP) on the same port number
- Bootstrap API is reachable via HTTPS/WSS and HTTP/3
- Self-signed cert is accepted after ed25519 cert-proof verification; fingerprint is persisted and reused on reconnect; cert rotation triggers re-proof rather than hard failure
- QUIC/HTTP3 path can carry session traffic and coexist with WSS in one session
- WireGuard path can be provisioned from bootstrap API (wave 2) and coexist with WSS/QUIC
- WireGuard peer assignments survive server restart without requiring re-pairing
- NaiveTCP is disabled in production server config; WSS is the default encrypted transport
- TUN MTU is set to 1420 (or lower); all transports enforce matching max frame payload sizes
- Optional Let’s Encrypt mode can issue and rotate certs without manual restart

---

## Phase 7: Peer Connection Sharing

CR-7 is no longer deferred. Base transports and bootstrap trust are in place, so the remaining work is the peer-sharing subsystem itself.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 7.1 | Finalize peer-sharing trust and discovery design | completed | See `docs/design/peer-sharing.md`. Discovery is mDNS/DNS-SD only; trust remains server-rooted via signed peer introductions bound to a provider listener nonce and cert fingerprint. Initial local peer transport is QUIC (`bonded-peer` ALPN) carrying relayed `SessionFrame` bytes. |
| 7.2 | Add server-signed peer introduction bootstrap endpoint | completed | Added `bonded_core::peer_share` introduction types plus `POST /v1/bootstrap/peer-share/introduction`. The server now verifies the consumer signature, requires both consumer/provider device keys to be authorized, and signs short-lived claims covering provider endpoint, listener transport, listener cert fingerprint, provider listener nonce, and expiry, with unit coverage in `bonded-server`. |
| 7.3 | Implement peer listener and relay transport | in-progress | Added `bonded-client::peer_listener` verification helpers plus a `bonded-peer` QUIC handshake slice: the consumer now dials a peer listener with a pinned listener cert fingerprint, sends the server-signed introduction, the provider verifies it against its listener identity, acknowledges it, and both sides can exchange `SessionFrame`s over the resulting QUIC stream in test coverage. Session 61 extends that transport with a relay-registration control frame so the provider can pass the verified server-signed introduction upstream when it opens a dedicated server path for the consumer. Long-lived listener lifecycle and device validation are still pending. |
| 7.4 | Implement mDNS advertiser and browser | in-progress | `PeerShareAdvertisement` now includes server affinity, listener endpoint, listener cert fingerprint, and instance nonce in TXT records. `bonded-client::peer_runtime` starts an mDNS advertiser/browser, filters discovered peers by paired server and self device key, requests signed introductions for matching peers, and dials accepted peers into `PeerRelay` transports. Session 62 added Android-visible `PeerShare:` log lines for runtime start, discovery, introduction, and relay dial outcomes; on-device runs now prove that discovery and introduction succeed between the two phones. Runtime teardown/reconnect behavior is still pending. |
| 7.5 | Wire peer paths into scheduler/runtime | in-progress | `ClientRuntime` now starts a background peer-share runtime on Linux when `client.peer_share_enabled = true`, and the TUN loop accepts dynamically injected `PeerRelay` transports through a channel. Session 61 adds a provider->server relay-registration control frame carrying the server-signed introduction, and the server now verifies that control frame before binding the dedicated upstream provider transport to the introduced consumer session. Session 62 extended Android `SocketProtectFn` coverage to peer-share QUIC client/listener sockets, added bind-aware peer relay dialing/listening on the configured advertise IP, and verified that peer listener LAN traffic no longer hairpins through the server-side VPN sessions. Follow-up adb-driven `DatagramSocket` probes now show the same failure mode outside Quinn: with both phones connected, both sender and listener sockets protect successfully, but protected inbound UDP still times out in both directions, and a host-originated UDP probe to a protected phone listener also times out. Additional no-VPN explicit-bind probes now show the same timeout even when the listener is bound directly to `192.168.1.250` and the sender is bound directly to `192.168.1.140`, so the remaining work is no longer in the peer runtime itself; it is either LAN isolation or some lower-level device-to-device reachability issue on the current network. |
| 7.6 | Validate bidirectional two-device peer sharing | completed | Session 63 revalidated peer sharing end-to-end on the two Android phones. Coordinated direct TCP and UDP probes succeed both without the VPN and with `VpnService.protect()` enabled on UDP sockets, eliminating the earlier LAN-isolation/protected-UDP hypotheses. Fresh `BondedFFI` logs now show the Pixel establishing `WebSocketTLS`, starting peer share, discovering the OnePlus, issuing introduction, and logging `relay dial succeeded`; the OnePlus logs `accepted relay ...` followed by `registered upstream relay session`. Session 63 also fixed Android session snapshot bookkeeping so provider-side relays contribute to `peerRelayCount`; after upstream registration the OnePlus now reports `peerRelayCount=1` instead of incorrectly remaining at `0`. |

### October 2026 — production server + physical-device validation (builds 130–132)

The October server (post-auth session binding via an initial session frame, stricter TLS bootstrap listener) exposed three Android FFI defects that the May server had masked. All three were found on physical devices against the production server (dell, `charter.codingwell.net:443`) and fixed in sequence:

- **Deep-link pairing**: the server startup log emits a clickable `bonded://pair?...` deep link alongside the QR code; the Android app handles it via an intent-filter + app_links. Pairing was exercised headlessly over ADB (Pixel 6a via deep link, OnePlus One via `MainActivity adb_action=pair`) and in the UI.
- **Build 130 — FFI session-discovery fix**: the October server's `resolve_session_binding` waits for an initial session frame to detect peer-relay registrations. The Android FFI session worker authenticated and then sent nothing until the 25s heartbeat, so the server logged `failed to bind websocket session after authentication … failed to receive initial session frame` and dropped every path; no Android session ever bound. The FFI worker now performs the same startup PING/PONG session-discovery exchange as the Linux client on every path, adopts the server-assigned session id from the PONG (replacing the hardcoded `SessionState::new(1)`), and drops paths that fail the exchange. The Settings screen also now shows the Play build number via `package_info_plus`.
- **Build 131 — redeem transport fix**: `redeem_invite_token` always dialed the plaintext naive-TCP handshake, including to the TLS bootstrap endpoint (server logged TLS `InvalidContentType`; the app showed `unexpected end of file`), so pairing against production never worked. Redeem now dials via `establish_transport_paths` and runs the session-binding exchange over that transport (`complete_pairing_session_binding`). With 131, the first successful physical Android end-to-end validation completed: both phones paired and their VPNs connected to the October server, with traffic through the tunnel verified.
- **Build 132 — heartbeat + peer advertise fixes**: (a) the FFI heartbeat pinged only the active path, so the server's 30s receive timeout kept killing secondary paths; the heartbeat now pings every path. (b) Peer advertise-IP selection picked the VPN tunnel address `10.8.0.2` (identical on every client) over the LAN address; selection now prefers a candidate sharing a /24 with a path bind address.
- **Physical-device validation status (2026-10-17, build 132)**: both phones (Pixel 6a, OnePlus One) run build 132 against the production October server. Each binds two direct WSS paths (Wi-Fi + cellular) to one server session; over a 5½-minute observation window the server logged zero session teardowns or path drops (the pre-132 secondary-path timeout is gone), and heartbeats pong on both phones every 25s. The Pixel's peer runtime advertises `192.168.1.140:54443` (LAN, not `10.8.0.2`). A physical peer relay formed on the home WLAN itself: the Pixel discovered the OnePlus, issued an introduction, and its relay dial succeeded; the OnePlus accepted the relay, and the server added the relay transport to the Pixel's session with `relayed_via_provider=true` (3 transports total). Still open: forced direct-path-loss failover carrying user traffic on the phones (covered for the Linux client by the Forge netns harness), and Play upload of builds 131/132 — build 130 shipped to the Play internal track on 2026-10-16, but 131 was sideloaded only and 132 has not been uploaded; both await explicit user confirmation per the standing rule.
- **Forge netns harness regression (2026-10-17, build-132 code)**: the remote-peer harness (provider + consumer in Forge network namespaces, paired to the production dell server) passed **7/7** — peer control plane, 40s idle soak, and the forced direct-path-loss data plane (HTTP 200 via the provider relay) all green, so the 130–132 client changes did not regress the QUIC/UDP peer data plane. A first attempt failed at consumer startup on a transient path-establishment timeout (no server-side trace; the provider was unaffected) and the immediate retry passed in full. The run also confirmed the server closes idle relay-upstream transports at its 30s receive timeout and the provider re-registers each time; on the phones, the same cycle exposed a longevity gap — after the server closed the OnePlus's relay upstream at ~00:30 PDT, its re-registration retries reused the by-then-expired introduction and were rejected (`peer relay introduction expired`, 44 attempts) until the Pixel issued a fresh introduction at 00:45:48 and the relay re-formed (server transport re-added with `relayed_via_provider=true`). Follow-up: a provider whose relay upstream drops after its introduction has expired cannot recover until the consumer happens to re-issue; consider provider-triggered introduction refresh.
- **Build 137 \u2014 server-identity verification at session start + dashboard update check (implemented and validated on-device 2026-10-17; rolled out to the Play internal track the same day, v137 completed)**: closes the silent failure behind two phones that connected but could never peer \u2014 their paired records pin a stale server identity (`Pjt73it\u2026`, from an earlier test-server pairing), and nothing in the client checked that pin outside the peer machinery, so the VPN worked while peering failed closed for reasons invisible to the user. The hole was in `resolve_wss_tls_connector`: when the cert-proof bootstrap failed, the WSS path logged a warning and **fell back to system-CA validation**. Changes: (a) cert-proof failures are classified (`cert_proof::is_identity_mismatch_error`) \u2014 a well-formed proof that does not verify against the paired key (bad signature, or signed fingerprint \u2260 presented certificate) is an *identity mismatch*, distinct from reachability failures (unreachable endpoint, malformed response), which say nothing about identity; (b) the WSS connector refuses the CA fallback on identity mismatches (reachability failures keep the fallback, now logged at error level as identity-unverified); (c) `establish_transport_paths` runs an up-front identity gate \u2014 one cert-proof fetch against the bootstrap endpoint under the existing 8s path budget \u2014 whenever a server key is configured, and fails closed on identity evidence from any attempt, including discarding a session a path managed to connect over an unverified transport; the failure is a canonical `Server identity verification failed \u2026 Re-pair this device` error that the FFI surfaces verbatim as the snapshot `lastError` (rendered by the dashboard's persistent error banner) and that the Android service matches to **skip automatic session recovery**, since reconnecting cannot fix a key mismatch. Legitimate ACME certificate rotation is unaffected: the proof re-verifies under the unchanged identity key and the fresh fingerprint is pinned for the session. Tests: bonded-client 42/42 (4 new cert-proof classification unit tests plus `identity_gate_fails_closed_on_wrong_paired_server_key`, an in-process TLS proof-server integration test: wrong pin fails establishment with the canonical error, right pin passes the gate), bonded-core 30/30, bonded-ffi 4/4. On-device validation: `install -r` on both phones, sessions restarted \u2014 the worker logs `server identity verified via cert proof fingerprint=sha256:81a97d05\u2026` at each start, both phones connected with 3 transports and `peerRelayCount=1`, relays bound server-side (`relayed_via_provider=true`). (d) Dashboard UX in the same build, at the user's direction: background status events no longer pop a SnackBar per event (they fired repeatedly after connecting and covered the bottom action button; state remains on the status banner/cards, errors on the persistent banner), and the dashboard checks Play for an update on open (Play Core app-update, IMMEDIATE flow) showing a tappable `Update available (build N)` banner \u2014 silently absent for sideloaded or Play-less installs. Operational note: implicit `am broadcast` VPN_START/STOP does not reach the manifest receiver at targetSdk 36 from a cold process \u2014 use the explicit-component form (recorded in TOOLS.md). Motivating diagnosis: goal checkpoint `stale-identity-pin-2026-10-17.md`.
- **Build 135 — peer rediscovery re-drive + dead-leg detection (implemented and validated on-device 2026-10-17; rolled out to the Play internal track)**: the build-134 soak exposed the next gap in the same flow. Validation: `install -r` on both phones — symmetric relays formed in ~1.5s; at the introductions' expiry the workers retired both relays (21:03:39Z server-side end), the browse tasks re-drove discovery from the cached advertisements, and **new relays were server-bound 5s later on the same sessions (transports 98/99, `relayed_via_provider=true`) with no session restart** — the retire→redial cycle took ~10s end to end. The part (c) stress-test fix was verified in the same session: warm-up negotiated h3 immediately and all 5 rounds passed `protocol=h3` with zero failures (previously rounds 1–2 failed 4 runs out of 4). After a relay path closed and the peer was un-marked ("allowing rediscovery"), no new relay ever formed until a runtime restart: `PeerShareBrowser::recv()` returns only on mdns-sd `ServiceResolved`, which fires **once per service instance**, so the browse task blocked forever waiting for an event that never repeats (this also explains why the overnight outage ended only with an incidental re-resolution). (a) Rediscovery: the browse task now caches the last accepted advertisement per peer and, on a path-close, re-drives discovery from the cache via a bounded `RedialQueue` — a fresh server introduction and re-dial after 10s, at most 3 attempts, so a departed peer cannot cause an introduction-request loop; fresh mDNS resolutions still take the normal path and refresh the cache. Unit coverage: `redial_queue_dedupes_pending_peer`, `redial_queue_exhausts_attempts_then_allows_fresh_enqueue`, `redial_queue_forget_clears_attempt_budget`. (b) Dead-leg detection: the soak also showed a consumer↔provider QUIC leg dying silently (~10:37 PDT) — the provider churned a starving upstream every 30s while the consumer's heartbeat sends kept succeeding into the dead connection until expiry cleanup bounded the loss. The FFI heartbeat tick now also retires non-active peer relays whose QUIC connection has closed (`QuicTransport::connection_closed` → `ClientTransport::peer_relay_connection_closed`), triggering the close-notifier and rediscovery within one tick instead of at introduction expiry. Test status: bonded-core 30/30, bonded-ffi 4/4, bonded-client peer tests + new queue tests pass; the 7 bonded-client UDP/QUIC integration failures are pre-existing sandbox limitations, verified identical on the pristine tree. Full diagnosis: goal checkpoint `rediscovery-gap-2026-10-17.md`. (c) Protocol stress test reliability (same build): the "unreliable" early-round http3 failures were a tester artifact, not corruption — `ProtocolStressTester` built a fresh Cronet engine per run with QUIC enabled but no hint and no persisted state, so the first ~2 rounds necessarily fell back to HTTP/2 while QUIC was discovered via Alt-Svc, and the tester hard-failed any non-h3 completion (reproduced 4/4 runs on-device: 8 of 25 http3 attempts, all in rounds 1–2, identical `protocol='h2'` error; all successful bodies byte-identical — the tunnel and QUIC payloads are exonerated). The tester now seeds the engine with `addQuicHint` for the configured HTTP/3 host and runs one unscored warm-up fetch before the scored rounds, so scored rounds measure steady-state HTTP/3; an h2 completion in a scored round remains a failure, as it then genuinely signals QUIC breakage. Diagnosis: goal checkpoint `http3-stress-investigation-2026-10-17.md`.
- **Build 134 — relay longevity + reconnect fixes (implemented and validated on-device 2026-10-17; shipped as versionCode 134 because the overnight documentation commit consumed the 133 slot in the git-count version formula; also rolled out to the Play internal track)**: addresses the follow-up above from both ends. Validation: `install -r` on both phones, sessions restarted — peer relays formed **symmetrically** within ~1s (each phone's session gained a `relayed_via_provider=true` transport via the other), and the reconnect trap regression test passed: a debug-connect restart issued with the TUN up re-authenticated and re-formed the relay in ~5s with zero 8s deadline failures (on build 132 the same action wedged the VPN until a full service stop/start). (a) Provider: the relay re-registration loop now checks the introduction's `expires_at` before every attempt and abandons the relay once it has expired — dropping the peer connection so the consumer notices promptly — instead of retrying a credential the server will always reject (the 44-attempt storm above). Only the consumer can mint a fresh introduction, so provider-side persistence past expiry is futile by design. (b) Consumer: the FFI worker only ever receives on the active path, so a non-active relay whose provider upstream died was never detected — its QUIC leg stayed healthy, heartbeat sends kept succeeding into the provider's buffers, and the dead relay blocked rediscovery for ~15 minutes (and inflated the reported transport counts). The worker's heartbeat tick now retires any non-active peer-relay transport whose introduction has expired (`ClientTransport::peer_relay_expired`); closing it fires the relay close-notifier, the peer runtime un-marks the peer, and the next advertisement produces a fresh introduction and a new relay. A relay actively carrying traffic is exempt — its failure surfaces through the existing active-path failover. Unit coverage: `introduction_expiry_gate`; the two pre-existing sandbox UDP failures in bonded-client lib tests are unchanged. (c) Reconnect DNS trap (found the same morning on both phones): session restarts that skip `onStartCommand`'s early DNS resolution (session recovery, network rebind, debug connects) handed the native worker the bare server hostname while the TUN was still up; DNS then routed into the dead tunnel, every protocol attempt timed out at 8s, and the VPN could never self-heal (recovery required a full service stop/start). The paired record now persists the last successful resolution (`lastResolvedAddress`, updated only by genuine IP-literal results, never the hostname fallback), and `startNativeSession` prefers fresh early resolution → persisted last-good → raw address. A live build-132 relay also showed the provider upstream does NOT time out while the consumer's 25s heartbeat pings traverse it — the overnight 00:30 drop required a ≥30s relaying stall (device doze/standby on the idle provider is the leading suspect), which is what parts (a)/(b) make recoverable.

## Deferred to Later Phases

These are in v1 scope but depend on the above being stable first:

- **ShadowSocks transport** — deferred until WSS and QUIC are stable and validated in production; CR-8 lists it as "v1 if feasible" but the effort is not justified before the primary transports are proven
- **Bootstrap API rate limiting** — per-IP and per-token rate limits on `/v1/bootstrap/*` endpoints; deferred until bootstrap API is implemented and attack surface is better understood; mitigated in the interim by invite token single-use semantics and device keypair binding
- **Peer-initiated bootstrap (future)** — a client with no working direct Internet path establishes its session entirely through a LAN peer: relayed server-signed introduction and cert-proof over a pre-introduction bootstrap stream, plus relay-first session creation on the server. Design note: `docs/design/peer-bootstrap-relay.md`
- **Battery optimization (AND-6)**
- **Quick settings tile (AND-7)**

---

## Key Implementation Decisions

Decisions made during implementation that aren't in the requirements docs.

| Decision | Date | Notes |
|----------|------|-------|
| Immediate Cargo workspace migration | 2026-03-30 | Move to `crates/` before substantial feature work |
| TOML for server/client config and simple persisted state | 2026-03-30 | Includes server config, authorized keys, invite tokens |
| `ed25519-dalek` for device identity and signing | 2026-03-30 | Matches invite-token plus per-device public-key auth model |
| `tun` crate for Linux TUN support | 2026-03-30 | Thin Linux-specific layer over shared client core |
| Thin Kotlin JNI wrapper for Android bridge | 2026-03-30 | Flutter uses platform channels; avoid introducing a second cross-platform bridge layer early |
| Session reassembly model uses per-connection ordered buffer with stale-sequence rejection | 2026-03-31 | `SessionState` tracks next expected RX sequence and releases contiguous frames only |
| Key material storage format is base64 string fields (private/public) in shared auth utilities | 2026-03-31 | Keeps config/state serialization straightforward for CLI and server TOML files |
| Invite tokens use URL-safe, no-padding base64 random bytes with decrement-on-redeem semantics | 2026-03-31 | Aligns with single-use/limited-use token model from OQ-1 while staying transport-agnostic |
| NaiveTCP framing uses 4-byte big-endian length prefix over TCP carrying `SessionFrame` bytes | 2026-03-31 | Keeps transport simple and deterministic for first end-to-end milestone |
| Server config env override names use `BONDED_*` with `PUBLIC_ADDRESS` alias support | 2026-03-31 | Keeps backwards-compatible public endpoint injection while standardizing environment variable naming |
| Authorized keys are stored in a path-indexed in-memory map and reloaded via `notify` watcher callbacks | 2026-03-31 | Enables revocation by editing file without process restart |
| Initial server auth handshake uses newline-delimited JSON messages over NaiveTCP before session traffic | 2026-03-31 | Keeps first auth exchange debuggable while validating challenge-signature flow |
| Server startup ensures at least one usable invite token exists in `invite_tokens.toml` | 2026-03-31 | Supports immediate pairing bootstrap before admin tooling exists |
| Health check endpoint uses a minimal raw-TCP HTTP responder returning `200 OK` with body `OK` | 2026-03-31 | Keeps health probe dependency-free and easy to container-check |
| Server session IDs are assigned from an in-memory registry keyed by authenticated client key | 2026-03-31 | Allows concurrent client session tracking before full packet-forwarding pipeline is wired |
| Pairing QR payload is JSON containing only public address, invite token, and server public key | 2026-04-04 | Transport protocol metadata removed from pairing so clients negotiate protocols when starting VPN sessions |
| Container runtime defaults mount config/state at `/etc/bonded` and `/var/lib/bonded` | 2026-03-31 | Aligns image behavior with documented server file conventions |
| Server integration tests exercise full auth handshake then framed payload exchange on the same TCP stream | 2026-03-31 | Ensures session traffic can continue immediately after authentication |
| Initial server internet-forwarding mode is payload relay to optional upstream TCP target with echo fallback | 2026-03-31 | Provides deterministic end-to-end forward/return behavior before full TUN/raw-socket integration |
| Linux client interface enumeration uses `pnet_datalink`; TUN provisioning uses `tun` with explicit interface name | 2026-03-31 | Keeps Linux-specific plumbing isolated in shared client runtime |
| Linux client persists private/public key material to configured paths and reuses it for reconnect auth | 2026-03-31 | Aligns runtime behavior with per-device identity requirement and avoids regenerating identity each launch |
| Pairing payload ingestion updates client config with server endpoint/key/token only | 2026-04-04 | Prevents stale protocol hints from pairing and keeps transport negotiation runtime-driven |
| Linux packet loop uses `tun::create_as_async` + `tokio::select!` to bridge TUN packets and NaiveTCP session frames | 2026-03-31 | Establishes bidirectional TUN transport plumbing in a single runtime loop |
| Linux multipath uses active-primary with failover-to-survivor strategy for first implementation | 2026-03-31 | Delivers CR-1/CR-2 behavior without introducing concurrent scheduler complexity in the initial client loop |
| Linux failover integration tests treat first-path send closure as acceptable and assert survivor-path continuity | 2026-03-31 | Avoids flaky timing assumptions while still validating failover behavior under path loss |
| Invite redemption is handled inline during auth hello when key is unknown and invite token is present | 2026-03-31 | Allows first-time pairing and key registration without a separate control endpoint in initial NaiveTCP milestone |
| Android shell starts as Flutter project under `android/` with Android-only scaffold | 2026-03-31 | Keeps initial mobile scope thin while preserving a direct path to FLT/AND tasks in later Phase 4 steps |
| Android Rust bridge uses dedicated `bonded-ffi` crate with minimal C ABI and explicit metadata decode wrapper | 2026-03-31 | Creates a stable JNI/FFI boundary while reusing `bonded-core` internals and enabling incremental API expansion |
| Flutter-to-Rust handshake starts via `MethodChannel` and Kotlin JNI stub before full native library packaging | 2026-03-31 | Enables incremental UI and bridge validation even when `jniLibs` artifacts are not yet produced in CI/dev flows |
| Android VPN lifecycle is first exposed through MethodChannel (`start/stop/status`) with `BondedVpnService` shell | 2026-03-31 | Allows Flutter UI and host plumbing to stabilize before binding live TUN packet flow into shared Rust runtime |
| MainActivity supports an ADB-triggerable pairing intent for non-interactive device tests | 2026-05-25 | Starting `MainActivity` with `adb_action=pair` plus server address/public key/invite token redeems pairing natively and persists a paired-server record; this enables real-device local-server validation over `adb reverse` without QR scanning or a debuggable build |
| ADB pairing can redeem on one address and persist a different bootstrap address | 2026-05-26 | `server_address` remains the native invite-redemption target, while optional `bootstrap_server_address` becomes the paired server's `publicAddress`; this supports split-port local validation where NaiveTCP pairing and WireGuard bootstrap use different published ports |
| Android background mode uses `BondedVpnService` foreground-service startup plus EventChannel status streaming | 2026-03-31 | Satisfies long-running VPN requirements and keeps Flutter UI synchronized with native service lifecycle |
| Android VPN foreground startup uses `specialUse` FGS declaration and runtime type flag | 2026-04-01 | Target SDK 35 requires both manifest declaration/permission and `startForeground(..., type)`; `systemExempted` is reserved for specific configured VPN cases, so `specialUse` is the safe general Bonded app path |
| Android socket protect: `JNI_OnLoad` stores `JavaVM`; `nativeStartSession` stores `GlobalRef` to service; `protect_fd()` attaches worker thread as daemon and calls `vpnService.protect(fd)` via JNI before each TCP socket `connect()` | 2026-04-01 | Prevents routing loop where Rust session TCP sockets got captured by the VPN TUN, deadlocking transport path establishment |
| `SocketProtectFn` newtype wrapping `Arc<dyn Fn(i32) -> bool + Send + Sync>` added to `ClientConfig` as `#[serde(skip)]` field | 2026-04-01 | Allows Android-specific JNI protect callback to be injected without leaking platform concerns into the shared config parsing path |
| Android WSS dialing uses split identity vs dial address (`server_address` + `server_resolved_address`) | 2026-05-25 | Android must pre-resolve before the VPN comes up to avoid DNS deadlock, but WSS/rustls hostname validation and cert-proof `Host`/`ServerName` handling must continue to use the DNS name from pairing; the client now dials the cached IP separately while preserving the original hostname for TLS identity |
| `establish_naive_tcp_session` now uses `TcpSocket` (not `TcpStream::connect`) to access raw fd before connecting | 2026-04-01 | Required to call `protect(fd)` before the OS assigns the socket to the VPN routing table via `connect()` |
| VPN builder adds `addDnsServer("8.8.8.8")` and `addDnsServer("1.1.1.1")` | 2026-04-01 | Without explicit DNS servers, hostname lookups fail when VPN captures the default route |
| Session snapshot tracks `outboundBytes`, `inboundBytes`, `connectedAtMs` (ms since epoch) updated per packet in the Rust session loop | 2026-04-01 | Enables dashboard display of bytes sent/received and connection uptime without Kotlin-side instrumentation |
| Android pairing trust root is always the server ed25519 identity key, stored as `serverIdentityPublicKey` with legacy `serverPublicKey` only treated as a compatibility alias | 2026-05-31 | Prevents confusion with the separate WireGuard public key and keeps cert-proof/TLS bootstrap aligned with the actual trust anchor used by WSS/H3 |
| Android path availability is defined by concrete bind addresses, not transport callbacks alone | 2026-05-31 | The VPN service now reports only paths with usable bind addresses, exposes bind-address/path-summary state for debugging, filters out non-`INTERNET` cellular networks, and prefers CLAT IPv4 interfaces like `v4-rmnet1` over IMS-only cellular addresses so Android multi-network status reflects what the shared Rust client can actually dial |
| Android dual-path completion requires a raw bound-socket reachability check, not just two selected bind addresses | 2026-05-31 | Session 64 proved that `bindAddresses=[wifi, 192.0.0.4]` is insufficient evidence: all Bonded path-1 protocols (`h3`, `wireguard`, `wss`) timed out from the CLAT bind, and a direct Android `tcp_connect` probe from `192.0.0.4` to `75.164.235.136:443` failed while the Wi-Fi-bound control succeeded immediately |
| Android cellular dual-path viability currently fails at the `Network` API boundary, not just inside Rust socket setup | 2026-06-01 | Session 65 showed that binding Rust-owned sockets to the cellular `Network` with `Network.bindSocket(fd)` returns `EPERM`, and even a direct `Network.getSocketFactory()` TCP probe from tracked bind `192.0.0.4` fails with the same `EPERM` while the matching Wi-Fi control succeeds |
| Android pairing metadata is stored in app `SharedPreferences`, while device key material is persisted by Rust under app-private files dir | 2026-03-31 | Keeps Flutter pairing UI simple and gives the native VPN service enough data to bootstrap reconnects without reusing invite tokens |
| Android VPN UI status is driven by Rust session snapshots polled by Kotlin service, not only service lifecycle flags | 2026-03-31 | Distinguishes VPN-service startup from actual transport/session connectivity in the dashboard and background events |
| Android multi-path currently steers NaiveTCP paths by binding each Rust socket to a local IP derived from Android `LinkProperties`, and restarts the native session when the active network set changes | 2026-03-31 | Preserves the shared Rust transport/session stack while giving Android concrete per-network path steering before a deeper socket-factory-based integration exists |
| Android cross-compilation configured via workspace-root `.cargo/config.toml` with NDK 26 linker/ar/CC/CXX/AR env vars per target | 2026-03-31 | `cc-rs` build scripts look for unversioned `aarch64-linux-android-clang`; explicit `CC_aarch64_linux_android` env var overrides that search; NDK 26.3.11579264 is the installed version; NDK 27 download attempted but incomplete |
| VPN notification icon changed from `android.R.drawable.stat_sys_vpn_ic` to `R.mipmap.ic_launcher` | 2026-03-31 | `stat_sys_vpn_ic` was removed from Android API 34; `R.mipmap.ic_launcher` is always present in Flutter-generated Android projects |
| Pre-compiled `libbonded_ffi.so` bundled in `jniLibs/arm64-v8a/` and `jniLibs/x86_64/` for debug builds | 2026-03-31 | Keeps Flutter Gradle build self-contained without requiring NDK in every CI/dev environment; `scripts/build-android-native.sh` automates rebuild on Rust changes |
| GitHub Actions artifact workflow builds both Docker image tarball and Android debug APK | 2026-03-31 | Added `.github/workflows/build-artifacts.yml`; Docker job exports `/tmp/bonded-server-image.tar`; Android job builds Rust JNI libs via `cargo-ndk`, runs `flutter build apk --debug`, and uploads APK artifact |
| Phase-5 websocket transport shares frame codec and auth flow semantics with NaiveTCP | 2026-03-31 | Uses binary websocket frames for session payloads plus JSON text messages for challenge-signature auth to keep protocol behavior aligned |
| Mixed-path establishment rotates preferred protocols per path with per-path fallback | 2026-03-31 | Enables one session to combine NaiveTCP and websocket paths without introducing a new scheduler strategy |
| QUIC implementation is deferred until WSS TLS server endpoint/certificate lifecycle is complete | 2026-03-31 | Reduces concurrent transport hardening risk while preserving planned `quinn` adoption path |
| Session forwarding sharding: 256 TCP flow shards and 16 UDP session shards per client session | 2026-04-08 | Reduces lock contention on per-session flow tables; each shard has its own Mutex<HashMap> so concurrent worker threads can access different flows in parallel without stalling; critical for supporting 50+ concurrent TCP connections without head-of-line blocking |
| Forwarding worker pool increased from 16 shards to 256 shards | 2026-04-08 | With 50+ concurrent connections, the 16-shard pool resulted in ~3 connections per shard causing head-of-line interference; 256 shards provides one worker per connection on average; ICMP remains on dedicated bounded queue (128 frames) per session to prevent ping storms from affecting TCP/UDP |
| Batch draining of response queue before select blocking | 2026-04-08 | Session send loops now pre-drain all available responses via try_recv() before blocking on tokio::select!; prevents artificial latency when multiple responses are queued from the 256 forwarding workers; critical for keeping ICMP/TCP response latency low when many connections are active |
| Server WSS termination uses rustls with PEM certificate/key configuration and optional enablement | 2026-03-31 | Websocket listener remains `ws://` when TLS files are unset and upgrades to `wss://` when both files are provided |
| WSS integration tests use generated self-signed certificates with explicit client trust roots | 2026-03-31 | Validates authenticated frame exchange over true TLS websocket without relying on external PKI in CI |
| Server startup pre-creates missing state files (`authorized_keys.toml`, `invite_tokens.toml`) and parent directories | 2026-04-01 | Ensures first boot succeeds with only `/etc/bonded/server.toml` present; keeps state-file defaults under configured paths (including `/var/lib/bonded`) |
| Authorized-keys watcher reloads only on mutating events and applies short debounce | 2026-04-01 | Prevents notify access/read event feedback loops and duplicate reload bursts when authorized-keys file is rewritten during pairing/auth flows |
| Server frame forwarder now performs user-space IPv4+UDP relay and response packet synthesis before fallback behavior | 2026-04-02 | Enables DNS/UDP tunnel round-trip without kernel NAT as first incremental gateway slice; TCP user-space flow tracking remains future work |
| Client multipath establishment now requires path 0 success but treats later-path failures as degradable warnings | 2026-04-02 | Prevents Android VPN session startup from collapsing when Wi-Fi+cellular dual-path setup partially fails; preserves failover architecture while prioritizing a working single-path tunnel |
| Android session startup diagnostics now preserve first transport-establish error and avoid clobbering it with downstream queue-closed noise | 2026-04-02 | `establish_transport_paths` now reports underlying timeout/connect/protect failures, Android socket protect failures are fatal, and FFI queue-closed updates keep prior `lastError` when already set |
| NaiveTCP client path establishment now always binds the socket to an ephemeral local wildcard address before VPN protect/connect | 2026-04-02 | Makes both explicit-bind and default paths follow bind -> protect -> connect ordering, aligning Android VPN socket-handling expectations and simplifying behavior across paths |
| Android VPN service now buffers outbound TUN packets during native-session restarts and flushes on reconnect | 2026-04-02 | Reduces `Native packet queue rejected outbound packet` spikes caused by short stop/start windows during recovery or network rebind; bounded queue avoids unbounded memory growth |
| Android socket-protect path now emits explicit protect(fd) success/failure diagnostics from both Kotlin and Rust layers | 2026-04-02 | JNI now calls `protectSocketForNative(fd)` (with fallback to `protect(fd)`), logging each result to distinguish true protect failures from downstream transport/auth disconnects |
| NaiveTCP session-frame receive path now fails fast on invalid tiny frame lengths and logs exact sizes for header-underflow decode errors | 2026-04-02 | Distinguishes malformed/corrupted framed data (`len < 16`) from generic transport disconnects and makes Android/server recovery diagnostics actionable |
| NaiveTCP auth handshake now reads newline-delimited JSON directly from TcpStream (byte-by-byte) instead of BufReader split/reunite | 2026-04-02 | Prevents buffered over-read during auth from consuming first framed session bytes, which could desynchronize length-prefix parsing and trigger `buffer too small for frame header` recovery loops |
| WireGuard peer allocations are persisted in a dedicated TOML state file and device re-provisioning keeps the same `/32` while rotating the WG key | 2026-05-30 | Prevents server restarts from invalidating previously provisioned WG endpoints and keeps bootstrap re-issue idempotent for an already-paired device |
| Android paired-server persistence is schema-tolerant across app updates | 2026-04-04 | `PairedServerStore` now tolerates malformed/partial entries, skips invalid records, and migrates legacy single-record preference keys into the current records array to avoid apparent unpairing after upgrades |
| Bind-aware path establishment now follows protocol negotiation order (including WebSocket) | 2026-04-04 | Removed special-case NaiveTCP pre-attempt for bound paths and added bind-aware WebSocket dialing so Android `wss` preference is honored when path bind addresses are present |
| Device-test workflow now gates DNS checks on explicit Android-side VPN state probe (`TEST_VPN_STATUS`) before running network diagnostics | 2026-04-02 | Avoids ambiguous results from DNS checks that run before VPN session establishment and keeps tunnel validation aligned with UDP-forwarding goals |
| Android network diagnostics now default DNS checks to `unifi.g.codingwell.net` with optional `expected_ip` assertion and use explicit component broadcasts for deterministic receiver execution | 2026-04-02 | Ensures DNS test intent validates a concrete expected answer (`34.82.88.79`) and avoids implicit-broadcast delivery ambiguity during adb-driven validation |
| Android HTTP/3 diagnostics use embedded Cronet and require negotiated protocol `h3`/`quic` to count as success | 2026-04-18 | Keeps the QUIC/HTTP3 stress path honest instead of silently succeeding over HTTPS fallback when the target or stack downgrades |
| Android inbound TUN drain now batches writes per cycle (single flush) with larger poll window and shorter idle sleep | 2026-04-18 | Throughput-testing optimization: moved from per-packet flush to per-cycle flush, increased `MAX_POLLED_INBOUND_PER_CYCLE` (32→128), and reduced idle sleep (5ms→1ms) to reduce server→Android bottlenecks |
| Android inbound JNI batching experiment was reverted; VPN now uses single-packet inbound polling for simplicity | 2026-04-18 | Device tests showed no meaningful throughput gain from batch JNI dequeue in current environment, so the path was removed to keep packet I/O behavior simple and debuggable |
| Server session loops now pre-drain queued forwarded/TUN response frames before `tokio::select!` blocking | 2026-04-19 | Throughput-debugging slice: avoids one-frame-per-select scheduling bottleneck for bursty server→client traffic in both TCP and WebSocket session loops; capped by `MAX_RESPONSE_DRAIN_PER_CYCLE` for fairness |
| NaiveTCP transport and smoltcp upstream bridge sockets now enable `TCP_NODELAY` | 2026-04-19 | Throughput/latency debugging slice: disables Nagle coalescing on framed session/control streams to reduce small-frame batching delays under VPN packetized traffic |
| Status endpoint now reports TCP bridge chunk-size counters (`bridge_read_*`, `bridge_to_smoltcp_*`) per flow | 2026-04-19 | Throughput-debugging instrumentation: makes average/total upstream read chunk sizes and smoltcp write chunk sizes visible to verify whether small chunking drives TCP amplification |
| Android VPN now disallows the app package from tunnel capture and treats `protect(fd)=false` as non-fatal on Android | 2026-04-02 | Prevents startup deadlocks when control-plane sockets would otherwise be captured by the VPN and removes brittle dependency on per-socket protect success |
| Android launcher icon generation is managed via `flutter_launcher_icons` using workspace-root `icon.png` | 2026-04-03 | Keeps launcher assets reproducible across densities and Android adaptive-icon resources instead of hand-editing mipmap files |
| Rust-only DNS tunnel diagnostics use an ignored localhost integration test in `bonded-server` that runs real server+client crates and injects synthetic UDP DNS probes | 2026-04-03 | Enables reproducible E2E debugging of server/client forwarding behavior without Android app/device dependencies |
| Server frame forwarder now handles IPv4 ICMP echo request/reply in addition to UDP | 2026-04-03 | Uses Linux-compatible IPv4 ICMP datagram sockets through `socket2`, matches echo identifier/sequence, and synthesizes IPv4 ICMP reply packets with recomputed checksums for client return path |
| UDP forwarding now uses per-client-session long-lived flow sockets with 4-minute idle expiry | 2026-04-06 | Each UDP 4-tuple creates/reuses a connected ephemeral socket; server pushes all remote datagrams back to client asynchronously until no client packet is seen for 4 minutes |
| Server exposes a lightweight status HTML endpoint on a dedicated bind (`status_bind`) | 2026-04-06 | Page auto-refreshes and reports authenticated sessions plus active UDP/TCP flow tables and recent ICMP outcomes to aid runtime diagnostics during tunnel bring-up |
| Per-session frame forwarding now runs through sharded async workers and a response queue (16 shards by connection ID) | 2026-04-08 | Reduces head-of-line blocking where one slow forward (for example upstream TCP timeout) could stall unrelated flows in the same session; preserves serialized transport writes in the main session loop |
| Per-session ICMP echo traffic is isolated onto a dedicated bounded worker queue | 2026-04-08 | IPv4 ICMP echo requests bypass the generic forwarding shards and use one dedicated per-session worker with a 128-frame queue; prevents ping storms from monopolizing normal forwarding workers and causing unrelated flow timeouts |
| Server heartbeat filter only treats empty-payload ping-flag frames as control messages | 2026-04-08 | Prevents accidental data-plane stalls where non-empty frames carrying `FLAG_PING` were consumed as heartbeats and never reached TCP/UDP/ICMP forwarding or status trackers |
| Server now supports config-gated Linux TUN runtime bootstrap/cleanup inside container namespace | 2026-04-10 | `forwarding_mode=tun` provisions `tun_name`/`tun_cidr`/`tun_mtu`, auto-detects default egress interface (or uses override), enables `ip_forward`, installs iptables MASQUERADE/FORWARD rules, and restores/removes state at shutdown to minimize manual Docker networking setup |
| TUN bridge routes naive-tcp session frames to Linux TUN and sends return packets back by destination-IP ownership map | 2026-04-10 | `tun_bridge` now tracks session registration and client source-IP ownership, writes client payload packets into TUN, reads return packets from TUN, and emits framed responses with per-session server sequence counters; this makes `forwarding_mode=tun` usable for naive-tcp transport in containerized deployments |
| Non-TUN forwarding migration completed: `SmoltcpForwarder` replaces `frame_forwarder` sharded worker pool | 2026-04-17 | Session 29: initial vertical slice — one `SmoltcpForwarder` per authenticated session, smoltcp TCP state machine + bridge tasks, UDP/ICMP via direct OS sockets, ForwarderRegistry plumbed through main/status/tests. Session 30 cleanup: `frame_forwarder.rs` deleted; `main.rs` concurrency_tests rewritten without legacy TcpFlowTable; `UdpSessionManager` now holds `Arc<TokioMutex<HashMap<UdpFlowKey, UdpFlowHandle>>>` so each UDP 4-tuple reuses one OS socket across packets; UDP response frames carry client `connection_id` from request; `bonded-core` `Default` impls converted to `#[derive(Default)]`; clippy clean (`-D warnings`) on bonded-server; all 32 integration/unit tests pass. Known limitation: ICMP still uses one DGRAM socket per probe — per-session shared socket deferred because DGRAM ICMP sockets receive kernel-assigned echo identifiers that differ from client IDs, making demultiplexing ambiguous without a separate mapping layer. |
| Server can emit tunnel packet captures to a fixed PCAP file when explicitly enabled by env var | 2026-04-24 | `BONDED_TUNNEL_PCAP_MAX_MB` enables capture to `/var/lib/bonded/tunnel.pcap` (file reused each run); writer stops logging when configured size cap is reached to bound disk usage during diagnostics |
| smoltcp bridge remote→client path now preserves partial write tails across polls | 2026-04-30 | `send_slice` may accept fewer bytes than requested when socket send buffer has limited room; forwarder now stores unsent remainder per TCP connection and retries later so server-originated payload bytes are not silently dropped between bridge logs and tunnel output |
| smoltcp poll thread now waits on `Interface::poll_delay()` deadlines instead of a fixed 1 ms tick | 2026-05-03 | The forwarder still preserves short-write tails and uses explicit condvar wakeups for new commands/bridge bytes, but idle sessions and backpressured flows no longer wake every millisecond when smoltcp reports a later advisory timer deadline |
| Android FFI session worker heartbeat now uses 25s interval ticks (no 50ms cycle counter) | 2026-05-09 | Replaced `tokio::time::sleep(50ms)` counter loop with `tokio::time::interval(25s)` + `MissedTickBehavior::Delay`, reducing idle CPU wakeups in Wi-Fi-only operation while keeping periodic keepalive pings |
| Android FFI session stop uses cancellation token + bounded join timeout | 2026-05-10 | Replaced atomic stop flag with `tokio_util::sync::CancellationToken` in the worker loop and switched stop teardown to a 250ms join timeout path, preventing long UI-visible hangs while still triggering cooperative shutdown |
| Android FFI cancellation now explicitly closes client transports before worker exit | 2026-05-10 | Added `ClientTransport::close()` plumbing over NaiveTCP/WebSocket transports and invoked it from the cancellation branch with a bounded timeout, so transport sockets are actively closed instead of waiting for passive drop semantics |
| Production bootstrap uses `server_public_address` from pairing as the single bootstrap endpoint for all transports | 2026-05-10 | The `host:port` in the pairing QR payload is the bootstrap endpoint for WSS/HTTPS (TCP) and HTTP/3/WireGuard (same port, UDP); no extra configuration needed; 443 is the recommended default but any port works |
| TLS trust for self-signed certs uses ed25519 signature over cert fingerprint (task 6.0.5) | 2026-05-11 | Client already holds server ed25519 public key from QR payload; if TLS cert is not system-CA-trusted, server signs SHA-256(cert DER) with its identity key and the client verifies before pinning; MITM is impossible without the private identity key; no new QR fields required; LE-issued certs skip this step |
| Client reconnect on rotated TLS cert retries cert-proof once and then reconnects with the refreshed fingerprint across HTTPS, WSS, QUIC, and H3 | 2026-05-30 | Prevents stale stored fingerprints from turning certificate rotation into a hard outage; the retry path is only enabled when the client has both a stored fingerprint and the QR-trusted server ed25519 key |
| NaiveTCP is excluded from production dial sets unless `allow_insecure_debug_transports` is explicitly enabled | 2026-05-30 | Keeps the unencrypted transport available for controlled debug scenarios while preventing it from appearing in normal Linux or Android client defaults |
| Peer-share discovery uses `mdns-sd` with explicit TXT-advertised `endpoint`, listener cert fingerprint, and server-affinity metadata in `PeerShareAdvertisement` | 2026-05-30 | Lets the consumer request a server-signed introduction for a concrete listener instance and then pin the peer QUIC certificate before handshake |
| The first provider runtime slice establishes a dedicated upstream transport per accepted peer relay instead of exporting from the existing live transport pool | 2026-05-30 | Preserves the session-layer contract and allows end-to-end peer relay validation now; provider transport-pool selection remains follow-up work in phase 7.5 |
| Peer relay upstream connections use a one-time relay-registration control frame carrying the server-signed introduction, and the server binds that dedicated provider transport to the introduced consumer session before data forwarding starts | 2026-05-30 | This preserves consumer identity at the server boundary without requiring the provider to hold consumer credentials or tag every relayed `SessionFrame`; the current runtime still uses one dedicated upstream server path per accepted peer relay |
| Android peer-share QUIC sockets use the same `SocketProtectFn` contract as other transports, and the peer runtime emits Android-visible `PeerShare:` event logs for discovery/introduction/dial outcomes | 2026-05-31 | This removed the earlier VPN hairpin symptom for peer listener traffic and made the real-device blocker concrete: mDNS discovery and signed introduction succeed, but the provider-side direct QUIC listener remains unreachable from the peer phone. App-level UDP probes now time out even with the VPN stopped and with explicit Wi-Fi-IP binds on both phones, while `ping` and `ip neigh` also fail between `192.168.1.140` and `192.168.1.250`; the next work should focus on the current LAN's direct device-to-device reachability rather than more Quinn-specific changes. |
| ShadowSocks transport deferred past v1 | 2026-05-11 | CR-8 marks it "v1 if feasible"; deferred until WSS and QUIC/HTTP3 are stable in production; censorship-resistance use case is lower priority than reliability and latency goals |
| Bootstrap API rate limiting deferred until API is implemented | 2026-05-11 | Per-IP and per-token rate limits on `/v1/bootstrap/*` are a real attack surface but premature to design before the API shape is known; interim protection comes from single-use invite tokens and device keypair binding |
| All transports dial concurrently; preferred path wins primary slot | 2026-05-11 | Sequential dialing adds startup latency equal to each failing transport's timeout; concurrent dial lets the fastest-succeeding path carry traffic immediately while slower paths complete or time out in the background; preference order (WSS > H3 > WG) is configurable and used only when multiple paths succeed simultaneously |
| WireGuard runs as in-process crypto engine with no second TUN | 2026-05-11 | Android gives one TUN fd to the VPN app; a kernel or full-userspace WG that owns its own TUN is incompatible with this model; instead `boringtun` runs inline — plaintext session frames pass through the WG crypto layer and egress as UDP datagrams, symmetric with how NaiveTCP sends over a TCP socket; scheduler sees WG as just another `ClientTransport`; inner payload is a session frame not a raw IP packet so there is no tunnel IP, no allowed-IPs, and no IP routing layer — WG is used purely for its Noise handshake and ChaCha20 encryption; standard two-peer raw-IP WG would be a separate non-bondable VPN path incompatible with CR-1/CR-2 |
| `SocketProtectFn` extended to cover UDP sockets for QUIC and WireGuard | 2026-05-11 | Existing `protect_fd()` only guarded NaiveTCP TCP sockets; QUIC and WireGuard each create UDP sockets that must also be protected before use on Android or they enter the VPN routing loop; protect callback invoked in every transport's socket-creation path; no-op on non-Android |
| Session 53: MTU 1420, persistent server identity, bootstrap server with cert-proof endpoint | 2026-05-13 | `bonded-core/src/config.rs`: `tun_mtu` default 1400→1420; added `identity_key_file` to `ServerSection` (default `/var/lib/bonded/server-identity.pem`). `bonded-core/src/auth.rs`: added `load_or_create_keypair()` (loads/generates/persists ed25519 keypair) and `sign_bytes()`. `BondedVpnService.kt`: `setMtu(1420)`. `bonded-core/src/transport.rs`: added `PrependedStream<S>` (replays HTTP headers after routing); added `ServerRoutedPlain` and `ServerRoutedTls` variants to `WebSocketStreamInner`; added `from_routed_plain`/`from_routed_tls` constructors; all match arms updated. `bonded-server/src/bootstrap.rs` (new): unified HTTP+WS listener, HTTP header routing, `GET /v1/bootstrap/cert-proof` endpoint (SHA-256 fingerprint signed by persistent identity key), WebSocket session handler. `bonded-server/src/main.rs`: `mod bootstrap` wired in; `load_websocket_tls_acceptor` returns cert DER; `run_websocket_server` removed; `BootstrapContext` constructed and passed to `run_bootstrap_websocket_server`. `bonded-server/Cargo.toml`: added `sha2`. `Cargo.toml` workspace: added `sha2 = "0.10"`. All 4 crates pass `cargo check`. |
| Direct WireGuard bootstrap now uses the bootstrap API on `server_public_address` | 2026-05-25 | `establish_wireguard_session()` no longer assumes a preconfigured WG endpoint/public key; it queries `/v1/bootstrap/capabilities`, registers the client WG key via `/v1/bootstrap/wireguard/peer`, and dials the advertised UDP endpoint. Scheme selection prefers HTTPS, but falls back to HTTP when the configured websocket address is `ws://...`, which keeps local/dev bootstrap usable without TLS while leaving production bootstrap on HTTPS. |
| WireGuard dials in wave 2 (after wave 1 WSS/H3 succeeds) not wave 1 | 2026-05-12 | Original production dial policy: WG provisioning requires a bootstrap API round-trip, so WSS and H3 were intended to establish wave 1 first and WG would join in the background. Current implementation also supports direct standalone WG bootstrap/dial for integration and explicit `preferred_protocols = ["wireguard"]` flows; final production multipath wave ordering remains a scheduler/policy decision rather than a transport limitation. |
| TUN MTU default is 1420; all transports enforce matching max frame payload | 2026-05-12 | Worst-case transport overhead is ~60 bytes (WireGuard: 32-byte WG header + outer UDP/IP); 1500 - 80 = 1420 provides safe headroom for all transport types; Android `Builder.setMtu(1420)` called at VPN bring-up before transport paths are known; each `ClientTransport` caps its frame payload to match so the outer packet never exceeds the outer network MTU |
| NaiveTCP retired from production at Phase 6 acceptance; WSS is default encrypted transport | 2026-05-12 | CR-5 requires encryption; NaiveTCP has no TLS layer; it remains available as a debug-only opt-in but must be disabled by default in production server config once WSS is stable |
| Let’s Encrypt automation is conditional on configured public domain and should be the default certificate source in managed mode | 2026-05-10 | ACME-managed certificates should feed all TLS consumers (HTTPS/WSS/H3) with hot reload; static cert files remain fallback |

---

## Blockers / Issues

| Issue | Status | Resolution |
|-------|--------|------------|
| Android `flutter build apk --debug` fails in dev container due Maven hostname resolution (`repo.maven.apache.org: No address associated with hostname`) while resolving `mobile_scanner` Gradle dependencies | **resolved** | Maven is accessible; APK builds successfully in ~3s (Gradle cache warm). Fixed notification icon (`stat_sys_vpn_ic` removed in API 34, replaced with `R.mipmap.ic_launcher`). APK is at `android/build/app/outputs/flutter-apk/app-debug.apk`. |
| Android-target Rust validation for `bonded-ffi` is blocked in this dev container because `aarch64-linux-android-clang` is unavailable while building `aws-lc-sys` | **resolved** | NDK 26.3.11579264 was already installed; configured `.cargo/config.toml` with per-target `linker`/`ar` paths and `CC_*`/`CXX_*`/`AR_*` env vars for `cc-rs`; `cargo build --target aarch64-linux-android -p bonded-ffi --release` now produces `libbonded_ffi.so`; both arm64-v8a and x86_64 `.so` files are committed to `android/android/app/src/main/jniLibs/`. |
| Android VPN connect crashed on API 35 with `MissingForegroundServiceTypeException` | **resolved** | Declared `android:foregroundServiceType="specialUse"`, added `FOREGROUND_SERVICE_SPECIAL_USE` permission and special-use subtype property, and updated `BondedVpnService` to call `startForeground(..., ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)`. |
| VPN-connected-but-no-traffic: two root causes — (A) no DNS in VPN builder, (B) routing-loop deadlock when Rust session TCP sockets were captured by the VPN TUN before transport paths could be established | **resolved** | (A) fixed by adding `addDnsServer()` calls; (B) fixed by calling `VpnService.protect(fd)` from Rust via stored JVM/GlobalRef before each `socket.connect()`. |
| Server internet egress was previously payload-echo/TCP-relay oriented and could not return real DNS/UDP tunnel traffic | **resolved** | Implemented user-space IPv4+UDP relay in `frame_forwarder` with checksum-correct packet synthesis for return traffic; validated with new unit test `forwarder_relays_ipv4_udp_payload_and_builds_response_packet` and full `bonded-server` test suite. |
| Flutter update remains blocked in this dev container due outbound network restrictions (`storage.googleapis.com` and `pub.dev`/`pub.flutter-io.cn` are not reachable) | **open** | `flutter upgrade --force` fails downloading Dart SDK; manual SDK restore attempt hit flutter-tool dependency refresh limits because hosted pub packages for newer toolchain metadata cannot be fetched from this environment. |
| Android VPN runtime looped in `connecting` with zero counters because WSS used the pre-resolved IP as its TLS identity on device | **resolved** | Added Android/Rust logcat diagnostics, installed rustls' process `CryptoProvider` during `JNI_OnLoad`, aggregated per-protocol transport failures, and split the paired hostname from the pre-resolved dial target. The client now dials `97.115.185.254:8080` while preserving `charter.codingwell.net` for TLS and cert-proof verification; verified on device with `DebugVpnActivity` showing `WebSocketTLS` established and session snapshots reaching `state=connected` with live traffic counters. |
| Android broadcast-started VPN reports running in app status but is not visible as active in system UI | **resolved** | Root cause: `Builder.establish()` can return null when VPN permission is missing/revoked; service previously logged success without null-check and status logic masked this. Fixed by failing fast when establish returns null and restoring strict `isRunning()` semantics. Current device run shows explicit error: `VpnService.Builder.establish() returned null (VPN permission missing or revoked)`. |
| Real-device local WireGuard validation against the devcontainer host is blocked by incomplete server-observed session establishment | **resolved** | Session 56 closed the remaining gap. Two independent bugs were involved: on the client, `WireGuardTransport` treated `boringtun` `TunnResult::Done` as fatal during both encapsulation retry and `format_handshake_initiation()`, which could stall otherwise-valid session establishment; on the server, the WireGuard forwarder path created a `tun_rx` receiver even when `tun_bridge` was absent, so the per-peer task immediately observed a closed channel, cleaned up the session, and caused repeated stale-runtime recreation. After fixing both sides and reconnecting the physical Android device to the local server, `http://127.0.0.1:9002/api/status` reports `sessions_count=1` with the authenticated WireGuard client key present. |
| Android peer-share status under-reported provider-side relays | **resolved** | Session 63 confirmed that peer relay establishment succeeds on-device: the Pixel logs `relay dial succeeded`, the OnePlus logs `accepted relay ...` and `registered upstream relay session`, and protected local UDP reaches the peer listener while both VPNs are active. The remaining issue was status bookkeeping: provider-side relays do not enter the worker transport list, so Android previously left `peerRelayCount=0` on the provider even while it was relaying. Fixed in `bonded-ffi` by tracking provider-side upstream-registration events in the session snapshot; the OnePlus now reports `peerRelayCount=1` after relay registration. |
| Android simultaneous Wi-Fi + cellular server uplinks are not yet functional on real devices | **open** | Session 65 proved the current blocker sits at Android's `Network` API boundary for the cellular path. After adding JNI/Kotlin routing hooks, Wi-Fi-bound sockets succeed when bound to their tracked `Network`, but the cellular tracked network (`192.0.0.4`) fails with `EPERM (Operation not permitted)` both for `Network.bindSocket(fd)` on Rust-owned sockets and for a direct `Network.getSocketFactory()` TCP debug probe to `75.164.235.136:443`. The next step is to determine why Android denies socket use on that cellular network for this app and whether a different network selection method, capability request, or platform permission model is required. |
| Android invite redeem failed against the October server with "unexpected end of file" (server log: "failed to bind websocket session after authentication … failed to receive initial session frame") | **resolved** | The October server binds a session to the first frame received after authentication (`resolve_session_binding`); the FFI redeem path only connected + authenticated + dropped, never sending a frame, so the server starved and discarded the connection when the stream closed. `redeem_invite_token` now completes the binding with the same PING/PONG discovery exchange the full client runtime performs on every path, and the FFI integration test's mock server now performs the bind so the exchange stays covered. Found on-device 2026-10-15 against the dell server (build 127). |
| Android connect died with "failed to start peer-share runtime: Invalid argument (os error 22)", tearing down the just-established server paths | **resolved** | `resolve_advertise_ip` took the first non-loopback interface address; on the phone that is an IPv6 link-local (fe80::/10) address, which `UdpSocket::bind` rejects with EINVAL because it carries no scope id. Selection now prefers a bindable IPv4 address (skipping loopback/unspecified/multicast/link-local), then any bindable address, keeping the old first-non-loopback pick as a last resort; unit tests cover the orderings. Found on-device 2026-10-15 (build 127). |
| A peer-share startup failure tore down the whole client session (fault-isolation gap behind the row above) | **resolved** | Peer-share is an enhancement layered on the session, not the session itself. Both session entry points now degrade instead of failing: the Android FFI worker records the failure in the session snapshot (`peerShareError`, surfaced in the dashboard's Peer Sharing card) and continues with direct paths only, and the shared `ClientRuntime` (Linux/CLI) logs a warning and likewise continues without peer-share. |
| Android sessions authenticated against the October server but never bound (server: "failed to receive initial session frame") | **resolved** | The October server's `resolve_session_binding` waits for an initial session frame after authentication to detect peer-relay registrations. The FFI session worker sent nothing until the 25s heartbeat, so every authenticated path was dropped at binding — zero successful bindings were ever recorded against the October server. Build 130: the FFI worker performs the startup PING/PONG session-discovery exchange on every path, adopts the server-assigned session id from the PONG, and drops paths that fail the exchange. Verified on-device 2026-10-16 (Pixel session bound via Wi-Fi + cellular WSS paths). |
| Android pairing never worked against production: `redeem_invite_token` dialed plaintext naive-TCP to the TLS bootstrap endpoint | **resolved** | Server logged TLS `InvalidContentType`; the app reported `unexpected end of file`. Build 131: redeem dials via `establish_transport_paths` and completes the binding exchange over that transport (`complete_pairing_session_binding`). First successful physical pairing + VPN connection against the production October server followed immediately (both phones, 2026-10-16). |
| Server 30s receive timeout kept killing the phones' secondary (cellular) paths | **resolved** | The FFI heartbeat pinged only the active path; idle paths received no frames and the server dropped them at its 30s receive timeout. Build 132: the heartbeat pings every established path. Verified 2026-10-17: over a 5½-minute window the server logged zero teardowns for either phone's session and both cellular paths survived. |
| Pixel peer runtime advertised the VPN tunnel address `10.8.0.2:54443`, identical on every client | **resolved** | Advertise-IP selection took the tunnel address over the LAN address, so peers could never dial the advertised endpoint. Build 132: selection prefers a candidate sharing a /24 with a path bind address. Verified 2026-10-17: Pixel advertises `192.168.1.140:54443`, and a physical peer relay formed on the home WLAN (server bound the relay transport with `relayed_via_provider=true`). |

---

## Phase 4 Android UI Implementation Session (2026-03-31)

Completed QR scanner, pairing flow, and dashboard UI:

| Item | Details |
|------|---------|
| 4.6 QR Scanner | `mobile_scanner` Flutter package with camera preview, QR detection via native platform channels, JSON payload parsing via `jsonDecode`; scanning overlay with framing guides |
| 4.7 Pairing Flow | `ServerPairingPayload` model parsing QR JSON, `PairingService` MethodChannel wrapper for Rust-side token redemption, `PairingConfirmScreen` displaying server details with confirm/cancel buttons and error display |
| 4.8 Dashboard | `DashboardScreen` with VPN status indicator, connect/disconnect toggle, connection details display, and per-device ID tracking; `HomeScreen` listing paired servers with navigation options |
| Navigation | Main.dart updated with `initialRoute`, `routes` map for static screens, `onGenerateRoute` for dynamic screens with arguments (ServerPairingPayload, deviceId, etc.); supports deep linking |
| Analysis | `flutter analyze` clean; `flutter pub get` successful with mobile_scanner ^5.2.0; all async BuildContext gaps protected with `mounted` checks |
