# Desktop clients — scope note (Windows UWP VPN plugin + macOS)

Written 2026-11-19 overnight, from the Bonded checklist (item 21 Windows UWP
VPN Plugin, items 22/23 macOS client — 23 was an exact duplicate of 22 and
was removed). This is a scoping document, not a build plan: no code was
written for either desktop client. Nothing here is a commitment on ship date.

## What Tom asked for

- Windows: a **UWP VPN plugin** — i.e. a component for the Windows VPN
  stack (Windows.Networking.Vpn), not just a Windows desktop app with a
  bundled TUN driver.
- macOS: a macOS VPN client (no platform detail given — see open questions).

## What reuses, what is new

The Rust core (`crates/bonded-client`: session, transports, peer sharing,
grading, diagnostics) is platform-independent except for small Linux-gated
pieces (`crates/bonded-client/src/lib.rs` lines ~9–52, 251, 2729–2772:
TUN setup + `pnet_datalink` interface enumeration). The `tun` crate already
knows Windows (wintun) and macOS (utun), so the core's TUN side is a
porting job, not a rewrite. The transports (QUIC, WSS, WireGuard via
boringtun, NaiveTCP) are pure-Rust/tokio and have no Android dependency.

What does NOT reuse:

1. **The FFI layer.** `crates/bonded-ffi` (5,927 lines) is JNI throughout
   (`JNI_OnLoad`, `Java_com_bonded_bonded_1app_*`, jni 0.21) and is
   `cfg(any(target_os = "android", test))` gated. A desktop client needs
   a new plain C-ABI surface over the same core (a `bonded-ffi-desktop`
   crate, or a `cfg`-gated C export module next to the JNI one).
   `bonded_ffi_api_version` is already `extern "C"` — the versioning
   precedent exists, the session API does not.
2. **The Dart native bridge.** Every Dart service talks to Kotlin through
   `MethodChannel('bonded/native')` (pairing, path grades, traffic rules,
   background service, settings). On desktop those channels need
   Windows/macOS plugin implementations, or the services move to
   `dart:ffi` against the new C ABI. Either way it is a per-service port,
   not a flag flip.
3. **The Flutter shell.** The project is Android-only today (`android/` +
   `lib/`, no `windows/` or `macos/` runners). Generating the runners is
   cheap (`flutter create --platforms windows,macos`); making the app
   actually run on them is the work in (2) plus desktop packaging.

## Windows UWP VPN plugin — the shape

A UWP VPN plugin is a WinRT component implementing the VPN plugin
interfaces; the system loads it when the user connects the VPN profile,
and the plugin owns the tunnel. Concretely:

- **Plugin (native):** C++/WinRT component in an MSIX package. It loads
  the Rust core as a native DLL through the new C ABI, drives the session
  (bootstrap, transports, WireGuard), and moves packets between the
  plugin's channel and the core. UWP sandboxing applies: the plugin runs
  brokered, so file/network capabilities must be declared; the Rust core
  must not assume a writable home directory or raw sockets outside the
  declared capabilities.
- **UI app (Flutter Windows):** the management UI — pairing, paths,
  settings — talking to the plugin through an AppService connection.
  The Flutter app does NOT hold the tunnel; the system does.
- **Distribution:** MSIX via the Microsoft Store or sideloaded. Store
  submission needs a Microsoft Partner Center account, an app identity,
  and the VPN capability declaration reviewed by Microsoft. Sideloading
  needs the MSIX signing cert trusted on the target machine.
- **Testing:** needs a real Windows 10/11 machine (VM or hardware). No
  Windows host exists in this workspace today; the plugin cannot be built
  or tested here — the Rust core cross-compile check below is the only
  part verifiable on Linux.

## macOS client — the shape

Two candidate shapes, to be decided:

- **NetworkExtension PacketTunnelProvider** (the App Store way): the
  tunnel lives in a system extension; the app talks to it via
  `NETunnelProviderManager`. Needs an Apple Developer account, the
  NetworkExtension entitlement (approved by Apple), and a Mac to build.
- **Plain app + utun** (the direct-distribution way): the app opens
  `/dev/utun` itself and drives the core in-process. No entitlement,
  no extension — distributable as a signed .app / .dmg. Simpler by a
  lot; the cost is no App Store listing and the user grants the VPN
  permission differently (no system VPN profile).

The Flutter macOS runner + `dart:ffi` core + utun is the smallest
credible macOS slice. The NetworkExtension shape is a second slice if
the App Store matters.

**DECISION (Tom, 2026-11-20): PacketTunnelProvider, App Store path.**
The plain app + utun option is NOT App Store-viable (sandboxed apps
cannot open `/dev/utun` or change routes; only the NetworkExtension
entitlement lets the system build the tunnel). Plan rows 4.94–4.98 in
`docs/design/implementation-plan.md` carry the slices: 4.95 C-ABI FFI
(shared with Windows), 4.96 macOS core build + test baseline on CI,
4.97 PacketTunnelProvider skeleton + plumbing, 4.98 app UI + store
packaging. Open: peer sharing on day one vs single-device v1; is
there a Mac for live tunnel testing. Note: the "rely on GitHub agents"
direction in the Next steps below is SUPERSEDED — Tom reversed it
2026-11-19 ("I don't want you to use GitHub agents. Write the PR
yourself"). Desktop work is written directly by the assistant; CI
runners (macos-latest) are the build/test host, not agents.

## Next steps (in order)

1. **Rust core cross-compile check** (Linux-verifiable): add the
   `x86_64-pc-windows-gnu` target and run
   `cargo check -p bonded-client --target x86_64-pc-windows-gnu`.
   The failure list is the exact porting surface (which Linux-gated
   modules need a Windows arm, which deps don't support the target).
   Same for `aarch64-apple-darwin` / `x86_64-apple-darwin` — but the
   macOS targets need the macOS SDK for linking; `cargo check` (no
   link) still works and lists the same surface.

   **RESULT (2026-11-19 ~01:05–01:12 PST, run on this VM):** both checks
   stop at the C toolchain, before any Rust code is type-checked — the
   porting surface itself is still unmeasured.
   - Windows (`x86_64-pc-windows-gnu`, target installed via rustup):
     `ring`'s build script fails — `cc-rs` cannot find
     `x86_64-w64-mingw32-gcc`. Needs the MinGW cross-compiler
     (`apt-get install gcc-mingw-w64-x86-64`); that install asks for
     Tom's approval and is still unapproved — told to Tom 2026-11-19
     ~01:00 PST, no answer yet.
   - macOS (`aarch64-apple-darwin`, target installed via rustup):
     `aws-lc-sys`'s build script runs the host `cc` (Linux gcc) with
     Apple-only flags (`-arch arm64`, `-mmacosx-version-min=11.0`),
     which gcc rejects. Needs an Apple clang + SDK (e.g. osxcross, or
     a real Mac) as `CC_aarch64_apple_darwin`. No approval needed to
     *check* this — the blocker is the missing toolchain, not a
     permission.
   - Neither failure says anything about the Rust code yet. Once a
     toolchain exists, re-run both checks; the real list (Linux-gated
     modules, dep support) comes out of that run.

   **DIRECTION (Tom, 2026-11-19 ~08:42 PST, Bonded chat — "should you
   just rely on GitHub agents"):** yes, mostly. A GitHub agent on a
   Windows or macOS runner has MinGW / Apple clang natively, so the
   cross-compile problem goes away. Split: the agent does the
   implementation and the native build and opens a PR; the assistant
   reviews the PR and does the verification the agent can't (no bench
   phones, no Dell, no real device). The local cross-compile checks
   above stay as the record of why this route was chosen; they are not
   the path forward.
2. **C-ABI FFI design** (small doc + skeleton): the session-start /
   stop / status / diagnostics surface the desktop shells need, mirroring
   what the JNI layer exposes today. Decide whether the desktop FFI is
   a new crate or a `cfg`-gated module in `bonded-ffi`.
3. **Windows plugin skeleton**: C++/WinRT project that loads the core
   DLL and implements the plugin interfaces as stubs, on a Windows host.
   Proves packaging + Store capability declarations before any tunnel
   logic lands.
4. **macOS shape decision** (Tom): NetworkExtension vs plain utun app.
   Blocks the macOS slice; the Windows slice does not depend on it.

## Open questions for Tom

- Windows: is the Store listing required, or is sideloaded MSIX fine?
  (Store review is the long pole; sideloading skips it.)
- macOS: NetworkExtension (App Store) or plain utun app (direct)?
- Does the desktop client need peer sharing on day one, or is a
  single-device tunnel the v1 (peer sharing is the hardest part to port:
  mDNS discovery + the relay dial-back + the Diagnostics UI)?
- Is there a Windows 11 machine (or VM) and a Mac available for
  building/testing, or does that need provisioning first?
