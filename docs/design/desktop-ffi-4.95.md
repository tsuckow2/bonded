# 4.95 — C-ABI FFI for desktop: design note

## Decision: cfg-gated C export module inside `bonded-ffi`, NOT a new crate

The desktop C-ABI lives in `crates/bonded-ffi/src/desktop.rs`, as a
module next to the JNI layer, and the session machinery it calls is
now ungated in `crates/bonded-ffi/src/lib.rs`. A new crate
(`bonded-ffi-desktop`) was considered and rejected:

- The session worker, snapshot builder, peer-share plumbing, pairing
  helpers, packet queues, and traffic-mode engine already exist as
  ~2,000 lines of internals in `bonded-ffi`. A new crate would
  duplicate that logic or force a large refactor moving it into
  `bonded-client` (which does not own the session worker or the
  snapshot shape).
- The C-ABI is the same pattern as the JNI layer: thin wrappers over
  shared internals. The JNI wrappers translate Java types to the
  internals; the C wrappers translate C types to the same internals.
  One crate, two translation layers, one session implementation.
- `bonded-ffi` already builds `cdylib` + `staticlib` + `rlib` — the
  exact artifact shapes a desktop shell links (a Swift package links
  the dylib/staticlib; a C++ plugin links the same). No new crate
  type or build wiring was needed.
- No other crate depends on `bonded-ffi`, so widening its gate
  affects only this crate's own build. The Android build is
  unchanged: the gate was already true there, and every JNI
  function, `JNI_OnLoad`, the logcat subscriber, the log ring, the
  socket protect/bind callbacks, and the JVM/VPN-service globals
  stay `#[cfg(target_os = "android")]`.

## What changed in `lib.rs`

- The 57 `#[cfg(any(target_os = "android", test))]` attributes on
  the session machinery (imports, consts, structs, fns) were
  removed. The machinery is now compiled on every target.
- The TUN writer was generalized from Android to Unix:
  `ANDROID_TUN_WRITER` → `TUN_WRITER` (`#[cfg(unix)]`),
  `android_tun_writer_slot` → `tun_writer_slot`,
  `set_android_tun_fd` → `set_tun_fd`, and the worker's
  inbound-delivery branch went from `target_os = "android"` /
  `not(android)` to `unix` / `not(unix)`. The worker already
  branched: on Android it tries the direct-write TUN writer first
  and falls back to the inbound queue; on non-Android it always
  uses the queue. The queue path is the portable one, and it is
  what the desktop packet I/O uses. `libc` moved from an
  Android-only dep to a Unix dep (the TUN writer dups the fd).
- `LAST_NATIVE_ERROR` is now ungated (the C-ABI shares the
  last-error slot with the JNI wrappers).
- A shared `send_path_control(control: PathControl) -> bool` was
  extracted from the five JNI wrappers that duplicated the
  lock-slot-and-send pattern (pause, display interactive, device
  idle mode, reset, update paths). The JNI wrappers and the C
  wrappers both call it.
- A shared `ensure_crypto_provider()` installs the rustls ring
  provider once. It is called from `start_android_session`,
  `redeem_invite_token`, and `mint_invite_token` (the three entry
  points that open TLS connections), and `JNI_OnLoad` now calls it
  too. On desktop there is no load hook, so without this the
  worker thread panics the first time it opens a TLS connection.
  This also fixes the pre-existing test failure in
  `android_session_runtime_can_pair_and_exchange_packets` (see
  Tests). `rustls` moved from an Android-only dep to an
  unconditional dep for the same reason.
- Small cleanups the gate widening exposed (the code was always
  like this; it just was not compiled on Linux non-test before):
  `establish_naive_tcp_session` / `NaiveTcpTransport` /
  `Transport` imports are test-only (the tests module has its own
  imports), `AtomicU64` was an unused import (the struct uses
  full paths), a `///` doc comment on a `let` binding became `//`,
  the dead `diagnostics_client_build` local was removed and the
  `app_version_code` parameter renamed `_app_version_code`
  (accepted, not yet wired to diagnostics), and two unnecessary
  `mut`s plus a dead initial `Vec::new()` were removed.
  `poll_inbound_packet` and `BONDED_ERR_UNSUPPORTED` carry
  `#[allow(dead_code)]` with a comment — they are used only by the
  JNI/test path and the non-Unix branch respectively.
- The internal names keep their `android_` prefix
  (`start_android_session`, `AndroidSessionHandle`, …). They are
  private implementation details shared by both translation
  layers; renaming them across the whole file was churn with no
  behavioural value. The public C surface uses neutral names
  (`bonded_session_*`).

## The C-ABI surface (`crates/bonded-ffi/src/desktop.rs`)

- `bonded_ffi_api_version()` — already existed in `lib.rs`,
  `extern "C"`, ungated; still the version (currently 1).
- Session: `bonded_session_start(config_json)` — one JSON object
  mirroring `start_android_session`'s 18 parameters (serverAddress,
  resolvedServerAddress, serverPublicKey, protocols, pathCount,
  bindAddresses, cellularBindAddresses, peerShareEnabled,
  peerShareBindAddress, peerShareAdvertiseIp,
  peerShareMaxConsumers, peerShareRelayBandwidthKbps,
  diagnosticsUploadEnabled, diagnosticsUploadPeriodSecs,
  appVersionCode, storageDir, batterySaver, trafficRules), so new
  keys stay backward-compatible. `bonded_session_stop()`,
  `bonded_session_snapshot(out, out_len)`,
  `bonded_session_last_error(out, out_len)`.
- Pairing: `bonded_redeem_invite_token(...)`,
  `bonded_mint_invite_token(..., out, out_len)`,
  `bonded_device_public_key(storage_dir, out, out_len)`.
- Packet I/O: `bonded_tun_set_fd(fd)` (Unix only; Windows returns
  `BONDED_ERR_UNSUPPORTED`), `bonded_tun_handle_outbound(packet,
  len)`, `bonded_tun_poll_inbound(out, out_len)` (peek-then-pop,
  so a too-small buffer leaves the packet queued).
- Path controls: `bonded_path_pause`, `bonded_path_reset`,
  `bonded_paths_update`, `bonded_traffic_rules_update`,
  `bonded_path_grades_update`, `bonded_display_interactive`,
  `bonded_device_idle_mode`.
- Error convention: 0 = OK; negative `BONDED_ERR_*` codes
  (NO_SESSION -1, NULL_POINTER -2, INVALID_UTF8 -3,
  BUFFER_TOO_SMALL -4, OPERATION_FAILED -5, UNSUPPORTED -6).
  String functions use caller-provided buffers; NULL/0-length
  queries the required length (snprintf-style).
- Peer sharing (day one): exposed through the session config
  (`peerShare*` keys) and the snapshot JSON (`relayedPeers[]`
  per-peer counters, `paths[].peerId` for peer transports). There
  is no separate discovery API — discovery is mDNS-driven inside
  the session and the dial-back / introduction flow is
  server-driven; the snapshot is where the shell reads the
  result. The QUIC handshake probe (`NetworkTestReceiver`) is not
  exposed — it is a standalone diagnostic, not part of the
  session API.
- Header: `crates/bonded-ffi/include/bonded_ffi_desktop.h`, with
  the full key table, the snapshot key list, and the calling
  conventions. A C/Swift caller needs only this header plus the
  built library.

## Tests

- `bonded-ffi --lib`: **44 passed / 0 failed** (was 34/1).
  The 1 pre-existing failure is FIXED, not worked around: the
  rustls CryptoProvider panic in
  `android_session_runtime_can_pair_and_exchange_packets` is gone
  because `start_android_session` now installs the provider
  itself. Fixing the provider exposed a second latent harness
  issue in the same test: the session-start identity gate opens a
  TLS connection to the bootstrap endpoint before any path is
  established, and the plaintext test server's accept sequence
  (pair, then session) consumed the gate connection as the
  session connection. Both session tests now accept-and-drop the
  gate connection between the pair handshake and the session
  accept, with a comment. The gate runs over the default route
  (from 127.0.0.1, not the session's 127.0.0.2 bind address), so
  it must be consumed before the session accept asserts the
  peer address.
- New tests (9): 8 in `desktop.rs` — C-string/buffer helpers
  (null, invalid UTF-8, buffer-too-small, exact fit, query-size),
  API version is 1, no-session behaviour for every session/path
  call, session-start config validation (null, non-JSON, missing
  required fields + last-error text), TUN fd clear + bad fd,
  device-public-key create + persist + query-size, mint-invite
  without a pairing (fails with "not paired" in last error),
  redeem null-pointer rejection. 1 in `lib.rs` tests —
  `desktop_c_abi_session_lifecycle`, the same pair-and-exchange
  flow as the Android session test driven entirely through the C
  functions (start via JSON with peerShareEnabled=true, snapshot
  via C fn asserting connected + `relayedPeers` + `paths`,
  too-small snapshot buffer, outbound via C fn, echo back via C
  poll, stop via C fn).
- `bonded-client --lib`: 109 passed / 9 failed — identical to
  the pre-change baseline (the 9 are the known sandbox-UDP set).
  Untouched by this slice; run to confirm no regression.

## Not verified

- macOS / Windows compilation of the new code. The C-ABI is
  written platform-neutrally (Unix-gated TUN fd, `not(unix)`
  returns UNSUPPORTED), but no macOS or Windows toolchain exists
  on this VM. That is slice 4.96 (macOS core build + test
  baseline on CI, macos-latest) and the Windows CI job.
- Live desktop session (no desktop shell exists yet — that is
  4.97/4.98). The C-ABI session lifecycle is proven against the
  plaintext test server, not against a production server or a
  real PacketTunnelProvider / UWP plugin.
- The redeem path through the C-ABI against a real server: the
  production redeem dials wss first, which the plaintext test
  server cannot serve, so only argument validation is covered.
  A redeem against a TLS server is out of scope for this slice.
