//! Plain C-ABI surface for desktop shells (4.95).
//!
//! The Android JNI layer (`Java_com_bonded_bonded_1app_*`) cannot serve a
//! desktop shell: Swift (macOS PacketTunnelProvider) and C++ (Windows UWP
//! plugin) need a plain C ABI. This module is that surface — thin
//! `extern "C"` wrappers over the same session internals the JNI layer
//! uses (`start_android_session`, `snapshot_json`, the pairing helpers,
//! the packet queues). It is compiled on every target, not just Android:
//! the session machinery it calls is platform-independent (the
//! Android-only pieces — JNI, logcat, socket protect/bind — stay
//! `target_os = "android"` gated inside `lib.rs`).
//!
//! Conventions (also spelled out in `include/bonded_ffi_desktop.h`):
//! - Every function returns an `i32` status: `0` is success, negative
//!   is one of the `BONDED_ERR_*` codes below. Details live in the
//!   last-error string (`bonded_session_last_error`).
//! - String outputs use caller-provided buffers. Pass `out == NULL` or
//!   `out_len == 0` to query the required length (returned as a
//!   positive byte count, excluding the NUL); pass a big enough buffer
//!   to receive the string plus its NUL. A buffer that is too small
//!   returns `BONDED_ERR_BUFFER_TOO_SMALL` and nothing is written.
//! - `bonded_tun_poll_inbound` returns `0` when the inbound queue is
//!   empty (not an error) and leaves an oversized packet queued when
//!   the caller's buffer is too small.
//! - The peer-share surface is exposed through the session config
//!   (`peerShare*` keys at start) and the snapshot JSON
//!   (`relayedPeers` per-peer counters, `paths[].peerId` for peer
//!   transports). There is no separate discovery API: discovery is
//!   mDNS-driven inside the session, and the dial-back / introduction
//!   flow is server-driven — the snapshot is where the shell reads
//!   the result. Peer sharing is day one (Tom, 2026-11-20), so none
//!   of this is deferred.
//! - The TUN fd direct-write path (`bonded_tun_set_fd`) is Unix-only.
//!   On Windows it returns `BONDED_ERR_UNSUPPORTED` and inbound
//!   packets always go through the poll queue. On Unix a shell that
//!   genuinely owns a TUN fd may install it for direct writes;
//!   shells that move packets through their own channel (the macOS
//!   PacketTunnelProvider's `NEPacketTunnelFlow`, the UWP plugin's
//!   channel) just use `bonded_tun_handle_outbound` /
//!   `bonded_tun_poll_inbound` and never call it.

use std::ffi::{c_char, c_int, CStr};
use std::ptr;
use std::slice;

use serde::Deserialize;

/// Success.
pub const BONDED_OK: i32 = 0;
/// No session is running.
pub const BONDED_ERR_NO_SESSION: i32 = -1;
/// A required pointer argument was NULL.
pub const BONDED_ERR_NULL_POINTER: i32 = -2;
/// A C string argument was not valid UTF-8.
pub const BONDED_ERR_INVALID_UTF8: i32 = -3;
/// The caller's output buffer is too small (nothing was written).
pub const BONDED_ERR_BUFFER_TOO_SMALL: i32 = -4;
/// The operation failed; see `bonded_session_last_error` for detail.
pub const BONDED_ERR_OPERATION_FAILED: i32 = -5;
/// The operation is not supported on this platform
/// (`bonded_tun_set_fd` on Windows). Only referenced from the
/// `not(unix)` branch, so it is unused on Unix builds.
#[allow(dead_code)]
pub const BONDED_ERR_UNSUPPORTED: i32 = -6;

/// Read a NUL-terminated UTF-8 C string. The caller guarantees the
/// pointer is either NULL or points at a valid NUL-terminated string.
fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, i32> {
    if ptr.is_null() {
        return Err(BONDED_ERR_NULL_POINTER);
    }
    // Safety: the caller guarantees a valid NUL-terminated C string.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().map_err(|_| BONDED_ERR_INVALID_UTF8)
}

/// Write `value` plus a terminating NUL into the caller's buffer.
/// When `out` is NULL or `out_len` is 0, return the required length
/// (bytes excluding the NUL) so the caller can size its buffer.
/// Returns the bytes written (excluding the NUL) on success.
fn write_str_to_buf(value: &str, out: *mut c_char, out_len: usize) -> i32 {
    if out.is_null() || out_len == 0 {
        return value.len() as i32;
    }
    if value.len() + 1 > out_len {
        return BONDED_ERR_BUFFER_TOO_SMALL;
    }
    // Safety: `out` is a caller-provided buffer of at least `out_len`
    // bytes, and we just proved the string plus NUL fits.
    unsafe {
        ptr::copy_nonoverlapping(value.as_ptr(), out as *mut u8, value.len());
        *out.add(value.len()) = 0;
    }
    value.len() as i32
}

/// Record a failure for `bonded_session_last_error` (shared with the
/// JNI wrappers, which read the same slot).
fn set_last_error(message: String) {
    if let Ok(mut last_error) = super::LAST_NATIVE_ERROR.lock() {
        *last_error = Some(message);
    }
}

/// Clear the last-error slot (called on success, mirroring the JNI
/// wrappers, so a stale error never survives a good call).
fn clear_last_error() {
    if let Ok(mut last_error) = super::LAST_NATIVE_ERROR.lock() {
        *last_error = None;
    }
}

fn last_error_string() -> Option<String> {
    super::LAST_NATIVE_ERROR
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

fn default_protocols() -> String {
    "h3,wireguard,wss".to_owned()
}

fn default_path_count() -> usize {
    1
}

fn default_peer_share_max_consumers() -> u32 {
    4
}

fn default_diagnostics_upload_period_secs() -> u64 {
    900
}

/// Session-start config, as one JSON object (see
/// `include/bonded_ffi_desktop.h` for the key table). The shape
/// mirrors `start_android_session`'s parameters; the JSON form keeps
/// the C boundary to a single string instead of eighteen separate
/// arguments, and new keys stay backward-compatible.
#[derive(Deserialize)]
#[serde(default)]
struct SessionConfig {
    #[serde(rename = "serverAddress")]
    server_address: String,
    #[serde(rename = "resolvedServerAddress")]
    resolved_server_address: String,
    #[serde(rename = "serverPublicKey")]
    server_public_key: String,
    #[serde(default = "default_protocols")]
    protocols: String,
    #[serde(rename = "pathCount", default = "default_path_count")]
    path_count: usize,
    #[serde(rename = "bindAddresses")]
    bind_addresses: Vec<String>,
    #[serde(rename = "cellularBindAddresses")]
    cellular_bind_addresses: Vec<String>,
    #[serde(rename = "peerShareEnabled")]
    peer_share_enabled: bool,
    #[serde(rename = "peerShareBindAddress")]
    peer_share_bind_address: String,
    #[serde(rename = "peerShareAdvertiseIp")]
    peer_share_advertise_ip: String,
    #[serde(
        rename = "peerShareMaxConsumers",
        default = "default_peer_share_max_consumers"
    )]
    peer_share_max_consumers: u32,
    #[serde(rename = "peerShareRelayBandwidthKbps")]
    peer_share_relay_bandwidth_kbps: u64,
    #[serde(rename = "diagnosticsUploadEnabled")]
    diagnostics_upload_enabled: bool,
    #[serde(
        rename = "diagnosticsUploadPeriodSecs",
        default = "default_diagnostics_upload_period_secs"
    )]
    diagnostics_upload_period_secs: u64,
    #[serde(rename = "appVersionCode")]
    app_version_code: u64,
    #[serde(rename = "storageDir")]
    storage_dir: String,
    #[serde(rename = "batterySaver")]
    battery_saver: bool,
    #[serde(rename = "trafficRules")]
    traffic_rules: serde_json::Value,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            server_address: String::new(),
            resolved_server_address: String::new(),
            server_public_key: String::new(),
            protocols: default_protocols(),
            path_count: default_path_count(),
            bind_addresses: Vec::new(),
            cellular_bind_addresses: Vec::new(),
            peer_share_enabled: false,
            peer_share_bind_address: String::new(),
            peer_share_advertise_ip: String::new(),
            peer_share_max_consumers: default_peer_share_max_consumers(),
            peer_share_relay_bandwidth_kbps: 0,
            diagnostics_upload_enabled: false,
            diagnostics_upload_period_secs: default_diagnostics_upload_period_secs(),
            app_version_code: 0,
            storage_dir: String::new(),
            battery_saver: false,
            traffic_rules: serde_json::Value::Null,
        }
    }
}

/// Start a session from one JSON config object (see the header for
/// the key table). Stops any running session first, like the JNI
/// entry point. Returns `BONDED_OK` or a negative error code.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_session_start(config_json: *const c_char) -> c_int {
    let config_json = match cstr_to_str(config_json) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let config: SessionConfig = match serde_json::from_str(config_json) {
        Ok(config) => config,
        Err(err) => {
            set_last_error(format!("bonded_session_start: invalid config JSON: {err}"));
            return BONDED_ERR_OPERATION_FAILED;
        }
    };
    if config.server_address.trim().is_empty() {
        set_last_error("bonded_session_start: serverAddress is required".to_owned());
        return BONDED_ERR_OPERATION_FAILED;
    }
    if config.server_public_key.trim().is_empty() {
        set_last_error("bonded_session_start: serverPublicKey is required".to_owned());
        return BONDED_ERR_OPERATION_FAILED;
    }
    if config.storage_dir.trim().is_empty() {
        set_last_error("bonded_session_start: storageDir is required".to_owned());
        return BONDED_ERR_OPERATION_FAILED;
    }
    let bind_addresses_json = serde_json::to_string(&config.bind_addresses)
        .unwrap_or_else(|_| "[]".to_owned());
    let cellular_bind_addresses_json =
        serde_json::to_string(&config.cellular_bind_addresses)
            .unwrap_or_else(|_| "[]".to_owned());
    let traffic_rules_json = if config.traffic_rules.is_null() {
        "{}".to_owned()
    } else {
        config.traffic_rules.to_string()
    };
    match super::start_android_session(
        &config.server_address,
        &config.resolved_server_address,
        &config.server_public_key,
        &config.protocols,
        config.path_count,
        &bind_addresses_json,
        config.peer_share_enabled,
        &config.peer_share_bind_address,
        &config.peer_share_advertise_ip,
        config.peer_share_max_consumers,
        config.peer_share_relay_bandwidth_kbps,
        config.diagnostics_upload_enabled,
        config.diagnostics_upload_period_secs,
        config.app_version_code,
        &config.storage_dir,
        config.battery_saver,
        &cellular_bind_addresses_json,
        &traffic_rules_json,
    ) {
        Ok(()) => {
            clear_last_error();
            BONDED_OK
        }
        Err(err) => {
            set_last_error(format!("bonded_session_start failed: {err}"));
            BONDED_ERR_OPERATION_FAILED
        }
    }
}

/// Stop the running session, if any. Always returns `BONDED_OK`
/// (stopping with no session running is a no-op, like the JNI
/// entry point).
#[unsafe(no_mangle)]
pub extern "C" fn bonded_session_stop() -> c_int {
    super::stop_android_session();
    BONDED_OK
}

/// Write the session snapshot JSON into the caller's buffer (see
/// `write_str_to_buf` for the sizing convention). Returns
/// `BONDED_ERR_NO_SESSION` when no session is running.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_session_snapshot(out: *mut c_char, out_len: usize) -> c_int {
    match super::get_session_snapshot_json() {
        Some(snapshot) => write_str_to_buf(&snapshot, out, out_len),
        None => BONDED_ERR_NO_SESSION,
    }
}

/// Write the last error string into the caller's buffer. Writes an
/// empty string (and returns 0) when there is no recorded error.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_session_last_error(out: *mut c_char, out_len: usize) -> c_int {
    match last_error_string() {
        Some(message) => write_str_to_buf(&message, out, out_len),
        None => write_str_to_buf("", out, out_len),
    }
}

/// Redeem an invite token against the server (pairing). Returns
/// `BONDED_OK` or a negative error code; detail in
/// `bonded_session_last_error`.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_redeem_invite_token(
    server_address: *const c_char,
    server_public_key: *const c_char,
    invite_token: *const c_char,
    storage_dir: *const c_char,
) -> c_int {
    let server_address = match cstr_to_str(server_address) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let server_public_key = match cstr_to_str(server_public_key) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let invite_token = match cstr_to_str(invite_token) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let storage_dir = match cstr_to_str(storage_dir) {
        Ok(value) => value,
        Err(code) => return code,
    };
    match super::redeem_invite_token(
        server_address,
        server_public_key,
        invite_token,
        storage_dir,
    ) {
        Ok(()) => {
            clear_last_error();
            BONDED_OK
        }
        Err(err) => {
            set_last_error(format!("bonded_redeem_invite_token failed: {err}"));
            BONDED_ERR_OPERATION_FAILED
        }
    }
}

/// Mint a bound invite for another device (QR-pairing flow),
/// authenticated by this device's existing pairing. Writes the
/// invite token into the caller's buffer.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_mint_invite_token(
    server_address: *const c_char,
    server_public_key: *const c_char,
    storage_dir: *const c_char,
    target_device_key: *const c_char,
    out: *mut c_char,
    out_len: usize,
) -> c_int {
    let server_address = match cstr_to_str(server_address) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let server_public_key = match cstr_to_str(server_public_key) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let storage_dir = match cstr_to_str(storage_dir) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let target_device_key = match cstr_to_str(target_device_key) {
        Ok(value) => value,
        Err(code) => return code,
    };
    match super::mint_invite_token(
        server_address,
        server_public_key,
        storage_dir,
        target_device_key,
    ) {
        Ok(token) => {
            clear_last_error();
            write_str_to_buf(&token, out, out_len)
        }
        Err(err) => {
            set_last_error(format!("bonded_mint_invite_token failed: {err}"));
            BONDED_ERR_OPERATION_FAILED
        }
    }
}

/// This device's public key, creating the keypair if this is the
/// first run. Writes the base64 key into the caller's buffer.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_device_public_key(
    storage_dir: *const c_char,
    out: *mut c_char,
    out_len: usize,
) -> c_int {
    let storage_dir = match cstr_to_str(storage_dir) {
        Ok(value) => value,
        Err(code) => return code,
    };
    match super::device_public_key(storage_dir) {
        Ok(key) => {
            clear_last_error();
            write_str_to_buf(&key, out, out_len)
        }
        Err(err) => {
            set_last_error(format!("bonded_device_public_key failed: {err}"));
            BONDED_ERR_OPERATION_FAILED
        }
    }
}

/// Install (or clear, with `fd < 0`) the TUN fd the worker writes
/// inbound packets to directly. Unix-only: on Windows this returns
/// `BONDED_ERR_UNSUPPORTED` and inbound packets always go through
/// the poll queue.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_tun_set_fd(fd: c_int) -> c_int {
    #[cfg(unix)]
    {
        if super::set_tun_fd(fd) {
            BONDED_OK
        } else {
            set_last_error(format!("bonded_tun_set_fd failed for fd={fd}"));
            BONDED_ERR_OPERATION_FAILED
        }
    }
    #[cfg(not(unix))]
    {
        let _ = fd;
        BONDED_ERR_UNSUPPORTED
    }
}

/// Feed one outbound packet (as read from the platform tunnel) into
/// the session. Returns `BONDED_OK`, or `BONDED_ERR_OPERATION_FAILED`
/// when no session is running (or its channel is closed).
#[unsafe(no_mangle)]
pub extern "C" fn bonded_tun_handle_outbound(packet: *const u8, len: usize) -> c_int {
    if packet.is_null() {
        return BONDED_ERR_NULL_POINTER;
    }
    // Safety: the caller guarantees `packet` points at `len` bytes.
    let bytes = unsafe { slice::from_raw_parts(packet, len) };
    if super::queue_outbound_packet(bytes.to_vec()) {
        BONDED_OK
    } else {
        BONDED_ERR_OPERATION_FAILED
    }
}

/// Drain one inbound packet (to be written to the platform tunnel)
/// into the caller's buffer. Returns the bytes written, `0` when
/// the inbound queue is empty, `BONDED_ERR_NO_SESSION` when no
/// session is running, or `BONDED_ERR_BUFFER_TOO_SMALL` when the
/// front packet does not fit — in that case the packet stays queued.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_tun_poll_inbound(out: *mut u8, out_len: usize) -> c_int {
    if out.is_null() {
        return BONDED_ERR_NULL_POINTER;
    }
    let Some(handle) = super::android_session_slot()
        .lock()
        .expect("android session slot lock poisoned")
        .as_ref()
        .map(|handle| handle.inbound_queue.clone())
    else {
        return BONDED_ERR_NO_SESSION;
    };
    let mut queue = handle
        .lock()
        .expect("android inbound queue lock poisoned");
    let Some(front) = queue.front() else {
        return 0;
    };
    if front.len() > out_len {
        return BONDED_ERR_BUFFER_TOO_SMALL;
    }
    let packet = queue.pop_front().expect("front packet was just checked");
    // Safety: `out` is a caller-provided buffer of at least `out_len`
    // bytes, and the packet was just proved to fit.
    unsafe {
        ptr::copy_nonoverlapping(packet.as_ptr(), out, packet.len());
    }
    packet.len() as c_int
}

/// Pause (`paused != 0`) or resume one direct path. Returns
/// `BONDED_OK` or `BONDED_ERR_NO_SESSION`.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_path_pause(path_index: u32, paused: c_int) -> c_int {
    if super::send_path_control(super::PathControl::Pause {
        path_index: path_index as usize,
        paused: paused != 0,
    }) {
        BONDED_OK
    } else {
        BONDED_ERR_NO_SESSION
    }
}

/// Tear one direct path's transport down and let the path
/// supervisor re-dial it in place. Returns `BONDED_OK` or
/// `BONDED_ERR_NO_SESSION`.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_path_reset(path_index: u32) -> c_int {
    if super::send_path_control(super::PathControl::Reset {
        path_index: path_index as usize,
    }) {
        BONDED_OK
    } else {
        BONDED_ERR_NO_SESSION
    }
}

/// Hand the live worker a fresh pre-resolved server address
/// ("ip:port", 4.116): the platform layer re-resolved the server
/// hostname outside a dead tunnel. The worker validates it
/// (malformed or unchanged values are ignored), swaps its own
/// config copy, and forwards it to the path supervisor for an
/// immediate re-dial. Returns `BONDED_OK` or
/// `BONDED_ERR_NO_SESSION` (no live session — the caller has
/// already persisted the fresh address, so the next session
/// (re)start picks it up anyway). A null pointer returns
/// `BONDED_ERR_INVALID_ARG`.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_refresh_server_address(
    resolved_server_address: *const c_char,
) -> c_int {
    let address = match cstr_to_str(resolved_server_address) {
        Ok(value) => value,
        Err(code) => return code,
    };
    if super::send_path_control(super::PathControl::RefreshServerAddress {
        address: address.to_owned(),
    }) {
        BONDED_OK
    } else {
        BONDED_ERR_NO_SESSION
    }
}

/// Hand the live worker a new bind-address list (an interface
/// appeared or vanished) without restarting the session. Both
/// arguments are JSON arrays of address strings. Returns
/// `BONDED_OK` or `BONDED_ERR_NO_SESSION`.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_paths_update(
    bind_addresses_json: *const c_char,
    cellular_bind_addresses_json: *const c_char,
) -> c_int {
    let bind_addresses_json = match cstr_to_str(bind_addresses_json) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let cellular_bind_addresses_json = match cstr_to_str(cellular_bind_addresses_json) {
        Ok(value) => value,
        Err(code) => return code,
    };
    if super::send_path_control(super::PathControl::PathsChanged {
        bind_addresses: super::parse_bind_address_list(bind_addresses_json),
        cellular_bind_addresses: super::parse_bind_address_list(
            cellular_bind_addresses_json,
        ),
    }) {
        BONDED_OK
    } else {
        BONDED_ERR_NO_SESSION
    }
}

/// Hand the running worker a new traffic-rules table (JSON)
/// without restarting the session. Always returns `BONDED_OK` — a
/// malformed table falls back to the default engine, so there is
/// no failure to report.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_traffic_rules_update(traffic_rules_json: *const c_char) -> c_int {
    let traffic_rules_json = match cstr_to_str(traffic_rules_json) {
        Ok(value) => value,
        Err(code) => return code,
    };
    super::set_traffic_mode_engine(traffic_rules_json);
    BONDED_OK
}

/// Hand the running worker the current per-transport grades (JSON
/// array, one entry per transport vec index). Always returns
/// `BONDED_OK` — malformed JSON clears the grades, so there is no
/// failure to report.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_path_grades_update(path_grades_json: *const c_char) -> c_int {
    let path_grades_json = match cstr_to_str(path_grades_json) {
        Ok(value) => value,
        Err(code) => return code,
    };
    super::set_path_grades(path_grades_json);
    BONDED_OK
}

/// Tell the worker whether the display is interactive (screen
/// on/off). Returns `BONDED_OK` or `BONDED_ERR_NO_SESSION`.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_display_interactive(interactive: c_int) -> c_int {
    if super::send_path_control(super::PathControl::DisplayInteractive {
        interactive: interactive != 0,
    }) {
        BONDED_OK
    } else {
        BONDED_ERR_NO_SESSION
    }
}

/// Tell the worker whether the device is in idle mode (Doze).
/// Returns `BONDED_OK` or `BONDED_ERR_NO_SESSION`.
#[unsafe(no_mangle)]
pub extern "C" fn bonded_device_idle_mode(idle: c_int) -> c_int {
    if super::send_path_control(super::PathControl::DeviceIdleMode {
        idle: idle != 0,
    }) {
        BONDED_OK
    } else {
        BONDED_ERR_NO_SESSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn c_string_helpers_reject_bad_input_and_size_buffers() {
        // NULL pointer.
        assert_eq!(
            cstr_to_str(ptr::null()),
            Err(BONDED_ERR_NULL_POINTER)
        );
        // Invalid UTF-8.
        let bad = [0xff, 0xfe, 0x00];
        assert_eq!(
            cstr_to_str(bad.as_ptr() as *const c_char),
            Err(BONDED_ERR_INVALID_UTF8)
        );
        // Valid string round-trips.
        let hello = CString::new("hello").expect("CString should build");
        assert_eq!(cstr_to_str(hello.as_ptr()), Ok("hello"));

        // Buffer sizing: a NULL/empty buffer queries the required length.
        assert_eq!(write_str_to_buf("hello", ptr::null_mut(), 0), 5);
        assert_eq!(write_str_to_buf("", ptr::null_mut(), 0), 0);
        // Too small: nothing is written, error returned.
        let mut buf = [0u8; 4];
        assert_eq!(
            write_str_to_buf("hello", buf.as_mut_ptr() as *mut c_char, buf.len()),
            BONDED_ERR_BUFFER_TOO_SMALL
        );
        assert_eq!(buf, [0u8; 4]);
        // Exact fit (string + NUL) writes and returns the length.
        let mut buf = [0u8; 6];
        assert_eq!(
            write_str_to_buf("hello", buf.as_mut_ptr() as *mut c_char, buf.len()),
            5
        );
        assert_eq!(&buf, b"hello\0");
    }

    #[test]
    fn c_api_version_is_one() {
        assert_eq!(super::super::bonded_ffi_api_version(), 1);
    }

    #[test]
    fn c_session_calls_without_a_session_report_no_session() {
        let _guard = super::super::tests::session_test_lock();
        // Make sure no session is running (a previous test may have
        // left one behind; stop is a no-op when there is none).
        assert_eq!(bonded_session_stop(), BONDED_OK);

        let mut buf = [0u8; 256];
        assert_eq!(
            bonded_session_snapshot(buf.as_mut_ptr() as *mut c_char, buf.len()),
            BONDED_ERR_NO_SESSION
        );
        assert_eq!(
            bonded_tun_poll_inbound(buf.as_mut_ptr(), buf.len()),
            BONDED_ERR_NO_SESSION
        );
        assert_eq!(
            bonded_tun_handle_outbound(b"packet".as_ptr(), 6),
            BONDED_ERR_OPERATION_FAILED
        );
        assert_eq!(bonded_path_pause(0, 1), BONDED_ERR_NO_SESSION);
        assert_eq!(bonded_path_reset(0), BONDED_ERR_NO_SESSION);
        assert_eq!(
            bonded_paths_update(
                c"[]".as_ptr(),
                c"[]".as_ptr(),
            ),
            BONDED_ERR_NO_SESSION
        );
        assert_eq!(bonded_display_interactive(1), BONDED_ERR_NO_SESSION);
        assert_eq!(bonded_device_idle_mode(1), BONDED_ERR_NO_SESSION);
        // Traffic rules and path grades never fail (they apply to
        // the global engine, not the session).
        assert_eq!(bonded_traffic_rules_update(c"{}".as_ptr()), BONDED_OK);
        assert_eq!(bonded_path_grades_update(c"[]".as_ptr()), BONDED_OK);
    }

    #[test]
    fn c_session_start_rejects_bad_config() {
        // NULL config pointer.
        assert_eq!(bonded_session_start(ptr::null()), BONDED_ERR_NULL_POINTER);
        // Not JSON.
        let bad = CString::new("not json").expect("CString should build");
        assert_eq!(
            bonded_session_start(bad.as_ptr()),
            BONDED_ERR_OPERATION_FAILED
        );
        // Missing required fields.
        let empty = CString::new("{}").expect("CString should build");
        assert_eq!(
            bonded_session_start(empty.as_ptr()),
            BONDED_ERR_OPERATION_FAILED
        );
        // The failure is recorded in the last-error string.
        let mut buf = [0u8; 256];
        let len = bonded_session_last_error(buf.as_mut_ptr() as *mut c_char, buf.len());
        assert!(len > 0);
        let message =
            std::str::from_utf8(&buf[..len as usize]).expect("error should be UTF-8");
        assert!(message.contains("serverAddress"));
    }

    #[test]
    fn c_redeem_rejects_null_pointers() {
        assert_eq!(
            bonded_redeem_invite_token(
                std::ptr::null(),
                c"server-pub".as_ptr(),
                c"token".as_ptr(),
                c"/tmp".as_ptr(),
            ),
            BONDED_ERR_NULL_POINTER
        );
        assert_eq!(
            bonded_redeem_invite_token(
                c"127.0.0.1:1".as_ptr(),
                std::ptr::null(),
                c"token".as_ptr(),
                c"/tmp".as_ptr(),
            ),
            BONDED_ERR_NULL_POINTER
        );
    }

    #[test]
    fn c_tun_set_fd_clears_and_rejects_a_bad_fd() {
        // Clearing the writer (fd < 0) always succeeds on Unix.
        assert_eq!(bonded_tun_set_fd(-1), BONDED_OK);
        // A fd that was never opened cannot be duped.
        assert_eq!(bonded_tun_set_fd(999_999), BONDED_ERR_OPERATION_FAILED);
    }

    #[test]
    fn c_device_public_key_creates_a_keypair_in_a_temp_dir() {
        let dir = super::super::tests::temp_dir_path("desktop-device-key");
        std::fs::create_dir_all(&dir).expect("storage dir should be created");
        let dir_c = CString::new(dir.to_string_lossy().as_ref())
            .expect("CString should build");
        // Query the required length first, then read.
        let needed = bonded_device_public_key(dir_c.as_ptr(), ptr::null_mut(), 0);
        assert!(needed > 0);
        let mut buf = vec![0u8; needed as usize + 1];
        let len = bonded_device_public_key(
            dir_c.as_ptr(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        );
        assert_eq!(len, needed);
        let key = std::str::from_utf8(&buf[..len as usize]).expect("key should be UTF-8");
        assert!(!key.is_empty());
        // A second call returns the same key (the keypair persists).
        let mut buf2 = vec![0u8; needed as usize + 1];
        let len2 = bonded_device_public_key(
            dir_c.as_ptr(),
            buf2.as_mut_ptr() as *mut c_char,
            buf2.len(),
        );
        assert_eq!(len2, len);
        assert_eq!(&buf2[..len2 as usize], &buf[..len as usize]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn c_mint_invite_without_a_pairing_fails_with_last_error() {
        let dir = super::super::tests::temp_dir_path("desktop-mint-no-pairing");
        std::fs::create_dir_all(&dir).expect("storage dir should be created");
        let dir_c = CString::new(dir.to_string_lossy().as_ref())
            .expect("CString should build");
        let target_c = CString::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .expect("CString should build");
        let mut buf = [0u8; 256];
        let rc = bonded_mint_invite_token(
            c"127.0.0.1:1".as_ptr(),
            c"server-pub".as_ptr(),
            dir_c.as_ptr(),
            target_c.as_ptr(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        );
        assert_eq!(rc, BONDED_ERR_OPERATION_FAILED);
        let len = bonded_session_last_error(buf.as_mut_ptr() as *mut c_char, buf.len());
        assert!(len > 0);
        let message =
            std::str::from_utf8(&buf[..len as usize]).expect("error should be UTF-8");
        assert!(message.contains("not paired"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
