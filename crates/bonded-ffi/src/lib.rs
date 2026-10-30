#[cfg(any(target_os = "android", test))]
use bonded_client::{
    establish_naive_tcp_session, establish_transport_paths,
    establish_transport_paths_with_observer, peer_runtime, ClientTransport,
};
#[cfg(any(target_os = "android", test))]
use bonded_core::config::ClientConfig;
#[cfg(target_os = "android")]
use bonded_core::config::SocketNetworkBindFn;
#[cfg(target_os = "android")]
use bonded_core::config::SocketProtectFn;
use bonded_core::session::SessionFrame;
#[cfg(any(target_os = "android", test))]
use bonded_core::session::{
    decode_observed_address, SessionHeader, SessionState, FLAG_MULTIPATH_RECV, FLAG_PATH_RETIRE,
    FLAG_PING, FLAG_PONG, FLAG_SESSION_EPOCH,
};
#[cfg(any(target_os = "android", test))]
use bonded_core::transport::{NaiveTcpTransport, Transport};
#[cfg(any(target_os = "android", test))]
use bytes::Bytes;
#[cfg(any(target_os = "android", test))]
use std::collections::VecDeque;
#[cfg(target_os = "android")]
use std::fs::File;
#[cfg(target_os = "android")]
use std::io::Write;
#[cfg(target_os = "android")]
use std::os::fd::FromRawFd;
#[cfg(any(target_os = "android", test))]
use std::path::PathBuf;
use std::slice;
#[cfg(any(target_os = "android", test))]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(any(target_os = "android", test))]
use std::thread::{self, JoinHandle};
#[cfg(any(target_os = "android", test))]
use std::time::Duration;
#[cfg(any(target_os = "android", test))]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(any(target_os = "android", test))]
use tokio_util::sync::CancellationToken;

mod path_supervisor;
use path_supervisor::{
    spawn_path_supervisor, PathIndexMap, PathsUpdate, RedialOutcome,
};

// Per-path connect attempts inside establish_transport_paths each carry an 8s
// timeout.  With two paths and a bind-aware attempt first, path 0 can take close
// to 16s before the inner layer reports a failure.  Give the outer wrapper 30s so
// it never races with the inner per-attempt timeouts and we always surface the
// real error message rather than a generic outer-timeout.
#[cfg(any(target_os = "android", test))]
const ANDROID_PATH_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);

// ── JVM / VPN-service globals (Android only) ────────────────────────────────

/// The JavaVM singleton stored once in JNI_OnLoad so threads can attach later.
#[cfg(target_os = "android")]
static ANDROID_JVM: OnceLock<jni::JavaVM> = OnceLock::new();

/// A global reference to the currently active BondedVpnService instance, used
/// to call `protect(fd)` on session sockets before they connect.
#[cfg(target_os = "android")]
static ANDROID_VPN_SERVICE: Mutex<Option<jni::objects::GlobalRef>> = Mutex::new(None);

/// A duplicated TUN fd owned by native code for direct inbound packet writes.
#[cfg(target_os = "android")]
static ANDROID_TUN_WRITER: OnceLock<Mutex<Option<File>>> = OnceLock::new();

#[cfg(target_os = "android")]
static LAST_NATIVE_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// Called by the JVM when the native library is first loaded.  We grab the
/// JavaVM here so we can attach arbitrary threads later.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(vm: jni::JavaVM, _: *mut std::ffi::c_void) -> jni::sys::jint {
    let _ = ANDROID_JVM.set(vm);

    // Install the rustls crypto provider (ring) once at library load time.
    // Without this rustls panics with "Could not automatically determine the
    // process-level CryptoProvider" when the worker thread first tries to open
    // a TLS connection.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Install a panic hook that writes the panic message to Android logcat so
    // panics in Rust worker threads are visible without a debugger.
    std::panic::set_hook(Box::new(|info| {
        let msg = if let Some(s) = info.payload().downcast_ref::<String>() {
            format!("PANIC at {:?}: {}", info.location(), s)
        } else if let Some(s) = info.payload().downcast_ref::<&str>() {
            format!("PANIC at {:?}: {}", info.location(), s)
        } else {
            format!("PANIC at {:?}: (non-string payload)", info.location())
        };
        // alog is not yet in scope here; call the C function directly.
        use std::ffi::CString;
        extern "C" {
            fn __android_log_write(
                prio: libc::c_int,
                tag: *const libc::c_char,
                text: *const libc::c_char,
            ) -> libc::c_int;
        }
        if let (Ok(tag), Ok(text)) = (CString::new("BondedFFI"), CString::new(msg)) {
            unsafe {
                __android_log_write(6, tag.as_ptr(), text.as_ptr());
            }
        }
    }));

    jni::sys::JNI_VERSION_1_6
}

/// Write a log line directly to Android's logcat via `__android_log_write`.
/// This works from any thread, including native threads that are not attached
/// to the JVM, so it is the right tool for Rust worker-thread diagnostics.
///
/// Priority constants (from <android/log.h>):
///   2 = VERBOSE, 3 = DEBUG, 4 = INFO, 5 = WARN, 6 = ERROR
#[cfg(target_os = "android")]
fn alog(priority: i32, msg: &str) {
    use std::ffi::CString;
    extern "C" {
        fn __android_log_write(
            prio: libc::c_int,
            tag: *const libc::c_char,
            text: *const libc::c_char,
        ) -> libc::c_int;
    }
    if let (Ok(tag), Ok(text)) = (CString::new("BondedFFI"), CString::new(msg)) {
        // SAFETY: valid null-terminated C strings passed to a standard Android API.
        unsafe {
            __android_log_write(priority, tag.as_ptr(), text.as_ptr());
        }
    }
    log_ring_append(priority, msg);
}

/// On-device diagnostic log ring. When diagnostics upload is enabled,
/// `alog` tees every line into a bounded file in app storage so the
/// periodic uploader has something durable to send (logcat alone is a
/// rotating buffer that loses exactly the evidence that matters).
#[cfg(target_os = "android")]
struct LogRing {
    path: std::path::PathBuf,
    lock: std::sync::Mutex<()>,
}

#[cfg(target_os = "android")]
static LOG_RING: std::sync::OnceLock<LogRing> = std::sync::OnceLock::new();

#[cfg(target_os = "android")]
const LOG_RING_MAX_BYTES: u64 = 2 * 1024 * 1024;
#[cfg(target_os = "android")]
const LOG_RING_KEEP_BYTES: usize = 1024 * 1024;

#[cfg(target_os = "android")]
fn init_log_ring(storage_dir: &str) {
    let path = std::path::Path::new(storage_dir)
        .join("diagnostics")
        .join("client.log");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // The path is identical across sessions; a second set() just fails.
    let _ = LOG_RING.set(LogRing {
        path,
        lock: std::sync::Mutex::new(()),
    });
}

#[cfg(target_os = "android")]
fn log_ring_append(priority: i32, msg: &str) {
    let Some(ring) = LOG_RING.get() else {
        return;
    };
    let Ok(_guard) = ring.lock.lock() else {
        return;
    };
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let line = format!("{now_ms} {priority} {msg}\n");
    use std::io::Write as _;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ring.path)
    {
        let _ = file.write_all(line.as_bytes());
    }
    if std::fs::metadata(&ring.path)
        .map(|meta| meta.len())
        .unwrap_or(0)
        > LOG_RING_MAX_BYTES
    {
        rotate_log_ring(&ring.path);
    }
}

/// Trim the ring to its newest [`LOG_RING_KEEP_BYTES`], starting at a
/// line boundary, via a temp file + rename.
#[cfg(target_os = "android")]
fn rotate_log_ring(path: &std::path::Path) {
    let Ok(contents) = std::fs::read(path) else {
        return;
    };
    if contents.len() <= LOG_RING_KEEP_BYTES {
        return;
    }
    let mut start = contents.len() - LOG_RING_KEEP_BYTES;
    while start < contents.len() && contents[start] != b'\n' {
        start += 1;
    }
    let tail = &contents[start.min(contents.len())..];
    let tmp_path = path.with_extension("log.tmp");
    if std::fs::write(&tmp_path, tail).is_ok() {
        let _ = std::fs::rename(&tmp_path, path);
    }
}

/// Current ring contents for the diagnostics uploader.
#[cfg(target_os = "android")]
fn log_ring_read() -> Option<String> {
    let ring = LOG_RING.get()?;
    let contents = std::fs::read_to_string(&ring.path).ok()?;
    if contents.is_empty() {
        None
    } else {
        Some(contents)
    }
}

/// Convenience macros that route to `alog` on Android and `eprintln!` elsewhere.
#[cfg(target_os = "android")]
macro_rules! alog_info  { ($($arg:tt)*) => { alog(4, &format!($($arg)*)); } }
#[cfg(target_os = "android")]
macro_rules! alog_warn  { ($($arg:tt)*) => { alog(5, &format!($($arg)*)); } }
#[cfg(target_os = "android")]
macro_rules! alog_error { ($($arg:tt)*) => { alog(6, &format!($($arg)*)); } }
#[cfg(not(target_os = "android"))]
#[allow(unused_macros)]
macro_rules! alog_info  { ($($arg:tt)*) => { eprintln!("[bonded-ffi] {}", format!($($arg)*)); } }
#[cfg(not(target_os = "android"))]
#[allow(unused_macros)]
macro_rules! alog_warn  { ($($arg:tt)*) => { eprintln!("[bonded-ffi] WARN: {}", format!($($arg)*)); } }
#[cfg(not(target_os = "android"))]
#[allow(unused_macros)]
macro_rules! alog_error { ($($arg:tt)*) => { eprintln!("[bonded-ffi] ERROR: {}", format!($($arg)*)); } }

/// Ask the stored VpnService to protect `fd` so the socket bypasses the VPN.
#[cfg(target_os = "android")]
fn protect_fd(fd: i32) -> bool {
    let Some(jvm) = ANDROID_JVM.get() else {
        return false;
    };
    let mut guard = match jvm.attach_current_thread_as_daemon() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let service = match ANDROID_VPN_SERVICE.lock() {
        Ok(lock) => match lock.as_ref() {
            Some(r) => r.clone(),
            None => return false,
        },
        Err(_) => return false,
    };
    let call_args = [jni::objects::JValue::Int(fd)];

    let wrapper_result = guard
        .call_method(&service, "protectSocketForNative", "(I)Z", &call_args)
        .ok()
        .and_then(|v| v.z().ok());

    let result = if let Some(value) = wrapper_result {
        value
    } else {
        // Missing wrapper method throws NoSuchMethodError into JNI; clear it before fallback.
        if guard.exception_check().unwrap_or(false) {
            let _ = guard.exception_clear();
        }
        // Fallback for older app binaries that don't expose the wrapper method yet.
        guard
            .call_method(&service, "protect", "(I)Z", &call_args)
            .ok()
            .and_then(|v| v.z().ok())
            .unwrap_or(false)
    };
    alog_info!("protect_fd(fd={fd}) -> {result}");
    result
}

#[cfg(target_os = "android")]
fn bind_socket_to_network(fd: i32, bind_address: &str) -> bool {
    let Some(jvm) = ANDROID_JVM.get() else {
        return false;
    };
    let mut guard = match jvm.attach_current_thread_as_daemon() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let service = match ANDROID_VPN_SERVICE.lock() {
        Ok(lock) => match lock.as_ref() {
            Some(r) => r.clone(),
            None => return false,
        },
        Err(_) => return false,
    };
    let bind_address_text = bind_address.to_owned();
    let bind_address_java = match guard.new_string(bind_address) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let bind_address_object = jni::objects::JObject::from(bind_address_java);
    let call_args = [
        jni::objects::JValue::Int(fd),
        jni::objects::JValue::Object(&bind_address_object),
    ];

    let result = guard
        .call_method(
            &service,
            "bindSocketToNetworkForNative",
            "(ILjava/lang/String;)Z",
            &call_args,
        )
        .ok()
        .and_then(|v| v.z().ok())
        .unwrap_or(false);
    alog_info!("bind_socket_to_network(fd={fd}, bind_address={bind_address_text}) -> {result}");
    result
}

#[cfg(target_os = "android")]
fn android_tun_writer_slot() -> &'static Mutex<Option<File>> {
    ANDROID_TUN_WRITER.get_or_init(|| Mutex::new(None))
}

#[cfg(target_os = "android")]
fn set_android_tun_fd(fd: i32) -> bool {
    let mut guard = match android_tun_writer_slot().lock() {
        Ok(lock) => lock,
        Err(_) => return false,
    };

    if fd < 0 {
        *guard = None;
        alog_info!("Cleared native TUN writer fd");
        return true;
    }

    // Duplicate the Java-owned fd so native can own and close its copy safely.
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        alog_error!("Failed to dup TUN fd={fd}");
        return false;
    }

    // Safety: dup() returns a fresh owned fd on success.
    let file = unsafe { File::from_raw_fd(dup_fd) };
    *guard = Some(file);
    alog_info!("Set native TUN writer fd from source fd={fd}");
    true
}

#[cfg(target_os = "android")]
fn write_inbound_packet_to_tun(payload: &[u8]) -> bool {
    let mut guard = match android_tun_writer_slot().lock() {
        Ok(lock) => lock,
        Err(_) => return false,
    };
    let Some(file) = guard.as_mut() else {
        return false;
    };

    match file.write_all(payload) {
        Ok(()) => true,
        Err(err) => {
            alog_warn!("TUN write failed: {err}");
            false
        }
    }
}

#[cfg(any(target_os = "android", test))]
struct AndroidSessionHandle {
    outbound_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    inbound_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    snapshot: Arc<Mutex<AndroidSessionSnapshot>>,
    path_control_tx: tokio::sync::mpsc::UnboundedSender<PathControl>,
    cancel_token: CancellationToken,
    worker: Option<JoinHandle<()>>,
}

#[cfg(any(target_os = "android", test))]
#[derive(Clone, Debug)]
struct AndroidSessionSnapshot {
    state: String,
    server_address: String,
    active_transport: String,
    transport_count: u32,
    peer_relay_count: u32,
    accepted_peer_relay_count: u32,
    outbound_packets: u64,
    inbound_packets: u64,
    outbound_bytes: u64,
    inbound_bytes: u64,
    /// Unix timestamp in milliseconds when the session reached "connected".
    connected_at_ms: u64,
    last_error: Option<String>,
    /// Set when the peer-share runtime failed to start. The session itself
    /// keeps running without peer-share; this is informational, not fatal.
    peer_share_error: Option<String>,
    /// Per-transport stats in transport-vec order, for the app's main
    /// screen (per-path rows + graphs). Structure (which paths exist,
    /// their kinds, which is active) is refreshed by
    /// [`publish_path_stats`] wherever the transport set changes;
    /// counters are incremented in place by transport-vec index.
    path_stats: Vec<AndroidPathStat>,
    /// The most recent server-identity failure (possible interception)
    /// seen while establishing or re-dialing this session, if any. The
    /// app surfaces it as a dedicated warning naming the connection
    /// that presented the unverifiable credentials.
    interception: Option<InterceptionRecord>,
}

/// A server-identity verification failure attributed to a connection.
#[cfg(any(target_os = "android", test))]
#[derive(Clone, Debug)]
struct InterceptionRecord {
    /// Path whose connection presented the bad credentials; `None` when
    /// the failure came from the pre-session identity gate, which runs
    /// before any path exists.
    path_index: Option<usize>,
    detail: String,
    at_ms: u64,
}

/// Stats for one session transport, in transport-vec order.
#[cfg(any(target_os = "android", test))]
#[derive(Clone, Debug, Default)]
struct AndroidPathStat {
    /// Supervisor path index of this transport; `None` for peer relays,
    /// which have no path index.
    path_index: Option<usize>,
    kind: String,
    active: bool,
    /// Debug-paused via long-press (see [`PathControl`]): still
    /// connected, but outbound assignment treats it as last resort.
    paused: bool,
    outbound_bytes: u64,
    inbound_bytes: u64,
    /// Most recent heartbeat RTT in ms (0 = none measured yet). All
    /// paths are pinged on the same tick, so a pong's arrival transport
    /// identifies the path its RTT belongs to.
    last_rtt_ms: u64,
    /// Source address the server reports for this path's connection in
    /// its heartbeat pongs ("IP:port" exactly as the server sees it):
    /// the path's public egress address. `None` until a stamped pong
    /// arrives — servers older than the pong stamp never send one.
    server_seen_address: Option<String>,
}

#[cfg(any(target_os = "android", test))]
static ANDROID_SESSION: OnceLock<Mutex<Option<AndroidSessionHandle>>> = OnceLock::new();

const BONDED_FFI_OK: i32 = 0;
const BONDED_FFI_ERR_NULL_POINTER: i32 = 1;
const BONDED_FFI_ERR_DECODE: i32 = 2;

#[cfg(any(target_os = "android", test))]
const ANDROID_STOP_JOIN_TIMEOUT: Duration = Duration::from_millis(250);

#[cfg(any(target_os = "android", test))]
const ANDROID_TRANSPORT_CLOSE_TIMEOUT: Duration = Duration::from_millis(100);

#[cfg(any(target_os = "android", test))]
async fn close_client_transports(transports: &mut Vec<ClientTransport>) {
    for transport in transports.iter_mut() {
        alog_info!("Worker: closing transport for session stop");
        let close_result =
            tokio::time::timeout(ANDROID_TRANSPORT_CLOSE_TIMEOUT, transport.close()).await;
        if let Err(err) = close_result {
            eprintln!(
                "[bonded-ffi] Timed out closing transport after {:?}: {}",
                ANDROID_TRANSPORT_CLOSE_TIMEOUT, err,
            );
        } else {
            alog_info!("Worker: transport close completed");
        }
    }
    transports.clear();
}

#[repr(C)]
pub struct BondedFrameMetadata {
    pub connection_id: u32,
    pub sequence: u64,
    pub flags: u32,
    pub payload_len: usize,
}

fn decode_frame_metadata(raw: &[u8]) -> Result<BondedFrameMetadata, i32> {
    let frame = SessionFrame::decode(raw).map_err(|_| BONDED_FFI_ERR_DECODE)?;
    Ok(BondedFrameMetadata {
        connection_id: frame.header.connection_id,
        sequence: frame.header.sequence,
        flags: frame.header.flags,
        payload_len: frame.payload.len(),
    })
}

#[cfg(any(target_os = "android", test))]
fn android_session_slot() -> &'static Mutex<Option<AndroidSessionHandle>> {
    ANDROID_SESSION.get_or_init(|| Mutex::new(None))
}

#[cfg(any(target_os = "android", test))]
fn android_client_config(
    server_address: &str,
    resolved_server_address: &str,
    server_public_key: &str,
    storage_dir: &str,
) -> ClientConfig {
    let mut config = ClientConfig::default();
    let storage_root = PathBuf::from(storage_dir);
    config.client.device_name = "android-client".to_owned();
    config.client.server_public_address = server_address.to_owned();
    config.client.server_websocket_address = server_address.to_owned();
    config.client.server_resolved_address = resolved_server_address.to_owned();
    config.client.server_public_key = server_public_key.to_owned();
    config.client.preferred_protocols =
        vec!["wss".to_owned(), "h3".to_owned(), "wireguard".to_owned()];
    config.client.allow_insecure_debug_transports = false;
    config.client.private_key_path = storage_root
        .join("bonded-device-key.pem")
        .display()
        .to_string();
    config.client.public_key_path = storage_root
        .join("bonded-device-key.pub")
        .display()
        .to_string();
    config
}

#[cfg(any(target_os = "android", test))]
fn normalize_optional_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(any(target_os = "android", test))]
fn parse_protocol_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|protocol| !protocol.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(any(target_os = "android", test))]
fn parse_bind_address_list(raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(raw)
        .unwrap_or_default()
        .into_iter()
        .map(|address| address.trim().to_owned())
        .filter(|address| !address.is_empty())
        .collect()
}

#[cfg(any(target_os = "android", test))]
fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(any(target_os = "android", test))]
fn snapshot_json(snapshot: &AndroidSessionSnapshot) -> String {
    let last_error = snapshot
        .last_error
        .as_ref()
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_owned());
    let peer_share_error = snapshot
        .peer_share_error
        .as_ref()
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_owned());
    let interception = snapshot
        .interception
        .as_ref()
        .map(|record| {
            let path_index = record
                .path_index
                .map(|index| index.to_string())
                .unwrap_or_else(|| "null".to_owned());
            format!(
                "{{\"pathIndex\":{},\"detail\":\"{}\",\"atMs\":{}}}",
                path_index,
                escape_json(&record.detail),
                record.at_ms,
            )
        })
        .unwrap_or_else(|| "null".to_owned());
    let paths = snapshot
        .path_stats
        .iter()
        .map(|stat| {
            let path_index = stat
                .path_index
                .map(|index| index.to_string())
                .unwrap_or_else(|| "null".to_owned());
            let server_seen = stat
                .server_seen_address
                .as_ref()
                .map(|addr| format!("\"{}\"", escape_json(addr)))
                .unwrap_or_else(|| "null".to_owned());
            format!(
                "{{\"pathIndex\":{},\"kind\":\"{}\",\"active\":{},\"paused\":{},\"outboundBytes\":{},\"inboundBytes\":{},\"lastRttMs\":{},\"serverSeenAddress\":{}}}",
                path_index,
                escape_json(&stat.kind),
                stat.active,
                stat.paused,
                stat.outbound_bytes,
                stat.inbound_bytes,
                stat.last_rtt_ms,
                server_seen,
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "{{\"state\":\"{}\",\"serverAddress\":\"{}\",\"activeTransport\":\"{}\",\"transportCount\":{},\"peerRelayCount\":{},\"outboundPackets\":{},\"inboundPackets\":{},\"outboundBytes\":{},\"inboundBytes\":{},\"connectedAtMs\":{},\"lastError\":{},\"peerShareError\":{},\"interception\":{},\"paths\":[{}]}}",
        escape_json(&snapshot.state),
        escape_json(&snapshot.server_address),
        escape_json(&snapshot.active_transport),
        snapshot.transport_count,
        snapshot.peer_relay_count,
        snapshot.outbound_packets,
        snapshot.inbound_packets,
        snapshot.outbound_bytes,
        snapshot.inbound_bytes,
        snapshot.connected_at_ms,
        last_error,
        peer_share_error,
        interception,
        paths,
    )
}

#[cfg(any(target_os = "android", test))]
fn update_snapshot(
    snapshot: &Arc<Mutex<AndroidSessionSnapshot>>,
    update: impl FnOnce(&mut AndroidSessionSnapshot),
) {
    let mut guard = snapshot
        .lock()
        .expect("android session snapshot lock poisoned");
    update(&mut guard);
}

#[cfg(any(target_os = "android", test))]
fn client_transport_kind(transport: &ClientTransport) -> &'static str {
    match transport {
        ClientTransport::NaiveTcp(_) => "NaiveTCP",
        ClientTransport::WebSocket(_) => "WebSocketTLS",
        ClientTransport::Quic(_) => "QUIC",
        ClientTransport::PeerRelay { .. } => "PeerRelay",
        ClientTransport::WireGuard(_) => "WireGuard",
    }
}

/// Indices of the direct (non-peer-relay) transports, in vec order.
/// These are the paths eligible for multipath flow spreading; relay
/// transports keep active/standby semantics.
#[cfg(any(target_os = "android", test))]
fn direct_transport_indices(transports: &[ClientTransport]) -> Vec<usize> {
    transports
        .iter()
        .enumerate()
        .filter(|(_, transport)| {
            !matches!(transport, ClientTransport::PeerRelay { .. })
        })
        .map(|(index, _)| index)
        .collect()
}

/// Diff a path-set change against the worker's desired-path map
/// (`path_index -> bind address`). Returns `(removed, added)`:
/// indexes whose address vanished, and `(index, address)` pairs for
/// addresses that appeared, assigned the lowest index used by
/// neither the desired map (after removals) nor any live transport
/// (so a returning interface reuses its old index when it is free,
/// keeping pause flags and snapshot rows stable). Addresses already
/// desired are untouched even if their position in the new list
/// moved; duplicates in the new list are ignored after the first
/// occurrence. Unbound paths (no map entry) are never removed by a
/// diff — they have no address to match on.
#[cfg(any(target_os = "android", test))]
fn diff_path_addresses(
    current: &std::collections::HashMap<usize, String>,
    used_indexes: &std::collections::HashSet<usize>,
    new_list: &[String],
) -> (Vec<usize>, Vec<(usize, String)>) {
    let new_set: std::collections::HashSet<&str> =
        new_list.iter().map(String::as_str).collect();
    let mut removed: Vec<usize> = current
        .iter()
        .filter(|(_, address)| !new_set.contains(address.as_str()))
        .map(|(index, _)| *index)
        .collect();
    removed.sort_unstable();
    let removed_set: std::collections::HashSet<usize> =
        removed.iter().copied().collect();
    let mut used: std::collections::HashSet<usize> = used_indexes
        .difference(&removed_set)
        .copied()
        .collect();
    let mut seen: std::collections::HashSet<&str> =
        current.values().map(String::as_str).collect();
    let mut added = Vec::new();
    for address in new_list {
        if seen.insert(address.as_str()) {
            let mut index = 0;
            while used.contains(&index) {
                index += 1;
            }
            used.insert(index);
            added.push((index, address.clone()));
        }
    }
    (removed, added)
}

/// Debug controls for one direct path, sent from the app (long-press on
/// a path row) to the worker loop.
#[cfg(any(target_os = "android", test))]
enum PathControl {
    /// Pause (`paused = true`) or resume a path. A paused path stays
    /// in the transport set — heartbeats, session binding and inbound
    /// traffic are untouched — but outbound flow assignment treats it
    /// as a last resort (see [`order_candidates_for_send`]), so it
    /// carries ~no traffic while a healthy path exists.
    Pause { path_index: usize, paused: bool },
    /// Tear a path's transport down and let the path supervisor
    /// re-dial it in place (multi-path sessions). On a single-path
    /// session there is no supervisor, so emptying the transport set
    /// errors the session and the platform layer restarts it.
    Reset { path_index: usize },
    /// A network path-set change (an interface appeared or
    /// vanished): surgically add/remove direct paths WITHOUT
    /// restarting the session, so surviving transports (e.g. the
    /// cellular QUIC connection when Wi-Fi dies) are never
    /// recreated. Removed paths are closed, retired server-side
    /// over a surviving frame transport, and forgotten by the
    /// supervisor; added paths are dialed by the supervisor (which
    /// is spawned mid-session if the session started single-path).
    /// Diffing is by bind address (see [`diff_path_addresses`]):
    /// unbound paths are never removed by a path-set change, and a
    /// path's paused flag is kept across its removal (pause is a
    /// per-index debugging intent, and the index is reused when
    /// the interface returns).
    PathsChanged { bind_addresses: Vec<String> },
}

/// Order direct-transport candidates for one outbound packet's
/// try-list. Healthy paths keep today's hash rotation; paused paths
/// move to the end, tried only after every healthy path failed to
/// send. When every candidate is paused the rotation covers all of
/// them, so pausing everything degrades to today's behavior instead
/// of blackholing the session.
#[cfg(any(target_os = "android", test))]
fn order_candidates_for_send(
    candidates: Vec<usize>,
    is_paused: impl Fn(usize) -> bool,
    flow_hash: u64,
) -> Vec<usize> {
    let (mut healthy, mut paused): (Vec<usize>, Vec<usize>) =
        candidates.into_iter().partition(|&index| !is_paused(index));
    if healthy.is_empty() {
        if !paused.is_empty() {
            let rot = (flow_hash % paused.len() as u64) as usize;
            paused.rotate_left(rot);
        }
        paused
    } else {
        let rot = (flow_hash % healthy.len() as u64) as usize;
        healthy.rotate_left(rot);
        healthy.extend(paused);
        healthy
    }
}

/// Poll every transport's `recv()` concurrently and return the frames
/// that complete: the first one awaited, plus whatever else is already
/// buffered (bounded drain, no waiting). Every transport impl's `recv()`
/// is cancel-safe (persistent read buffers / datagram atomicity), so
/// dropping the still-pending futures when the caller's `select!` picks
/// another branch loses nothing.
///
/// Events carry their transport's vec index at poll time. Callers must
/// process removals carefully (errors in descending index order) because
/// removing a transport shifts the indices above it.
#[cfg(any(target_os = "android", test))]
async fn recv_batch(
    transports: &mut [ClientTransport],
) -> Vec<(usize, anyhow::Result<SessionFrame>)> {
    use futures_util::future::FutureExt;
    use futures_util::stream::{FuturesUnordered, StreamExt};

    if transports.is_empty() {
        std::future::pending::<()>().await;
        unreachable!("recv_batch resumed with no transports");
    }
    let mut set: FuturesUnordered<_> = transports
        .iter_mut()
        .enumerate()
        .map(|(index, transport)| async move { (index, transport.recv().await) })
        .collect();
    let mut events = Vec::new();
    if let Some(first) = set.next().await {
        events.push(first);
    }
    while events.len() < 64 {
        match set.next().now_or_never() {
            Some(Some(event)) => events.push(event),
            _ => break,
        }
    }
    events
}

#[cfg(any(target_os = "android", test))]
fn sync_transport_snapshot(
    snapshot: &Arc<Mutex<AndroidSessionSnapshot>>,
    transports: &[ClientTransport],
    active_index: usize,
) {
    let active_transport = transports
        .get(active_index)
        .map(client_transport_kind)
        .unwrap_or("Unknown")
        .to_owned();
    // Count distinct peers, not legs: during a renewal overlap one peer
    // briefly holds two legs, which must not read as two relays.
    let peer_relay_count = {
        let mut peer_ids = std::collections::HashSet::new();
        let mut unscoped = 0u32;
        for transport in transports {
            if let ClientTransport::PeerRelay { peer_id, .. } = transport {
                if peer_id.is_empty() {
                    unscoped += 1;
                } else {
                    peer_ids.insert(peer_id.as_str());
                }
            }
        }
        peer_ids.len() as u32 + unscoped
    };
    update_snapshot(snapshot, |session_snapshot| {
        session_snapshot.active_transport = active_transport;
        session_snapshot.transport_count = transports.len() as u32;
        session_snapshot.peer_relay_count =
            peer_relay_count.max(session_snapshot.accepted_peer_relay_count);
    });
}

/// Whether an error text represents a server-identity verification
/// failure: the error chain carries the `server-identity-mismatch`
/// marker, or the text is the canonical user-surfaced identity error.
#[cfg(any(target_os = "android", test))]
fn is_identity_failure_text(text: &str) -> bool {
    text.contains("server-identity-mismatch")
        || text.contains("Server identity verification failed")
}

/// Record a server-identity failure (possible interception) in the
/// session snapshot for the app to surface, attributed to the path
/// whose connection presented the bad credentials (`None` for the
/// pre-session identity gate).
#[cfg(any(target_os = "android", test))]
fn record_interception(
    snapshot: &Arc<Mutex<AndroidSessionSnapshot>>,
    path_index: Option<usize>,
    detail: String,
) {
    let at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    alog_error!(
        "Server identity failure recorded for surfacing: path_index={:?} detail={}",
        path_index,
        detail
    );
    update_snapshot(snapshot, |session_snapshot| {
        session_snapshot.interception = Some(InterceptionRecord {
            path_index,
            detail,
            at_ms,
        });
    });
}

/// Per-vec-index path-index slots from the worker's path map, in the
/// shape [`publish_path_stats`] expects.
#[cfg(any(target_os = "android", test))]
fn path_index_slots(map: &PathIndexMap, len: usize) -> Vec<Option<usize>> {
    (0..len).map(|index| map.path_of(index)).collect()
}

/// Refresh the snapshot's per-path structure (which transports exist,
/// their path indexes and kinds, which is active) after a transport-set
/// change. Counters survive the refresh: direct paths are matched by
/// path index (a re-dialed path keeps its totals), peer relays by vec
/// position. Between refreshes the worker increments counters in place
/// by vec index — safe because every structural change republishes
/// before any further counter update, all within the one worker task.
#[cfg(any(target_os = "android", test))]
fn publish_path_stats(
    snapshot: &Arc<Mutex<AndroidSessionSnapshot>>,
    transports: &[ClientTransport],
    path_index_of: &[Option<usize>],
    active_index: usize,
) {
    update_snapshot(snapshot, |session_snapshot| {
        let previous = std::mem::take(&mut session_snapshot.path_stats);
        session_snapshot.path_stats = transports
            .iter()
            .enumerate()
            .map(|(index, transport)| {
                let path_index = path_index_of.get(index).copied().flatten();
                let prior = match path_index {
                    Some(path_index) => previous
                        .iter()
                        .find(|stat| stat.path_index == Some(path_index)),
                    None => previous.get(index),
                };
                AndroidPathStat {
                    path_index,
                    kind: client_transport_kind(transport).to_owned(),
                    active: index == active_index,
                    paused: prior.map(|stat| stat.paused).unwrap_or(false),
                    outbound_bytes: prior.map(|stat| stat.outbound_bytes).unwrap_or(0),
                    inbound_bytes: prior.map(|stat| stat.inbound_bytes).unwrap_or(0),
                    last_rtt_ms: prior.map(|stat| stat.last_rtt_ms).unwrap_or(0),
                    server_seen_address: prior
                        .and_then(|stat| stat.server_seen_address.clone()),
                }
            })
            .collect();
    });
}

#[cfg(any(target_os = "android", test))]
fn stop_android_session() {
    let handle = {
        let mut slot = android_session_slot()
            .lock()
            .expect("android session slot lock poisoned");
        slot.take()
    };

    if let Some(mut handle) = handle {
        update_snapshot(&handle.snapshot, |snapshot| {
            snapshot.state = "stopped".to_owned();
            snapshot.last_error = None;
        });
        handle.cancel_token.cancel();
        let _ = handle.outbound_tx.send(Vec::new());
        if let Some(worker) = handle.worker.take() {
            let (done_tx, done_rx) = std::sync::mpsc::sync_channel::<()>(1);
            thread::spawn(move || {
                let _ = worker.join();
                let _ = done_tx.send(());
            });

            if done_rx.recv_timeout(ANDROID_STOP_JOIN_TIMEOUT).is_err() {
                alog_warn!(
                    "stop_android_session: worker join timed out after {:?}; continuing teardown",
                    ANDROID_STOP_JOIN_TIMEOUT,
                );
            }
        }
    }

    // NOTE: the native TUN writer is deliberately NOT cleared here. It is
    // service-lifetime state owned by the Kotlin side's explicit
    // nativeSetTunFd calls (set when the packet-IO loop starts, cleared by
    // stopPacketIoLoop on full VPN shutdown). Clearing it on every session
    // stop wedged session recovery: a restarted session's worker found no
    // TUN writer, queued every inbound frame, and the Kotlin side never
    // drains that queue when the direct-write handoff had succeeded at
    // startup — a healthy-looking session that passed no downlink traffic
    // until a manual VPN toggle (2026-10-18).
}

#[cfg(any(target_os = "android", test))]
fn start_android_session(
    server_address: &str,
    resolved_server_address: &str,
    server_public_key: &str,
    protocol_csv: &str,
    path_count: usize,
    bind_addresses_json: &str,
    peer_share_enabled: bool,
    peer_share_bind_address: &str,
    peer_share_advertise_ip: &str,
    peer_share_max_consumers: u32,
    peer_share_relay_bandwidth_kbps: u64,
    diagnostics_upload_enabled: bool,
    diagnostics_upload_period_secs: u64,
    app_version_code: u64,
    storage_dir: &str,
) -> anyhow::Result<()> {
    #[cfg(target_os = "android")]
    if diagnostics_upload_enabled {
        init_log_ring(storage_dir);
    }
    alog_info!(
        "Starting Android session: server={} resolved={} protocols={} paths={} bind={}",
        server_address,
        resolved_server_address,
        protocol_csv,
        path_count,
        bind_addresses_json
    );

    stop_android_session();

    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let inbound_queue = Arc::new(Mutex::new(VecDeque::new()));
    let worker_inbound_queue = Arc::clone(&inbound_queue);
    let snapshot = Arc::new(Mutex::new(AndroidSessionSnapshot {
        state: "connecting".to_owned(),
        server_address: server_address.to_owned(),
        active_transport: "Connecting".to_owned(),
        transport_count: 0,
        peer_relay_count: 0,
        accepted_peer_relay_count: 0,
        outbound_packets: 0,
        inbound_packets: 0,
        outbound_bytes: 0,
        inbound_bytes: 0,
        connected_at_ms: 0,
        last_error: None,
        peer_share_error: None,
        path_stats: Vec::new(),
        interception: None,
    }));
    let worker_snapshot = Arc::clone(&snapshot);
    let cancel_token = CancellationToken::new();
    let worker_cancel_token = cancel_token.clone();
    let worker_snapshot_panic = Arc::clone(&snapshot);
    let mut config = android_client_config(
        server_address,
        resolved_server_address,
        server_public_key,
        storage_dir,
    );
    let protocols = parse_protocol_list(protocol_csv);
    let bind_addresses = parse_bind_address_list(bind_addresses_json);
    if !protocols.is_empty() {
        config.client.allow_insecure_debug_transports = protocols
            .iter()
            .any(|protocol| protocol.eq_ignore_ascii_case("naive_tcp"));
        config.client.preferred_protocols = protocols;
    }
    if !bind_addresses.is_empty() {
        config.client.path_bind_addresses = bind_addresses;
    }
    config.client.peer_share_enabled = peer_share_enabled;
    config.client.peer_share_max_consumers = peer_share_max_consumers.max(1);
    config.client.peer_share_relay_bandwidth_kbps = peer_share_relay_bandwidth_kbps;
    config.client.diagnostics_upload_enabled = diagnostics_upload_enabled;
    config.client.diagnostics_upload_period_secs = diagnostics_upload_period_secs;
    let diagnostics_client_build = app_version_code.to_string();
    if let Some(bind_address) = normalize_optional_string(peer_share_bind_address) {
        config.client.peer_share_bind_address = bind_address;
    }
    if let Some(advertise_ip) = normalize_optional_string(peer_share_advertise_ip) {
        config.client.peer_share_advertise_ip = advertise_ip;
    }
    // Wire in the socket protect callback so session sockets bypass the VPN.
    #[cfg(target_os = "android")]
    {
        config.socket_protect = Some(SocketProtectFn(Arc::new(|fd| protect_fd(fd))));
        config.socket_network_bind = Some(SocketNetworkBindFn(Arc::new(|fd, bind_address| {
            bind_socket_to_network(fd, bind_address)
        })));
    }

    let (path_control_tx, mut path_control_rx) =
        tokio::sync::mpsc::unbounded_channel::<PathControl>();
    let worker = thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                alog_error!("Failed to create tokio runtime: {}", err);
                update_snapshot(&worker_snapshot, |session_snapshot| {
                    session_snapshot.state = "error".to_owned();
                    session_snapshot.last_error =
                        Some(format!("failed to create tokio runtime: {err}"));
                });
                return;
            }
        };

        let catch_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(async move {
            // Periodic diagnostics upload: silent on success by design;
            // only failures surface here as warnings (and those warnings
            // themselves land in the ring for the next upload).
            #[cfg(target_os = "android")]
            if config.client.diagnostics_upload_enabled {
                let _diagnostics_task = bonded_client::diagnostics::spawn_diagnostics_uploader(
                    config.clone(),
                    diagnostics_client_build.clone(),
                    std::sync::Arc::new(|| log_ring_read()),
                    std::sync::Arc::new(|message: String| {
                        alog_warn!("{message}");
                    }),
                );
            }
            alog_info!("Worker: establishing transport paths");
            // Bench instrumentation (quic-probe-diag): the WAN-session
            // dials observably never invoked the network-bind callback
            // while LAN-session dials did. Record, per establishment
            // cycle, whether this worker's config actually carries the
            // callbacks — distinguishing "config lost them" from
            // "the dial path skipped them".
            alog_info!(
                "Worker: establish config callbacks protect={} network_bind={}",
                config.socket_protect.is_some(),
                config.socket_network_bind.is_some()
            );
            let requested_paths = path_count.max(1);
            // Path indexes of the transports establishment returns, in
            // lockstep with `transports` below: establishment now yields
            // whatever subset of the requested paths connected (a dead
            // path no longer vetoes the session), and the supervisor
            // needs the true indexes to re-dial the missing ones.
            let mut session_path_indexes: Vec<usize> = Vec::new();
            let mut transports = match tokio::time::timeout(
                ANDROID_PATH_ESTABLISH_TIMEOUT,
                establish_transport_paths_with_observer(&config, requested_paths, |message| {
                    alog_info!("Worker: {message}");
                    // The client emits a machine-readable marker when a
                    // path's attempt fails server-identity verification;
                    // record it for the app to surface as an interception
                    // warning attributed to that path.
                    if let Some(rest) =
                        message.strip_prefix("server-identity-mismatch path_index=")
                    {
                        if let Some((index, detail)) = rest.split_once(" detail=") {
                            if let Ok(path_index) = index.parse::<usize>() {
                                record_interception(
                                    &worker_snapshot,
                                    Some(path_index),
                                    detail.to_owned(),
                                );
                            }
                        }
                    }
                }),
            )
            .await
            {
                Ok(Ok(established)) => {
                    session_path_indexes =
                        established.iter().map(|(path_index, _)| *path_index).collect();
                    alog_info!(
                        "Transport paths established: count={} path_indexes={:?}",
                        established.len(),
                        session_path_indexes
                    );
                    let mut transports: Vec<ClientTransport> =
                        established.into_iter().map(|(_, transport)| transport).collect();
                    for (index, transport) in transports.iter().enumerate() {
                        let kind = client_transport_kind(transport);
                        alog_info!("  transport[{}] = {}", index, kind);
                    }
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    sync_transport_snapshot(&worker_snapshot, &transports, 0);
                    publish_path_stats(
                        &worker_snapshot,
                        &transports,
                        &session_path_indexes
                            .iter()
                            .map(|index| Some(*index))
                            .collect::<Vec<_>>(),
                        0,
                    );
                    update_snapshot(&worker_snapshot, |session_snapshot| {
                        session_snapshot.state = "connected".to_owned();
                        session_snapshot.connected_at_ms = now_ms;
                        session_snapshot.last_error = None;
                    });
                    transports
                }
                Ok(Err(err)) => {
                    alog_error!("Failed to establish transport paths: {}", err);
                    // Establishment returns Err only for a server-identity
                    // failure. If no per-path marker was recorded (the
                    // pre-session identity gate failed, before any path
                    // existed), record it unattributed so the app still
                    // surfaces the warning.
                    if is_identity_failure_text(&format!("{err:#}")) {
                        let already_recorded = worker_snapshot
                            .lock()
                            .expect("android session snapshot lock poisoned")
                            .interception
                            .is_some();
                        if !already_recorded {
                            record_interception(
                                &worker_snapshot,
                                None,
                                format!("{err:#}"),
                            );
                        }
                    }
                    update_snapshot(&worker_snapshot, |session_snapshot| {
                        session_snapshot.state = "error".to_owned();
                        session_snapshot.last_error = Some(err.to_string());
                    });
                    return;
                }
                Err(_) => {
                    let message = format!(
                        "timed out after {}s while establishing transport paths",
                        ANDROID_PATH_ESTABLISH_TIMEOUT.as_secs()
                    );
                    alog_error!("{}", message);
                    update_snapshot(&worker_snapshot, |session_snapshot| {
                        session_snapshot.state = "error".to_owned();
                        session_snapshot.last_error = Some(message.clone());
                    });
                    return;
                }
            };
            let (peer_transport_tx, mut peer_transport_rx) = tokio::sync::mpsc::unbounded_channel();
            let _peer_transport_hold = peer_transport_tx.clone();
            let _peer_share_runtime = if config.client.peer_share_enabled {
                let peer_snapshot = Arc::clone(&worker_snapshot);
                let peer_logger = Arc::new(move |message: String| {
                    alog_info!("PeerShare: {}", message);
                    update_snapshot(&peer_snapshot, |session_snapshot| {
                        if message == "registered upstream relay session" {
                            session_snapshot.accepted_peer_relay_count =
                                session_snapshot.accepted_peer_relay_count.saturating_add(1);
                        } else if message.starts_with("relay loop terminated:") {
                            session_snapshot.accepted_peer_relay_count =
                                session_snapshot.accepted_peer_relay_count.saturating_sub(1);
                        }
                        session_snapshot.peer_relay_count = session_snapshot
                            .peer_relay_count
                            .max(session_snapshot.accepted_peer_relay_count);
                    });
                });
                match peer_runtime::start_peer_share_runtime(&config, peer_transport_tx, Some(peer_logger)).await {
                    Ok(runtime) => Some(runtime),
                    Err(err) => {
                        // Peer-share is an enhancement, not the session itself:
                        // degrade to a direct-paths-only session instead of
                        // tearing down transports that already connected.
                        alog_error!(
                            "Peer-share runtime failed to start; continuing without peer-share: {}",
                            err
                        );
                        update_snapshot(&worker_snapshot, |session_snapshot| {
                            session_snapshot.peer_share_error = Some(err.to_string());
                        });
                        None
                    }
                }
            } else {
                None
            };
            // Complete server-side session binding on every path with an
            // initial PING/PONG discovery exchange, mirroring the Linux
            // packet loop. The server binds the session to the first frame
            // it receives after authentication (resolve_session_binding)
            // and answers the ping with a PONG carrying the authoritative
            // session id, which the frame state below adopts. Without this
            // exchange the session sent nothing until the heartbeat,
            // and any teardown inside that window (e.g. the pre-129
            // peer-share failure path) closed the transports before the
            // server ever saw a frame — the server logged "failed to
            // receive initial session frame" and no session ever bound.
            let mut session_id: u32 = 0;
            // Path index of each transports[i], in lockstep: session
            // start establishes an arbitrary subset of the requested
            // paths (their true indexes, from establishment), and every
            // removal below removes from both vectors.
            let mut candidate_paths: Vec<usize> = session_path_indexes;
            if candidate_paths.len() != transports.len() {
                // Defensive: establishment's contract is one index per
                // transport; never let a drift here corrupt the map.
                candidate_paths = (0..transports.len()).collect();
            }
            let mut path_index = 0_usize;
            // Worker epoch: one value for this worker's whole life,
            // carried on every session-start binding PING so the
            // server can retire transports left by a previous worker
            // (see FLAG_SESSION_EPOCH). Supervisor re-dials never
            // carry it (same worker, same epoch).
            let session_epoch: u64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            while path_index < transports.len() {
                let ping = SessionFrame {
                    header: SessionHeader {
                        connection_id: 0,
                        sequence: 0,
                        flags: FLAG_PING | FLAG_MULTIPATH_RECV | FLAG_SESSION_EPOCH,
                    },
                    payload: Bytes::copy_from_slice(&session_epoch.to_be_bytes()),
                };
                if let Err(err) = transports[path_index].send(ping).await {
                    alog_warn!(
                        "Worker: path {} failed during session discovery (send): {}",
                        path_index, err
                    );
                    transports.remove(path_index);
                    candidate_paths.remove(path_index);
                    continue;
                }
                match tokio::time::timeout(
                    Duration::from_secs(10),
                    transports[path_index].recv(),
                )
                .await
                {
                    Ok(Ok(frame)) if frame.header.flags & FLAG_PONG != 0 => {
                        session_id = frame.header.connection_id;
                        alog_info!(
                            "Worker: path {} bound to session {}",
                            path_index, session_id
                        );
                        path_index += 1;
                    }
                    Ok(Ok(frame)) => {
                        let message = format!(
                            "expected session announcement pong on path {path_index}, got a frame with flags={}",
                            frame.header.flags
                        );
                        alog_error!("Worker: {}", message);
                        update_snapshot(&worker_snapshot, |session_snapshot| {
                            session_snapshot.state = "error".to_owned();
                            session_snapshot.last_error = Some(message);
                        });
                        close_client_transports(&mut transports).await;
                        return;
                    }
                    Ok(Err(err)) => {
                        alog_warn!(
                            "Worker: path {} failed during session discovery (recv): {}",
                            path_index, err
                        );
                        transports.remove(path_index);
                        candidate_paths.remove(path_index);
                    }
                    Err(_) => {
                        // Old servers drop non-empty PINGs without a
                        // PONG, so an epoch binding times out against
                        // them. Retry once as a plain PING before
                        // giving up on the path; a new server answers
                        // the epoch PING, so this costs nothing there
                        // (a late epoch PONG also satisfies the retry
                        // below, since only FLAG_PONG is checked).
                        let plain_ping = SessionFrame {
                            header: SessionHeader {
                                connection_id: 0,
                                sequence: 0,
                                flags: FLAG_PING | FLAG_MULTIPATH_RECV,
                            },
                            payload: Bytes::new(),
                        };
                        let retried = match transports[path_index].send(plain_ping).await {
                            Ok(()) => {
                                match tokio::time::timeout(
                                    Duration::from_secs(10),
                                    transports[path_index].recv(),
                                )
                                .await
                                {
                                    Ok(Ok(frame))
                                        if frame.header.flags & FLAG_PONG != 0 =>
                                    {
                                        session_id = frame.header.connection_id;
                                        alog_info!(
                                            "Worker: path {} bound to session {} (plain retry)",
                                            path_index, session_id
                                        );
                                        path_index += 1;
                                        true
                                    }
                                    _ => false,
                                }
                            }
                            Err(_) => false,
                        };
                        if !retried {
                            alog_warn!(
                                "Worker: path {} timed out during session discovery",
                                path_index
                            );
                            transports.remove(path_index);
                            candidate_paths.remove(path_index);
                        }
                    }
                }
            }
            if transports.is_empty() {
                let message =
                    "all transport paths failed session discovery".to_owned();
                alog_error!("Worker: {}", message);
                update_snapshot(&worker_snapshot, |session_snapshot| {
                    session_snapshot.state = "error".to_owned();
                    session_snapshot.last_error = Some(message);
                });
                return;
            }
            sync_transport_snapshot(&worker_snapshot, &transports, 0);
            publish_path_stats(
                &worker_snapshot,
                &transports,
                &candidate_paths
                    .iter()
                    .map(|index| Some(*index))
                    .collect::<Vec<_>>(),
                0,
            );
            // F4: give every direct path a durable identity and an
            // owner. candidate_paths[i] is the path index of
            // transports[i]; the map keeps that association across the
            // worker loop's inserts/removals, and the supervisor
            // re-dials any path that is missing now or lost later.
            let mut path_index_map = PathIndexMap::new();
            for (vec_index, path_index) in candidate_paths.iter().enumerate() {
                path_index_map.insert(vec_index, *path_index);
            }
            // Debug-paused direct paths, by durable path index (not
            // vec index, which shifts on insert/remove). Paused paths
            // stay connected; only outbound assignment deprioritizes
            // them (see order_candidates_for_send).
            let mut paused_paths: std::collections::HashSet<usize> =
                std::collections::HashSet::new();
            // Desired direct paths, by durable path index: the bind
            // address for every path this session wants, whether or
            // not it established (a path missing at start is still
            // desired — the supervisor dials it). This map is the
            // path-set change's source of truth, shared with the
            // supervisor (which reads it at dial time, since the
            // session-start config is frozen). Paths with no config
            // entry are unbound (default-network dials) and have no
            // entry here; they are never removed by a path-set diff.
            let path_addresses: Arc<
                std::sync::RwLock<std::collections::HashMap<usize, String>>,
            > = Arc::new(std::sync::RwLock::new(
                (0..requested_paths)
                    .filter_map(|path_index| {
                        config
                            .client
                            .path_bind_addresses
                            .get(path_index)
                            .map(|address| (path_index, address.clone()))
                    })
                    .collect(),
            ));
            let (path_lost_tx, path_lost_rx) =
                tokio::sync::mpsc::unbounded_channel::<usize>();
            let (redial_outcome_tx, mut redial_outcome_rx) =
                tokio::sync::mpsc::unbounded_channel::<RedialOutcome>();
            let (supervisor_paths_tx, supervisor_paths_rx) =
                tokio::sync::mpsc::unbounded_channel::<PathsUpdate>();
            // Receivers are held as Options so a supervisor spawned
            // mid-session (a session that started single-path and
            // grew) can take them; the setup spawn below takes them
            // in the multi-path case. Unsent path updates buffer
            // harmlessly when no supervisor exists yet.
            let mut supervisor_paths_rx = Some(supervisor_paths_rx);
            let mut path_lost_rx = Some(path_lost_rx);
            let supervisor_log: Arc<dyn Fn(String) + Send + Sync> =
                Arc::new(|message: String| {
                    alog_info!("PathSupervisor: {message}");
                });
            let mut supervisor_present = false;
            let _path_supervisor = if requested_paths >= 2 {
                supervisor_present = true;
                Some(spawn_path_supervisor(
                    config.clone(),
                    requested_paths,
                    (0..requested_paths).collect(),
                    candidate_paths.clone(),
                    session_id,
                    worker_cancel_token.clone(),
                    path_lost_rx.take().expect("supervisor lost channel"),
                    supervisor_paths_rx.take().expect("supervisor paths channel"),
                    path_addresses.clone(),
                    redial_outcome_tx.clone(),
                    supervisor_log.clone(),
                ))
            } else {
                None
            };
            let mut active_index = 0_usize;
            let mut session = SessionState::new(session_id);
            let mut ping_sequence = 0u64;
            let mut last_ping_sent_ms: Option<u64> = None;
            // Consecutive heartbeat ping failures per direct standby
            // transport index. Indices are only stable while the
            // transport set keeps its size, so the map is cleared
            // whenever the count changes (checked each tick).
            let mut standby_ping_failures: std::collections::HashMap<usize, u8> =
                std::collections::HashMap::new();
            let mut last_transport_count = transports.len();
            // 10 s, not 25: the server reaps any transport it receives
            // nothing on for 30 s, so a 25 s cadence leaves only 5 s of
            // slack and a single doze/scheduler stall kills every idle
            // standby path (measured 2026-10-18: median direct-transport
            // lifetime 276 s in production logs).
            let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Consume the immediate first tick so the first ping fires after 25s, not instantly.
            heartbeat.tick().await;

            loop {
                tokio::select! {
                    _ = worker_cancel_token.cancelled() => {
                        alog_info!("Worker: cancellation requested");
                        close_client_transports(&mut transports).await;
                        break;
                    }
                    control = path_control_rx.recv() => {
                        match control {
                            Some(PathControl::Pause { path_index, paused }) => {
                                if paused {
                                    paused_paths.insert(path_index);
                                } else {
                                    paused_paths.remove(&path_index);
                                }
                                update_snapshot(
                                    &worker_snapshot,
                                    |session_snapshot| {
                                        for stat in session_snapshot
                                            .path_stats
                                            .iter_mut()
                                        {
                                            if stat.path_index == Some(path_index) {
                                                stat.paused = paused;
                                            }
                                        }
                                    },
                                );
                                alog_info!(
                                    "Worker: path {} {}",
                                    path_index,
                                    if paused { "paused" } else { "resumed" }
                                );
                            }
                            Some(PathControl::Reset { path_index }) => {
                                if let Some(vec_index) =
                                    path_index_map.vec_index_of(path_index)
                                {
                                    paused_paths.remove(&path_index);
                                    let mut transport =
                                        transports.remove(vec_index);
                                    let _ = transport.close().await;
                                    path_index_map.on_remove(vec_index);
                                    if vec_index < active_index {
                                        active_index -= 1;
                                    } else if vec_index == active_index
                                        && active_index >= transports.len()
                                    {
                                        active_index = 0;
                                    }
                                    sync_transport_snapshot(
                                        &worker_snapshot,
                                        &transports,
                                        active_index,
                                    );
                                    publish_path_stats(
                                        &worker_snapshot,
                                        &transports,
                                        &path_index_slots(
                                            &path_index_map,
                                            transports.len(),
                                        ),
                                        active_index,
                                    );
                                    alog_info!(
                                        "Worker: path {} reset by debug control",
                                        path_index
                                    );
                                    if transports.is_empty() {
                                        // No supervisor on a single-path
                                        // session: nothing will re-dial,
                                        // so fail the session and let the
                                        // platform layer restart it.
                                        update_snapshot(
                                            &worker_snapshot,
                                            |session_snapshot| {
                                                session_snapshot.state =
                                                    "error".to_owned();
                                                session_snapshot.last_error =
                                                    Some(format!(
                                                        "path {path_index} reset with no other transport; restarting session"
                                                    ));
                                            },
                                        );
                                        break;
                                    }
                                    let _ = path_lost_tx.send(path_index);
                                } else {
                                    alog_warn!(
                                        "Worker: reset for unknown path {}",
                                        path_index
                                    );
                                }
                            }
                            Some(PathControl::PathsChanged { bind_addresses }) => {
                                // Surgical path-set update: surviving
                                // transports are never touched (no
                                // session restart, no re-dial of
                                // healthy paths). Only remove what
                                // vanished and queue what appeared.
                                let live_indexes: std::collections::HashSet<usize> =
                                    path_index_map.path_indexes().into_iter().collect();
                                let (removed, added) = {
                                    let desired = path_addresses
                                        .read()
                                        .expect("path address map lock poisoned");
                                    diff_path_addresses(
                                        &desired,
                                        &live_indexes,
                                        &bind_addresses,
                                    )
                                };
                                if removed.is_empty() && added.is_empty() {
                                    alog_info!(
                                        "Worker: path-set change is a no-op"
                                    );
                                } else {
                                    alog_info!(
                                        "Worker: path-set change removed={:?} added={:?}",
                                        removed, added
                                    );
                                    // Capture each removed path's
                                    // server-observed address before
                                    // its transport (and snapshot
                                    // row) goes away, for the retire
                                    // frames below.
                                    let mut retire_observed: Vec<String> = Vec::new();
                                    for path_index in &removed {
                                        if let Some(vec_index) =
                                            path_index_map.vec_index_of(*path_index)
                                        {
                                            let mut observed: Option<String> = None;
                                            update_snapshot(
                                                &worker_snapshot,
                                                |session_snapshot| {
                                                    observed = session_snapshot
                                                        .path_stats
                                                        .iter()
                                                        .find(|stat| {
                                                            stat.path_index
                                                                == Some(*path_index)
                                                        })
                                                        .and_then(|stat| {
                                                            stat.server_seen_address.clone()
                                                        });
                                                },
                                            );
                                            if let Some(observed) = observed {
                                                retire_observed.push(observed);
                                            }
                                            let mut transport =
                                                transports.remove(vec_index);
                                            let _ = transport.close().await;
                                            path_index_map.on_remove(vec_index);
                                            if vec_index < active_index {
                                                active_index -= 1;
                                            } else if vec_index == active_index
                                                && active_index >= transports.len()
                                            {
                                                active_index = 0;
                                            }
                                        }
                                    }
                                    {
                                        let mut desired = path_addresses
                                            .write()
                                            .expect("path address map lock poisoned");
                                        for path_index in &removed {
                                            desired.remove(path_index);
                                        }
                                        for (path_index, address) in &added {
                                            desired.insert(*path_index, address.clone());
                                        }
                                    }
                                    let added_indexes: Vec<usize> = added
                                        .iter()
                                        .map(|(index, _)| *index)
                                        .collect();
                                    if supervisor_present {
                                        let _ = supervisor_paths_tx.send(PathsUpdate {
                                            added: added_indexes,
                                            removed: removed.clone(),
                                        });
                                    } else if !added_indexes.is_empty() {
                                        // The session started
                                        // single-path and just grew:
                                        // give it a supervisor so
                                        // the new paths get dialed.
                                        // Desired = every direct
                                        // path now wanted (map keys
                                        // plus unbound live paths);
                                        // present = the live ones.
                                        // The update below makes
                                        // the added paths due now
                                        // (instead of the 5 s
                                        // missing-at-start delay).
                                        let desired: Vec<usize> = {
                                            let map = path_addresses
                                                .read()
                                                .expect("path address map lock poisoned");
                                            let mut d: Vec<usize> =
                                                map.keys().copied().collect();
                                            for p in path_index_map.path_indexes() {
                                                if !d.contains(&p) {
                                                    d.push(p);
                                                }
                                            }
                                            d
                                        };
                                        let present =
                                            path_index_map.path_indexes();
                                        if desired.len() >= 2 {
                                            if let (Some(lost_rx), Some(paths_rx)) = (
                                                path_lost_rx.take(),
                                                supervisor_paths_rx.take(),
                                            ) {
                                                spawn_path_supervisor(
                                                    config.clone(),
                                                    requested_paths,
                                                    desired,
                                                    present,
                                                    session_id,
                                                    worker_cancel_token.clone(),
                                                    lost_rx,
                                                    paths_rx,
                                                    path_addresses.clone(),
                                                    redial_outcome_tx.clone(),
                                                    supervisor_log.clone(),
                                                );
                                                supervisor_present = true;
                                                let _ = supervisor_paths_tx.send(
                                                    PathsUpdate {
                                                        added: added_indexes,
                                                        removed: removed.clone(),
                                                    },
                                                );
                                            }
                                        }
                                    }
                                    // Retire the dead paths
                                    // server-side, batched over the
                                    // first surviving frame
                                    // transport (QUIC/WSS — a
                                    // WireGuard transport carries no
                                    // session frames, and peer
                                    // relays have no path index).
                                    // Best effort with a short cap:
                                    // if no frame transport survives
                                    // (or the send stalls), the
                                    // server-side idle timeout is
                                    // still the backstop.
                                    if !retire_observed.is_empty() {
                                        if let Some((_, survivor)) = transports
                                            .iter_mut()
                                            .enumerate()
                                            .find(|(vec_index, transport)| {
                                                path_index_map
                                                    .path_of(*vec_index)
                                                    .is_some()
                                                    && client_transport_kind(transport)
                                                        != "WireGuard"
                                            })
                                        {
                                            for observed in retire_observed {
                                                let retire = SessionFrame {
                                                    header: SessionHeader {
                                                        connection_id: session_id,
                                                        sequence: 0,
                                                        flags: FLAG_PATH_RETIRE,
                                                    },
                                                    payload: Bytes::from(
                                                        observed.into_bytes(),
                                                    ),
                                                };
                                                let _ = tokio::time::timeout(
                                                    Duration::from_millis(500),
                                                    survivor.send(retire),
                                                )
                                                .await;
                                            }
                                        }
                                    }
                                    sync_transport_snapshot(
                                        &worker_snapshot,
                                        &transports,
                                        active_index,
                                    );
                                    publish_path_stats(
                                        &worker_snapshot,
                                        &transports,
                                        &path_index_slots(
                                            &path_index_map,
                                            transports.len(),
                                        ),
                                        active_index,
                                    );
                                    if path_index_map.path_indexes().is_empty() {
                                        // No direct path left: nothing
                                        // will re-dial (and an idle
                                        // session is reaped server-side
                                        // anyway), so fail the session
                                        // and let the platform layer
                                        // restart it when an interface
                                        // returns.
                                        update_snapshot(
                                            &worker_snapshot,
                                            |session_snapshot| {
                                                session_snapshot.state =
                                                    "error".to_owned();
                                                session_snapshot.last_error =
                                                    Some("all direct paths removed by path-set change; restarting session".to_owned());
                                            },
                                        );
                                        break;
                                    }
                                }
                            }
                            None => {}
                        }
                    }
                    peer_transport = peer_transport_rx.recv() => {
                        if let Some(transport) = peer_transport {
                            let kind = client_transport_kind(&transport);
                            transports.push(transport);
                            sync_transport_snapshot(&worker_snapshot, &transports, active_index);
                            publish_path_stats(
                                &worker_snapshot,
                                &transports,
                                &path_index_slots(&path_index_map, transports.len()),
                                active_index,
                            );
                            alog_info!(
                                "Worker: added peer-share transport kind={} total={}",
                                kind,
                                transports.len()
                            );
                        }
                    }
                    redial_outcome = redial_outcome_rx.recv() => {
                        match redial_outcome {
                            Some(RedialOutcome::Bound { path_index, transport, bind_address }) => {
                                let current_address = path_addresses
                                    .read()
                                    .expect("path address map lock poisoned")
                                    .get(&path_index)
                                    .cloned();
                                if path_index_map.contains_path(path_index) {
                                    // Raced with another restore of the
                                    // same path; keep the one already in
                                    // the vec and drop the duplicate.
                                    let mut duplicate = transport;
                                    let _ = duplicate.close().await;
                                    alog_warn!(
                                        "Worker: path {} already present; closed duplicate re-dial",
                                        path_index
                                    );
                                } else if current_address.as_deref()
                                    != bind_address.as_deref()
                                {
                                    // Stale re-dial: its path was
                                    // removed, or re-addressed, by a
                                    // path-set change while the dial
                                    // was in flight (an unbound path
                                    // has None on both sides and
                                    // passes). Drop it, and tell the
                                    // supervisor it is lost after
                                    // all — otherwise the supervisor
                                    // keeps it marked Present (it
                                    // noted the Bound) and never
                                    // re-dials the current address.
                                    let mut stale = transport;
                                    let _ = stale.close().await;
                                    alog_warn!(
                                        "Worker: path {} re-dial went stale (current {:?}, dialed {:?}); closed",
                                        path_index, current_address, bind_address
                                    );
                                    let _ = path_lost_tx.send(path_index);
                                } else {
                                    transports.push(transport);
                                    path_index_map
                                        .insert(transports.len() - 1, path_index);
                                    sync_transport_snapshot(
                                        &worker_snapshot,
                                        &transports,
                                        active_index,
                                    );
                                    publish_path_stats(
                                        &worker_snapshot,
                                        &transports,
                                        &path_index_slots(
                                            &path_index_map,
                                            transports.len(),
                                        ),
                                        active_index,
                                    );
                                    alog_info!(
                                        "Worker: path {} restored by supervisor total={}",
                                        path_index,
                                        transports.len()
                                    );
                                }
                            }
                            Some(RedialOutcome::SessionDead { reason, path_index }) => {
                                alog_error!(
                                    "Worker: path supervisor reports the session is dead: {}",
                                    reason
                                );
                                if is_identity_failure_text(&reason) {
                                    record_interception(
                                        &worker_snapshot,
                                        path_index,
                                        reason.clone(),
                                    );
                                }
                                update_snapshot(&worker_snapshot, |session_snapshot| {
                                    session_snapshot.state = "error".to_owned();
                                    session_snapshot.last_error = Some(reason);
                                });
                                close_client_transports(&mut transports).await;
                                break;
                            }
                            None => {}
                        }
                    }
                    maybe_packet = outbound_rx.recv() => {
                        match maybe_packet {
                            Some(packet) => {
                                if packet.is_empty() && worker_cancel_token.is_cancelled() {
                                    alog_info!("Worker: stop signal received");
                                    break;
                                }

                                let packet_len = packet.len() as u64;
                                // Multipath spreading: pin this packet's
                                // flow to a direct transport by hash, so
                                // every direct path carries real traffic
                                // instead of only the active one. Candidates
                                // are the hashed pick first, then the other
                                // direct transports, then the active
                                // transport as a last resort (which also
                                // covers the relay-only case). With a
                                // single direct transport this reduces to
                                // exactly the pre-multipath behavior.
                                let flow = bonded_core::flow::flow_hash(&packet);
                                let frame = session.create_outbound_frame(Bytes::from(packet), 0);
                                // Paused paths go last in the try-list:
                                // they stay connected, but a healthy path
                                // is always tried first.
                                let mut candidates = order_candidates_for_send(
                                    direct_transport_indices(&transports),
                                    |vec_index| {
                                        path_index_map
                                            .path_of(vec_index)
                                            .map(|path| paused_paths.contains(&path))
                                            .unwrap_or(false)
                                    },
                                    flow,
                                );
                                if candidates.is_empty() {
                                    candidates.push(active_index);
                                } else if !candidates.contains(&active_index) {
                                    candidates.push(active_index);
                                }
                                let mut send_queue: std::collections::VecDeque<usize> =
                                    candidates.into();
                                let mut sent = false;
                                let mut sent_index: Option<usize> = None;
                                let mut fatal_error: Option<String> = None;
                                while let Some(index) = send_queue.pop_front() {
                                    match transports[index].send(frame.clone()).await {
                                        Ok(()) => {
                                            sent = true;
                                            sent_index = Some(index);
                                            break;
                                        }
                                        Err(err) => {
                                            alog_warn!(
                                                "Worker: send on transport[{}] failed: {}",
                                                index, err
                                            );
                                            if transports.len() == 1 {
                                                fatal_error = Some(err.to_string());
                                                break;
                                            }
                                            if let Some(lost_path) =
                                                path_index_map.path_of(index)
                                            {
                                                let _ = path_lost_tx.send(lost_path);
                                            }
                                            transports.remove(index);
                                            path_index_map.on_remove(index);
                                            if index < active_index {
                                                active_index -= 1;
                                            } else if index == active_index
                                                && active_index >= transports.len()
                                            {
                                                active_index = 0;
                                            }
                                            // The removal shifts every
                                            // queued candidate above the
                                            // removed index down by one.
                                            for queued in send_queue.iter_mut() {
                                                if *queued > index {
                                                    *queued -= 1;
                                                }
                                            }
                                            sync_transport_snapshot(
                                                &worker_snapshot,
                                                &transports,
                                                active_index,
                                            );
                                            publish_path_stats(
                                                &worker_snapshot,
                                                &transports,
                                                &path_index_slots(
                                                    &path_index_map,
                                                    transports.len(),
                                                ),
                                                active_index,
                                            );
                                        }
                                    }
                                }
                                if let Some(message) = fatal_error {
                                    alog_error!(
                                        "Worker: only one transport available, cannot failover"
                                    );
                                    update_snapshot(&worker_snapshot, |session_snapshot| {
                                        session_snapshot.state = "error".to_owned();
                                        session_snapshot.last_error = Some(message);
                                    });
                                    break;
                                }
                                if sent {
                                    update_snapshot(&worker_snapshot, |session_snapshot| {
                                        session_snapshot.outbound_packets = session_snapshot.outbound_packets.saturating_add(1);
                                        session_snapshot.outbound_bytes = session_snapshot.outbound_bytes.saturating_add(packet_len);
                                        if let Some(index) = sent_index {
                                            if let Some(stat) =
                                                session_snapshot.path_stats.get_mut(index)
                                            {
                                                stat.outbound_bytes =
                                                    stat.outbound_bytes.saturating_add(packet_len);
                                            }
                                        }
                                    });
                                } else {
                                    // Every candidate failed but other
                                    // transports remain: drop the frame
                                    // (the inner IP protocols tolerate
                                    // loss) and let the supervisor restore
                                    // the direct paths.
                                    alog_warn!(
                                        "Worker: dropped outbound frame after all send candidates failed"
                                    );
                                }
                            }
                            None => {
                                alog_info!("Worker: outbound channel closed");
                                break;
                            }
                        }
                    }
                    recv_events = recv_batch(&mut transports) => {
                        // Receive on EVERY transport (multipath): downlink
                        // flows may arrive on any path now that the server
                        // spreads them per-flow for clients that advertise
                        // FLAG_MULTIPATH_RECV. Data/pong frames are handled
                        // first since they change no structure; recv errors
                        // are handled afterwards in DESCENDING index order
                        // so each removal leaves the remaining error
                        // indices valid.
                        let mut errors: Vec<(usize, anyhow::Error)> = Vec::new();
                        for (index, result) in recv_events {
                            match result {
                                Ok(frame) => {
                                    // Handle heartbeat pong — don't feed it to the session reorder buffer.
                                    if frame.header.flags & FLAG_PONG != 0 {
                                        // Newer servers stamp the pong
                                        // payload with the source address
                                        // they see for this path's
                                        // connection: record it as the
                                        // path's public egress address.
                                        if let Some(observed) =
                                            decode_observed_address(&frame.payload)
                                        {
                                            let observed = observed.to_string();
                                            update_snapshot(
                                                &worker_snapshot,
                                                |session_snapshot| {
                                                    if let Some(stat) = session_snapshot
                                                        .path_stats
                                                        .get_mut(index)
                                                    {
                                                        if stat.server_seen_address.as_deref()
                                                            != Some(observed.as_str())
                                                        {
                                                            stat.server_seen_address =
                                                                Some(observed);
                                                        }
                                                    }
                                                },
                                            );
                                        }
                                        let now_ms = SystemTime::now()
                                            .duration_since(UNIX_EPOCH)
                                            .map(|d| d.as_millis() as u64)
                                            .unwrap_or(0);
                                        let rtt_ms = last_ping_sent_ms
                                            .map(|sent| now_ms.saturating_sub(sent));
                                        if let Some(rtt) = rtt_ms {
                                            alog_info!(
                                                "Heartbeat pong received: seq={} rtt={}ms",
                                                frame.header.sequence, rtt
                                            );
                                            // Every path is pinged on the
                                            // same tick, so the transport
                                            // this pong arrived on owns
                                            // this RTT.
                                            update_snapshot(&worker_snapshot, |session_snapshot| {
                                                if let Some(stat) =
                                                    session_snapshot.path_stats.get_mut(index)
                                                {
                                                    stat.last_rtt_ms = rtt;
                                                }
                                            });
                                        } else {
                                            alog_info!(
                                                "Heartbeat pong received: seq={}",
                                                frame.header.sequence
                                            );
                                        }
                                        continue;
                                    }

                                    // Deliver the response payload immediately without reordering.
                                    // At the raw-IP VPN layer the Android kernel handles its own
                                    // TCP reordering; forcing in-order delivery here causes inbound
                                    // to stall whenever the server drops a response (e.g. UDP timeout).
                                    if !frame.payload.is_empty() {
                                        let payload = frame.payload.to_vec();
                                        let payload_len = payload.len() as u64;
                                        let delivered_to_tun = {
                                            #[cfg(target_os = "android")]
                                            {
                                                write_inbound_packet_to_tun(&payload)
                                            }
                                            #[cfg(not(target_os = "android"))]
                                            {
                                                false
                                            }
                                        };
                                        if !delivered_to_tun {
                                            worker_inbound_queue
                                                .lock()
                                                .expect("android inbound queue lock poisoned")
                                                .push_back(payload);
                                        }
                                        update_snapshot(&worker_snapshot, |session_snapshot| {
                                            session_snapshot.inbound_packets = session_snapshot.inbound_packets.saturating_add(1);
                                            session_snapshot.inbound_bytes = session_snapshot.inbound_bytes.saturating_add(payload_len);
                                            if let Some(stat) =
                                                session_snapshot.path_stats.get_mut(index)
                                            {
                                                stat.inbound_bytes =
                                                    stat.inbound_bytes.saturating_add(payload_len);
                                            }
                                        });
                                    }
                                }
                                Err(err) => errors.push((index, err)),
                            }
                        }
                        errors.sort_by_key(|(index, _)| std::cmp::Reverse(*index));
                        let mut session_failed = false;
                        for (index, err) in errors {
                            alog_warn!("Worker: recv on transport[{}] failed: {}", index, err);
                            if transports.len() == 1 {
                                alog_error!("Worker: only one transport, cannot failover");
                                update_snapshot(&worker_snapshot, |session_snapshot| {
                                    session_snapshot.state = "error".to_owned();
                                    session_snapshot.last_error = Some(err.to_string());
                                });
                                session_failed = true;
                                break;
                            }

                            if let Some(lost_path) =
                                path_index_map.path_of(index)
                            {
                                let _ = path_lost_tx.send(lost_path);
                            }
                            let was_active = index == active_index;
                            transports.remove(index);
                            path_index_map.on_remove(index);
                            if index < active_index {
                                active_index -= 1;
                            } else if was_active && active_index >= transports.len() {
                                active_index = 0;
                            }
                            sync_transport_snapshot(&worker_snapshot, &transports, active_index);
                            publish_path_stats(
                                &worker_snapshot,
                                &transports,
                                &path_index_slots(&path_index_map, transports.len()),
                                active_index,
                            );
                            if was_active {
                                alog_warn!("Worker: failover from recv error on transport[{}] to transport[{}]", index, active_index);
                            }
                        }
                        if session_failed {
                            break;
                        }
                    }
                    _ = heartbeat.tick() => {
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0);
                        let ping = SessionFrame {
                            header: bonded_core::session::SessionHeader {
                                connection_id: 0,
                                sequence: ping_sequence,
                                flags: FLAG_PING | FLAG_MULTIPATH_RECV,
                            },
                            payload: Bytes::new(),
                        };
                        alog_info!("Sending heartbeat ping seq={}", ping_sequence);
                        // Ping EVERY path, not just the active one: the
                        // server closes any transport it receives nothing
                        // on for 30s, so an active-path-only heartbeat lets
                        // every idle path be torn down and re-dialed in a
                        // loop, leaving the session single-path in practice.
                        if transports.len() != last_transport_count {
                            standby_ping_failures.clear();
                            last_transport_count = transports.len();
                        }
                        let mut any_sent = false;
                        for (path_index, transport) in transports.iter_mut().enumerate() {
                            match transport.send(ping.clone()).await {
                                Ok(()) => {
                                    any_sent = true;
                                    standby_ping_failures.remove(&path_index);
                                }
                                Err(err) => {
                                    alog_warn!(
                                        "Heartbeat ping send failed on path {}: {}",
                                        path_index,
                                        err
                                    );
                                    // Standby direct paths only: the
                                    // active path's failures drive
                                    // failover directly, and peer relays
                                    // have their own retirement below.
                                    if path_index != active_index
                                        && !matches!(
                                            transport,
                                            ClientTransport::PeerRelay { .. }
                                        )
                                    {
                                        *standby_ping_failures
                                            .entry(path_index)
                                            .or_default() += 1;
                                    }
                                }
                            }
                        }
                        if any_sent {
                            last_ping_sent_ms = Some(now_ms);
                            ping_sequence = ping_sequence.wrapping_add(1);
                        }
                        // Retire peer-relay transports that are not
                        // carrying traffic and can no longer recover: the
                        // relay's introduction has expired (the provider
                        // can never re-register it), or its QUIC
                        // connection to the provider has closed. The
                        // worker only recv()s the active path, so neither
                        // condition surfaces here on its own — sends keep
                        // succeeding into a dead connection's buffers
                        // while the provider's re-registered upstreams
                        // starve at the server. Closing the transport
                        // fires the relay's close notifier, which lets
                        // the peer runtime un-mark the peer and
                        // re-discover it. (Observed 2026-10-17: an expired
                        // dead relay lingered ~15 minutes overnight; a
                        // closed-leg relay churned provider upstreams
                        // every 30 s until its introduction expired.)
                        let now_secs = now_ms / 1000;
                        let mut retired_any = false;
                        let mut index = transports.len();
                        while index > 0 {
                            index -= 1;
                            if index == active_index {
                                continue;
                            }
                            let expired = transports[index].peer_relay_expired(now_secs);
                            let connection_closed =
                                transports[index].peer_relay_connection_closed();
                            // A direct standby whose heartbeat ping has
                            // failed on two consecutive ticks is dead:
                            // evict it so the snapshot stops counting it
                            // and failover never promotes a corpse. (The
                            // server reaps silently, so an un-evicted
                            // zombie otherwise lingers indefinitely; the
                            // removal below also notifies the F4 path
                            // supervisor, which re-dials the path in
                            // place.)
                            let standby_dead = !matches!(
                                transports[index],
                                ClientTransport::PeerRelay { .. }
                            ) && standby_ping_failures
                                .get(&index)
                                .copied()
                                .unwrap_or(0)
                                >= 2;
                            if !expired && !connection_closed && !standby_dead {
                                continue;
                            }
                            if let Some(lost_path) = path_index_map.path_of(index) {
                                let _ = path_lost_tx.send(lost_path);
                            }
                            let mut expired_transport = transports.remove(index);
                            path_index_map.on_remove(index);
                            if index < active_index {
                                active_index -= 1;
                            }
                            if standby_dead && !expired && !connection_closed {
                                alog_warn!(
                                    "Worker: retiring dead standby transport (was index {}, consecutive ping failures)",
                                    index
                                );
                            } else {
                                alog_info!(
                                    "Worker: retiring peer-relay transport (was index {}, expired={}, connection_closed={})",
                                    index,
                                    expired,
                                    connection_closed
                                );
                            }
                            let _ = tokio::time::timeout(
                                ANDROID_TRANSPORT_CLOSE_TIMEOUT,
                                expired_transport.close(),
                            )
                            .await;
                            retired_any = true;
                        }
                        if retired_any {
                            sync_transport_snapshot(&worker_snapshot, &transports, active_index);
                            publish_path_stats(
                                &worker_snapshot,
                                &transports,
                                &path_index_slots(&path_index_map, transports.len()),
                                active_index,
                            );
                        }
                    }
                }
            }
            alog_info!("Worker thread: exiting main loop");
        }); // end block_on
        })); // end catch_unwind
        if let Err(panic_val) = catch_result {
            let msg = panic_val
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic_val.downcast_ref::<&str>().copied())
                .unwrap_or("(non-string panic payload)");
            alog_error!("Worker panicked: {}", msg);
            update_snapshot(&worker_snapshot_panic, |session_snapshot| {
                session_snapshot.state = "error".to_owned();
                session_snapshot.last_error = Some(format!("worker panicked: {msg}"));
            });
        }
    });

    let handle = AndroidSessionHandle {
        outbound_tx,
        inbound_queue,
        snapshot,
        path_control_tx,
        cancel_token,
        worker: Some(worker),
    };

    let mut slot = android_session_slot()
        .lock()
        .expect("android session slot lock poisoned");
    *slot = Some(handle);
    alog_info!("Android session started");
    Ok(())
}

#[cfg(any(target_os = "android", test))]
fn get_session_snapshot_json() -> Option<String> {
    android_session_slot()
        .lock()
        .expect("android session slot lock poisoned")
        .as_ref()
        .map(|handle| {
            let snapshot = handle
                .snapshot
                .lock()
                .expect("android session snapshot lock poisoned")
                .clone();
            snapshot_json(&snapshot)
        })
}

#[cfg(any(target_os = "android", test))]
fn queue_outbound_packet(packet: Vec<u8>) -> bool {
    if let Some(handle) = android_session_slot()
        .lock()
        .expect("android session slot lock poisoned")
        .as_ref()
    {
        let result = handle.outbound_tx.send(packet);
        if result.is_err() {
            let message = "Failed to queue outbound packet: channel closed";
            update_snapshot(&handle.snapshot, |session_snapshot| {
                // Log before (and instead of) overwriting — helps surface the root cause.
                if let Some(existing) = &session_snapshot.last_error {
                    alog_warn!("Channel closed; existing last_error={}", existing);
                } else {
                    alog_error!("{}", message);
                    session_snapshot.state = "error".to_owned();
                    session_snapshot.last_error = Some(message.to_owned());
                }
                session_snapshot.state = "error".to_owned();
            });
            return false;
        }

        return true;
    }

    alog_warn!("Cannot queue outbound packet: no active session");
    false
}

#[cfg(any(target_os = "android", test))]
fn poll_inbound_packet() -> Option<Vec<u8>> {
    let result = android_session_slot()
        .lock()
        .expect("android session slot lock poisoned")
        .as_ref()
        .and_then(|handle| {
            handle
                .inbound_queue
                .lock()
                .expect("android inbound queue lock poisoned")
                .pop_front()
        });

    result
}

#[cfg(any(target_os = "android", test))]
fn redeem_invite_token(
    server_address: &str,
    server_public_key: &str,
    invite_token: &str,
    storage_dir: &str,
) -> anyhow::Result<()> {
    let mut config = android_client_config(server_address, "", server_public_key, storage_dir);
    config.client.invite_token = invite_token.to_owned();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async {
        // Dial with the same transport machinery the session runtime uses,
        // honoring the configured protocols (wss first against production
        // servers). This used to open the plaintext naive-TCP handshake
        // unconditionally, which a TLS bootstrap endpoint rejects while
        // handshaking — the server logs a TLS "corrupt message" error and
        // the redeem dies with "unexpected end of file" — so pairing
        // against a production server could never succeed.
        let mut paths = establish_transport_paths(&config, 1).await?;
        let mut transport = paths.remove(0).1;
        complete_pairing_session_binding(&mut transport).await?;
        drop(transport);
        Ok::<(), anyhow::Error>(())
    })
}

/// Complete server-side session binding on an authenticated pairing
/// connection with a PING/PONG discovery exchange. The server binds the
/// session to the first frame it receives after authentication (see
/// resolve_session_binding on the server), so a bare connect + auth +
/// drop leaves it waiting for a frame that never comes and the
/// connection is discarded when the stream closes.
#[cfg(any(target_os = "android", test))]
async fn complete_pairing_session_binding(
    transport: &mut ClientTransport,
) -> anyhow::Result<()> {
    transport
        .send(SessionFrame {
            header: SessionHeader {
                connection_id: 0,
                sequence: 0,
                flags: FLAG_PING,
            },
            payload: Bytes::new(),
        })
        .await?;
    let pong = tokio::time::timeout(Duration::from_secs(10), transport.recv())
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "timed out waiting for the server to bind the pairing session"
            )
        })??;
    anyhow::ensure!(
        pong.header.flags & FLAG_PONG != 0,
        "unexpected first frame from server while redeeming invite token: flags={}",
        pong.header.flags
    );
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn bonded_ffi_api_version() -> u32 {
    1
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_MainActivity_nativeApiVersion(
    _env: *mut jni_sys::JNIEnv,
    _clazz: jni_sys::jclass,
) -> jni_sys::jint {
    bonded_ffi_api_version() as jni_sys::jint
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_MainActivity_nativeRedeemInviteToken(
    mut env: jni::JNIEnv,
    _obj: jni::objects::JObject,
    server_address: jni::objects::JString,
    server_public_key: jni::objects::JString,
    invite_token: jni::objects::JString,
    storage_dir: jni::objects::JString,
) -> jni::sys::jboolean {
    let server_address: String = match env.get_string(&server_address) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let server_public_key: String = match env.get_string(&server_public_key) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let invite_token: String = match env.get_string(&invite_token) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let storage_dir: String = match env.get_string(&storage_dir) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };

    match redeem_invite_token(
        &server_address,
        &server_public_key,
        &invite_token,
        &storage_dir,
    ) {
        Ok(()) => {
            if let Ok(mut last_error) = LAST_NATIVE_ERROR.lock() {
                *last_error = None;
            }
            1
        }
        Err(err) => {
            let message = format!(
                "nativeRedeemInviteToken failed: {err}; server_address={server_address}; token_len={}",
                invite_token.len()
            );
            alog_error!("{message}");
            if let Ok(mut last_error) = LAST_NATIVE_ERROR.lock() {
                *last_error = Some(message);
            }
            0
        }
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_MainActivity_nativeLastError(
    env: jni::JNIEnv,
    _obj: jni::objects::JObject,
) -> jni::sys::jstring {
    let message = LAST_NATIVE_ERROR
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_else(|| "unknown native error".to_owned());

    match env.new_string(message) {
        Ok(jstr) => jstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativeStartSession(
    mut env: jni::JNIEnv,
    obj: jni::objects::JObject,
    server_address: jni::objects::JString,
    resolved_server_address: jni::objects::JString,
    server_public_key: jni::objects::JString,
    protocol_csv: jni::objects::JString,
    path_count: jni::sys::jint,
    bind_addresses_json: jni::objects::JString,
    peer_share_enabled: jni::sys::jboolean,
    peer_share_bind_address: jni::objects::JString,
    peer_share_advertise_ip: jni::objects::JString,
    peer_share_max_consumers: jni::sys::jint,
    peer_share_relay_bandwidth_kbps: jni::sys::jlong,
    storage_dir: jni::objects::JString,
    diagnostics_upload_enabled: jni::sys::jboolean,
    diagnostics_upload_period_secs: jni::sys::jlong,
    app_version_code: jni::sys::jlong,
) -> jni::sys::jboolean {
    // Store global ref to the service so protect_fd can call back into Java.
    if let Ok(global_ref) = env.new_global_ref(&obj) {
        if let Ok(mut guard) = ANDROID_VPN_SERVICE.lock() {
            *guard = Some(global_ref);
        }
    }

    let server_address: String = match env.get_string(&server_address) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let resolved_server_address: String = match env.get_string(&resolved_server_address) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let server_public_key: String = match env.get_string(&server_public_key) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let protocol_csv: String = match env.get_string(&protocol_csv) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let bind_addresses_json: String = match env.get_string(&bind_addresses_json) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let peer_share_bind_address: String = match env.get_string(&peer_share_bind_address) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let peer_share_advertise_ip: String = match env.get_string(&peer_share_advertise_ip) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };
    let storage_dir: String = match env.get_string(&storage_dir) {
        Ok(value) => value.into(),
        Err(_) => return 0,
    };

    if start_android_session(
        &server_address,
        &resolved_server_address,
        &server_public_key,
        &protocol_csv,
        path_count.max(1) as usize,
        &bind_addresses_json,
        peer_share_enabled != 0,
        &peer_share_bind_address,
        &peer_share_advertise_ip,
        peer_share_max_consumers.max(1) as u32,
        peer_share_relay_bandwidth_kbps.max(0) as u64,
        diagnostics_upload_enabled != 0,
        diagnostics_upload_period_secs.max(0) as u64,
        app_version_code.max(0) as u64,
        &storage_dir,
    )
    .is_ok()
    {
        1
    } else {
        0
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativeStopSession(
    _env: jni::JNIEnv,
    _obj: jni::objects::JObject,
) {
    stop_android_session();
    // Release the VPN service global ref now that the session is stopped.
    if let Ok(mut guard) = ANDROID_VPN_SERVICE.lock() {
        *guard = None;
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativeHandleTunOutbound(
    env: jni::JNIEnv,
    _obj: jni::objects::JObject,
    packet: jni::objects::JByteArray,
) -> jni::sys::jboolean {
    if let Ok(packet) = env.convert_byte_array(&packet) {
        return if queue_outbound_packet(packet) { 1 } else { 0 };
    }

    0
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativeSetTunFd(
    _env: jni::JNIEnv,
    _obj: jni::objects::JObject,
    fd: jni::sys::jint,
) -> jni::sys::jboolean {
    if set_android_tun_fd(fd as i32) {
        1
    } else {
        0
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativePollTunInbound(
    env: jni::JNIEnv,
    _obj: jni::objects::JObject,
) -> jni::sys::jbyteArray {
    match poll_inbound_packet() {
        Some(packet) => match env.byte_array_from_slice(&packet) {
            Ok(out) => out.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativeGetSessionSnapshot(
    env: jni::JNIEnv,
    _obj: jni::objects::JObject,
) -> jni::sys::jstring {
    match get_session_snapshot_json() {
        Some(snapshot) => match env.new_string(snapshot) {
            Ok(value) => value.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// Debug path controls (long-press on a path row): pause/resume and
/// reset one direct path. Returns false when no session is running.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativePausePath(
    _env: jni::JNIEnv,
    _obj: jni::objects::JObject,
    path_index: jni::sys::jint,
    paused: jni::sys::jboolean,
) -> jni::sys::jboolean {
    android_session_slot()
        .lock()
        .expect("android session slot lock poisoned")
        .as_ref()
        .map(|handle| {
            handle
                .path_control_tx
                .send(PathControl::Pause {
                    path_index: path_index as usize,
                    paused: paused != 0,
                })
                .is_ok()
        })
        .unwrap_or(false) as jni::sys::jboolean
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativeResetPath(
    _env: jni::JNIEnv,
    _obj: jni::objects::JObject,
    path_index: jni::sys::jint,
) -> jni::sys::jboolean {
    android_session_slot()
        .lock()
        .expect("android session slot lock poisoned")
        .as_ref()
        .map(|handle| {
            handle
                .path_control_tx
                .send(PathControl::Reset {
                    path_index: path_index as usize,
                })
                .is_ok()
        })
        .unwrap_or(false) as jni::sys::jboolean
}

/// Network path-set update (an interface appeared or vanished):
/// hands the live worker the current bind-address list so it can
/// add/remove paths surgically instead of restarting the session.
/// Returns false when no session is running (the caller falls back
/// to the stop/start rebind).
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativeUpdatePaths(
    mut env: jni::JNIEnv,
    _obj: jni::objects::JObject,
    bind_addresses_json: jni::objects::JString,
) -> jni::sys::jboolean {
    let bind_addresses_json: String = match env.get_string(&bind_addresses_json) {
        Ok(value) => value.into(),
        Err(_) => return false as jni::sys::jboolean,
    };
    let bind_addresses = parse_bind_address_list(&bind_addresses_json);
    android_session_slot()
        .lock()
        .expect("android session slot lock poisoned")
        .as_ref()
        .map(|handle| {
            handle
                .path_control_tx
                .send(PathControl::PathsChanged { bind_addresses })
                .is_ok()
        })
        .unwrap_or(false) as jni::sys::jboolean
}

/// In-app QUIC handshake probe (diagnostics): dials one production-shaped
/// QUIC session connection using the same protect / network-bind
/// callbacks as a live session, from a dedicated thread + runtime (the
/// FFI's per-session pattern). Backs the Kotlin TEST_QUIC_PROBE
/// broadcast; returns a one-line result string.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_bonded_bonded_1app_NetworkTestReceiver_nativeProbeQuicHandshake(
    mut env: jni::JNIEnv,
    _obj: jni::objects::JObject,
    bind_address: jni::objects::JString,
    host: jni::objects::JString,
    port: jni::sys::jint,
    timeout_ms: jni::sys::jint,
) -> jni::sys::jstring {
    let bind_address: String = match env.get_string(&bind_address) {
        Ok(value) => value.into(),
        Err(_) => String::new(),
    };
    let host: String = match env.get_string(&host) {
        Ok(value) => value.into(),
        Err(_) => String::new(),
    };
    let bind_ip = if bind_address.is_empty() {
        None
    } else {
        match bind_address.parse::<std::net::IpAddr>() {
            Ok(ip) => Some(ip),
            Err(_) => {
                let message = format!("ERR bad bind_address {bind_address}");
                return match env.new_string(message) {
                    Ok(value) => value.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
        }
    };
    let socket_protect = SocketProtectFn(Arc::new(|fd| protect_fd(fd)));
    let socket_network_bind = SocketNetworkBindFn(Arc::new(|fd, bind_address| {
        bind_socket_to_network(fd, bind_address)
    }));
    let timeout = std::time::Duration::from_millis(timeout_ms.max(0) as u64);
    let port_u16 = port as u16;
    let handle = std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => return format!("ERR runtime: {err}"),
        };
        runtime.block_on(async move {
            match bonded_client::probe_quic_handshake(
                Some(&socket_protect),
                Some(&socket_network_bind),
                bind_ip,
                &host,
                port_u16,
                timeout,
            )
            .await
            {
                Ok(line) => line,
                Err(line) => line,
            }
        })
    });
    let result = handle
        .join()
        .unwrap_or_else(|_| "ERR probe thread panicked".to_string());
    match env.new_string(result) {
        Ok(value) => value.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `raw_ptr` must point to `raw_len` bytes of readable memory.
/// `out_metadata` must point to writable memory for one `BondedFrameMetadata`.
pub unsafe extern "C" fn bonded_ffi_decode_frame_metadata(
    raw_ptr: *const u8,
    raw_len: usize,
    out_metadata: *mut BondedFrameMetadata,
) -> i32 {
    if raw_ptr.is_null() || out_metadata.is_null() {
        return BONDED_FFI_ERR_NULL_POINTER;
    }

    // Safety: caller guarantees `raw_ptr` is valid for `raw_len` bytes.
    let raw = unsafe { slice::from_raw_parts(raw_ptr, raw_len) };
    match decode_frame_metadata(raw) {
        Ok(metadata) => {
            // Safety: caller guarantees `out_metadata` points to writable memory.
            unsafe {
                *out_metadata = metadata;
            }
            BONDED_FFI_OK
        }
        Err(code) => code,
    }
}

#[cfg(test)]
mod tests {
    use super::diff_path_addresses;
    use super::order_candidates_for_send;

    #[test]
    fn path_diff_removes_vanished_and_reuses_freed_indexes() {
        use std::collections::{HashMap, HashSet};
        let current: HashMap<usize, String> = [
            (0, "192.168.1.250".to_owned()),
            (1, "192.0.0.4".to_owned()),
        ]
        .into_iter()
        .collect();
        let used: HashSet<usize> = [0, 1].into_iter().collect();
        // Wi-Fi dies: only cellular remains. Nothing added.
        let (removed, added) = diff_path_addresses(
            &current,
            &used,
            &["192.0.0.4".to_owned()],
        );
        assert_eq!(removed, vec![0]);
        assert!(added.is_empty());
        // Wi-Fi returns on the same address: it reuses index 0.
        let (removed, added) = diff_path_addresses(
            &current,
            &used,
            &["192.168.1.250".to_owned(), "192.0.0.4".to_owned()],
        );
        assert!(removed.is_empty());
        assert!(added.is_empty());
        // Wi-Fi returns on a NEW address (DHCP change): the old
        // index is freed by the removal and reused for the new one.
        let (removed, added) = diff_path_addresses(
            &current,
            &used,
            &["192.168.1.99".to_owned(), "192.0.0.4".to_owned()],
        );
        assert_eq!(removed, vec![0]);
        assert_eq!(added, vec![(0, "192.168.1.99".to_owned())]);
    }

    #[test]
    fn path_diff_ignores_order_and_duplicates() {
        use std::collections::{HashMap, HashSet};
        let current: HashMap<usize, String> =
            [(0, "10.0.0.1".to_owned())].into_iter().collect();
        let used: HashSet<usize> = [0].into_iter().collect();
        // Reordered list with a duplicate: no change, no second path.
        let (removed, added) = diff_path_addresses(
            &current,
            &used,
            &["10.0.0.1".to_owned(), "10.0.0.1".to_owned()],
        );
        assert!(removed.is_empty());
        assert!(added.is_empty());
        // A genuinely new address takes the next free index (1),
        // since 0 is live.
        let (removed, added) = diff_path_addresses(
            &current,
            &used,
            &["10.0.0.1".to_owned(), "10.0.0.2".to_owned()],
        );
        assert!(removed.is_empty());
        assert_eq!(added, vec![(1, "10.0.0.2".to_owned())]);
    }

    #[test]
    fn paused_paths_go_last_regardless_of_hash_pick() {
        // Candidates [0, 1, 2] with 2 paused: no hash pick may put 2
        // first; healthy rotation is preserved among [0, 1].
        for flow in 0..64u64 {
            let ordered = order_candidates_for_send(vec![0, 1, 2], |i| i == 2, flow);
            let first = flow as usize % 2;
            assert_eq!(
                ordered,
                vec![first, 1 - first, 2],
                "paused path must be last for flow {flow}"
            );
        }
    }

    #[test]
    fn all_paused_keeps_todays_rotation() {
        for flow in 0..16u64 {
            let ordered = order_candidates_for_send(vec![0, 1, 2], |_| true, flow);
            let mut expected = vec![0, 1, 2];
            expected.rotate_left(flow as usize % 3);
            assert_eq!(ordered, expected, "all-paused must rotate like today");
        }
    }

    #[test]
    fn no_paused_is_identity_rotation() {
        for flow in 0..16u64 {
            let ordered = order_candidates_for_send(vec![0, 1], |_| false, flow);
            let mut expected = vec![0, 1];
            expected.rotate_left(flow as usize % 2);
            assert_eq!(ordered, expected);
        }
        assert!(order_candidates_for_send(vec![], |_| false, 7).is_empty());
    }

    use super::{
        android_client_config, bonded_ffi_api_version, complete_pairing_session_binding,
        decode_frame_metadata, establish_naive_tcp_session, get_session_snapshot_json,
        poll_inbound_packet, queue_outbound_packet, start_android_session,
        stop_android_session,
    };
    use bonded_client::ClientTransport;
    use bonded_core::auth::{create_auth_challenge, verify_auth_challenge};
    use bonded_core::session::{
        SessionFrame, SessionHeader, FLAG_MULTIPATH_RECV, FLAG_PING, FLAG_PONG,
    };
    use bonded_core::transport::{NaiveTcpTransport, Transport};
    use bytes::Bytes;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    fn temp_dir_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("bonded-ffi-{name}-{stamp}"))
    }

    async fn handshake_server_connection(
        stream: TcpStream,
        expected_public_key: Option<&str>,
        expected_invite_token: &str,
    ) -> (String, TcpStream) {
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let mut hello_line = String::new();
        reader
            .read_line(&mut hello_line)
            .await
            .expect("hello should be readable");
        let hello: serde_json::Value =
            serde_json::from_str(hello_line.trim_end()).expect("hello should parse");
        let public_key = hello["public_key_b64"]
            .as_str()
            .expect("public key should exist")
            .to_owned();
        if let Some(expected) = expected_public_key {
            assert_eq!(public_key, expected);
            assert_eq!(hello["invite_token"].as_str().unwrap_or_default(), "");
        } else {
            assert_eq!(
                hello["invite_token"].as_str().unwrap_or_default(),
                expected_invite_token
            );
        }

        let challenge_b64 = create_auth_challenge();
        let challenge = json!({ "challenge_b64": challenge_b64 });
        write_half
            .write_all(format!("{}\n", challenge).as_bytes())
            .await
            .expect("challenge should be written");

        let mut proof_line = String::new();
        reader
            .read_line(&mut proof_line)
            .await
            .expect("proof should be readable");
        let proof: serde_json::Value =
            serde_json::from_str(proof_line.trim_end()).expect("proof should parse");
        let signature_b64 = proof["signature_b64"]
            .as_str()
            .expect("signature should exist");
        verify_auth_challenge(&public_key, &challenge_b64, signature_b64)
            .expect("signature should verify");

        write_half
            .write_all(b"{\"status\":\"ok\"}\n")
            .await
            .expect("result should be written");

        let stream = reader
            .into_inner()
            .reunite(write_half)
            .expect("stream should reunite");
        (public_key, stream)
    }

    #[test]
    fn ffi_api_version_is_stable() {
        assert_eq!(bonded_ffi_api_version(), 1);
    }

    #[test]
    fn decode_frame_metadata_reads_session_headers() {
        let frame = SessionFrame {
            header: SessionHeader {
                connection_id: 42,
                sequence: 9,
                flags: 7,
            },
            payload: b"hello".to_vec().into(),
        };

        let decoded = decode_frame_metadata(&frame.encode()).expect("decode should succeed");
        assert_eq!(decoded.connection_id, 42);
        assert_eq!(decoded.sequence, 9);
        assert_eq!(decoded.flags, 7);
        assert_eq!(decoded.payload_len, 5);
    }

    #[test]
    fn decode_frame_metadata_rejects_short_buffers() {
        let result = decode_frame_metadata(b"tiny");
        assert!(result.is_err());
    }

    /// The session tests drive a process-global session slot; serialize
    /// them so they cannot interleave workers and snapshots.
    static SESSION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn session_test_lock() -> std::sync::MutexGuard<'static, ()> {
        SESSION_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn android_session_runtime_can_pair_and_exchange_packets() {
        let _guard = session_test_lock();
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let storage_dir = temp_dir_path("android-session-runtime");
        fs::create_dir_all(&storage_dir).expect("storage dir should be created");

        let listener = runtime
            .block_on(TcpListener::bind("127.0.0.1:0"))
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should resolve");

        let server_task = runtime.spawn(async move {
            let (pair_stream, _) = listener.accept().await.expect("pair accept should succeed");
            let (public_key, pair_stream) =
                handshake_server_connection(pair_stream, None, "android-invite").await;
            // The redeem flow completes the server's session binding with a
            // PING/PONG exchange after authentication; answer it the way the
            // real server does.
            let mut pair_transport = NaiveTcpTransport::from_stream(pair_stream);
            let ping = pair_transport
                .recv()
                .await
                .expect("pairing ping should arrive");
            assert!(
                ping.header.flags & FLAG_PING != 0,
                "expected PING as the pairing session's first frame"
            );
            pair_transport
                .send(SessionFrame {
                    header: SessionHeader {
                        connection_id: 7,
                        sequence: 0,
                        flags: FLAG_PONG,
                    },
                    payload: Bytes::new(),
                })
                .await
                .expect("pairing pong should send");

            let (session_stream, session_peer_addr) = listener
                .accept()
                .await
                .expect("session accept should succeed");
            assert_eq!(session_peer_addr.ip().to_string(), "127.0.0.2");
            let (_, session_stream) =
                handshake_server_connection(session_stream, Some(&public_key), "").await;
            let mut transport = NaiveTcpTransport::from_stream(session_stream);
            // The session runtime completes server-side session binding with
            // a PING/PONG discovery exchange on each path before any data
            // flows; answer it the way the real server does.
            let discovery_ping = transport
                .recv()
                .await
                .expect("session discovery ping should arrive");
            assert!(
                discovery_ping.header.flags & FLAG_PING != 0,
                "expected PING as the session's first frame"
            );
            transport
                .send(SessionFrame {
                    header: SessionHeader {
                        connection_id: 3,
                        sequence: discovery_ping.header.sequence,
                        flags: FLAG_PONG,
                    },
                    payload: Bytes::new(),
                })
                .await
                .expect("session discovery pong should send");
            let frame = transport.recv().await.expect("session frame should arrive");
            transport.send(frame).await.expect("echo should send");
        });

        // The production redeem entry dials via establish_transport_paths
        // (the configured session protocols, wss first); against this
        // plaintext test server, dial the naive path directly and then run
        // the same pairing session-binding exchange the redeem performs
        // once its transport is up.
        let mut pair_config = android_client_config(
            &addr.to_string(),
            "",
            "server-pub",
            storage_dir.to_string_lossy().as_ref(),
        );
        pair_config.client.invite_token = "android-invite".to_owned();
        runtime
            .block_on(async {
                let pair_stream = establish_naive_tcp_session(&pair_config)
                    .await
                    .expect("pairing connection should establish");
                let mut pair_transport =
                    ClientTransport::NaiveTcp(NaiveTcpTransport::from_stream(pair_stream));
                complete_pairing_session_binding(&mut pair_transport)
                    .await
                    .expect("pairing session binding should complete");
            });

        start_android_session(
            &addr.to_string(),
            "",
            "server-pub",
            "naive_tcp",
            1,
            "[\"127.0.0.2\"]",
            false,
            "",
            "",
            4,
            0,
            false,
            900,
            0,
            storage_dir.to_string_lossy().as_ref(),
        )
        .expect("android session should start");

        let connected = (0..20).any(|_| {
            std::thread::sleep(Duration::from_millis(100));
            get_session_snapshot_json()
                .map(|snapshot| snapshot.contains("\"state\":\"connected\""))
                .unwrap_or(false)
        });
        assert!(connected, "session should report connected state");

        queue_outbound_packet(b"android-smoke".to_vec());

        let echoed = (0..30)
            .find_map(|_| {
                std::thread::sleep(Duration::from_millis(100));
                poll_inbound_packet()
            })
            .expect("inbound packet should be echoed back");
        assert_eq!(echoed, b"android-smoke");

        stop_android_session();
        runtime
            .block_on(server_task)
            .expect("server task should join");
        let _ = fs::remove_dir_all(storage_dir);
    }

    /// F4 proof: when a standby direct path dies silently (the server
    /// drops its connection; no network change for the OS to react
    /// to), the worker must evict it and the path supervisor must
    /// re-dial it in place — same session, same connected-at stamp,
    /// data plane on the surviving path never interrupted.
    #[test]
    fn android_session_supervisor_restores_a_killed_standby_path() {
        let _guard = session_test_lock();
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let storage_dir = temp_dir_path("android-session-supervisor");
        fs::create_dir_all(&storage_dir).expect("storage dir should be created");

        let listener = runtime
            .block_on(TcpListener::bind("127.0.0.1:0"))
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should resolve");

        let (kill_tx, kill_rx) = tokio::sync::oneshot::channel::<()>();

        let server_task = runtime.spawn(async move {
            // The client establishes both paths (auth handshakes)
            // before its discovery exchange starts, so accept and
            // authenticate both first, then answer discovery pings.
            let (stream0, _) = listener.accept().await.expect("path 0 accept");
            let (public_key, stream0) =
                handshake_server_connection(stream0, None, "").await;
            let (stream1, _) = listener.accept().await.expect("path 1 accept");
            let (_, stream1) =
                handshake_server_connection(stream1, Some(&public_key), "").await;
            let mut transport0 = NaiveTcpTransport::from_stream(stream0);
            let mut transport1 = NaiveTcpTransport::from_stream(stream1);
            for transport in [&mut transport0, &mut transport1] {
                let ping = transport.recv().await.expect("discovery ping");
                assert!(
                    ping.header.flags & FLAG_PING != 0,
                    "expected PING as the session's first frame"
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 3,
                            sequence: ping.header.sequence,
                            flags: FLAG_PONG,
                        },
                        payload: Bytes::new(),
                    })
                    .await
                    .expect("discovery pong should send");
            }

            // Active path pump: echo data frames, answer heartbeat
            // pings, for the rest of the test.
            let pump0 = tokio::spawn(async move {
                loop {
                    match transport0.recv().await {
                        Ok(frame) => {
                            if frame.header.flags & FLAG_PING != 0 {
                                let pong = SessionFrame {
                                    header: SessionHeader {
                                        connection_id: 3,
                                        sequence: frame.header.sequence,
                                        flags: FLAG_PONG,
                                    },
                                    payload: Bytes::new(),
                                };
                                if transport0.send(pong).await.is_err() {
                                    break;
                                }
                            } else if !frame.payload.is_empty()
                                && transport0.send(frame).await.is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });

            // Standby: answer its heartbeat pings and echo data
            // frames (the real server forwards data arriving on ANY
            // transport; since the multipath client spreads flows
            // across both paths, the mock must too) until told to
            // drop the connection — the silent-death case the
            // supervisor exists for.
            tokio::select! {
                _ = kill_rx => {}
                _ = async {
                    loop {
                        match transport1.recv().await {
                            Ok(frame) => {
                                if frame.header.flags & FLAG_PING != 0 {
                                    let pong = SessionFrame {
                                        header: SessionHeader {
                                            connection_id: 3,
                                            sequence: frame.header.sequence,
                                            flags: FLAG_PONG,
                                        },
                                        payload: Bytes::new(),
                                    };
                                    if transport1.send(pong).await.is_err() {
                                        break;
                                    }
                                } else if !frame.payload.is_empty()
                                    && transport1.send(frame).await.is_err()
                                {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                } => {}
            }
            drop(transport1);

            // The supervisor must re-dial path 1: a fresh connection
            // from the same bind, a fresh auth handshake, and a
            // binding ping that gets the SAME session id back.
            let (stream1b, _) = tokio::time::timeout(
                std::time::Duration::from_secs(120),
                listener.accept(),
            )
            .await
            .expect("redial accept should not time out")
            .expect("redial accept should succeed");
            let (_, stream1b) =
                handshake_server_connection(stream1b, Some(&public_key), "").await;
            let mut transport1b = NaiveTcpTransport::from_stream(stream1b);
            let ping = transport1b.recv().await.expect("redial binding ping");
            assert!(
                ping.header.flags & FLAG_PING != 0,
                "expected PING as the re-dialed path's first frame"
            );
            transport1b
                .send(SessionFrame {
                    header: SessionHeader {
                        connection_id: 3,
                        sequence: ping.header.sequence,
                        flags: FLAG_PONG,
                    },
                    payload: Bytes::new(),
                })
                .await
                .expect("redial binding pong should send");
            // Serve the restored path (pongs + data echo, like every
            // other path) until the client goes away.
            loop {
                match transport1b.recv().await {
                    Ok(frame) => {
                        if frame.header.flags & FLAG_PING != 0 {
                            let pong = SessionFrame {
                                header: SessionHeader {
                                    connection_id: 3,
                                    sequence: frame.header.sequence,
                                    flags: FLAG_PONG,
                                },
                                payload: Bytes::new(),
                            };
                            if transport1b.send(pong).await.is_err() {
                                break;
                            }
                        } else if !frame.payload.is_empty()
                            && transport1b.send(frame).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            drop(pump0);
        });

        start_android_session(
            &addr.to_string(),
            "",
            "",
            "naive_tcp",
            2,
            "[\"127.0.0.2\",\"127.0.0.3\"]",
            false,
            "",
            "",
            4,
            0,
            false,
            900,
            0,
            storage_dir.to_string_lossy().as_ref(),
        )
        .expect("android session should start");

        fn snapshot_connected_at(snapshot: &str) -> Option<u64> {
            snapshot
                .split("\"connectedAtMs\":")
                .nth(1)
                .and_then(|rest| rest.split(',').next())
                .and_then(|value| value.trim().parse::<u64>().ok())
        }

        // Wait for the two-path connected state and remember the
        // session's connected-at stamp: F4 must restore the path
        // WITHOUT the session ever restarting.
        let mut connected_at_ms = None;
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(200));
            if let Some(snapshot) = get_session_snapshot_json() {
                if snapshot.contains("\"state\":\"connected\"")
                    && snapshot.contains("\"transportCount\":2")
                {
                    connected_at_ms = snapshot_connected_at(&snapshot);
                    break;
                }
            }
        }
        let connected_at_ms =
            connected_at_ms.expect("session should connect with two transports");

        // Data plane works before the kill.
        queue_outbound_packet(b"f4-before".to_vec());
        let echoed = (0..50)
            .find_map(|_| {
                std::thread::sleep(Duration::from_millis(100));
                poll_inbound_packet()
            })
            .expect("inbound packet should echo before the kill");
        assert_eq!(echoed, b"f4-before");

        // Kill the standby server-side.
        let _ = kill_tx.send(());

        // The worker must evict the dead standby (transport count
        // 2 -> 1) and the supervisor must restore it (1 -> 2), with
        // the session state and connected-at stamp unmoved throughout.
        let mut saw_single_path = false;
        let mut restored = false;
        for _ in 0..300 {
            std::thread::sleep(Duration::from_millis(500));
            if let Some(snapshot) = get_session_snapshot_json() {
                assert!(
                    snapshot.contains("\"state\":\"connected\""),
                    "session must stay connected throughout: {snapshot}"
                );
                assert_eq!(
                    snapshot_connected_at(&snapshot),
                    Some(connected_at_ms),
                    "session must not restart: {snapshot}"
                );
                if snapshot.contains("\"transportCount\":1") {
                    saw_single_path = true;
                }
                if saw_single_path && snapshot.contains("\"transportCount\":2") {
                    restored = true;
                    break;
                }
            }
        }
        assert!(
            saw_single_path,
            "the killed standby should have been evicted"
        );
        assert!(
            restored,
            "the supervisor should have restored the standby in place"
        );

        // Data plane still works after the restore.
        queue_outbound_packet(b"f4-after".to_vec());
        let echoed = (0..50)
            .find_map(|_| {
                std::thread::sleep(Duration::from_millis(100));
                poll_inbound_packet()
            })
            .expect("inbound packet should echo after the restore");
        assert_eq!(echoed, b"f4-after");

        stop_android_session();
        runtime
            .block_on(server_task)
            .expect("server task should join");
        let _ = fs::remove_dir_all(storage_dir);
    }

    /// Build a raw IPv4/UDP packet (10.8.0.2:<src_port> ->
    /// 203.0.113.7:443) carrying `marker`. Only the header fields feed
    /// the flow hash; checksums are left zero because neither the
    /// worker nor the mock server validates them.
    fn mp_udp_packet(src_port: u16, marker: &[u8]) -> Vec<u8> {
        let total_len = 20 + 8 + marker.len();
        let mut packet = Vec::with_capacity(total_len);
        packet.push(0x45); // IPv4, IHL 20
        packet.push(0);
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]); // id + flags/fragment
        packet.push(64); // TTL
        packet.push(17); // UDP
        packet.extend_from_slice(&[0, 0]); // header checksum
        packet.extend_from_slice(&[10, 8, 0, 2]);
        packet.extend_from_slice(&[203, 0, 113, 7]);
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&443u16.to_be_bytes());
        packet.extend_from_slice(&((8 + marker.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]); // UDP checksum
        packet.extend_from_slice(marker);
        packet
    }

    #[test]
    fn android_session_spreads_flows_across_both_paths() {
        let _guard = session_test_lock();
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let storage_dir = temp_dir_path("android-session-multipath");
        fs::create_dir_all(&storage_dir).expect("storage dir should be created");

        let listener = runtime
            .block_on(TcpListener::bind("127.0.0.1:0"))
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should resolve");

        // Two flows pinned to different paths by the shared flow hash
        // (candidate order = transports vec order = bind order).
        let (mut port_on_0, mut port_on_1) = (None, None);
        for port in 21000..21100u16 {
            let packet = mp_udp_packet(port, b"x");
            let pick = bonded_core::flow::pick_index(
                bonded_core::flow::flow_hash(&packet),
                2,
            );
            match pick {
                0 => port_on_0 = port_on_0.or(Some(port)),
                _ => port_on_1 = port_on_1.or(Some(port)),
            }
            if port_on_0.is_some() && port_on_1.is_some() {
                break;
            }
        }
        let packet_a = mp_udp_packet(port_on_0.expect("port pinning to path 0"), b"flow-a");
        let packet_b = mp_udp_packet(port_on_1.expect("port pinning to path 1"), b"flow-b");
        let packet_b2 = mp_udp_packet(
            port_on_1.expect("port pinning to path 1"),
            b"flow-b-after-kill",
        );
        let downlink_marker = b"mp-downlink-on-standby".to_vec();

        // Server-side record of which connection each data frame
        // arrived on: (connection index, payload).
        let arrivals: std::sync::Arc<
            std::sync::Mutex<Vec<(usize, Vec<u8>)>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let arrivals_server = arrivals.clone();
        let (kill_tx, kill_rx) = tokio::sync::oneshot::channel::<()>();
        let packet_b_server = packet_b.clone();
        let downlink_server = downlink_marker.clone();

        let server_task = runtime.spawn(async move {
            // The client completes each path's auth handshake before
            // opening the next path, so accept + handshake must
            // interleave per connection (accepting both first would
            // deadlock). Identify the paths afterwards by the client's
            // bind address (127.0.0.2 = path 0, 127.0.0.3 = path 1);
            // both handshakes belong to the same device key, so the
            // streams can be labeled after the fact.
            let (stream_a, peer_a) = listener.accept().await.expect("first accept");
            let (public_key, stream_a) =
                handshake_server_connection(stream_a, None, "").await;
            let (stream_b, _peer_b) = listener.accept().await.expect("second accept");
            let (_, stream_b) =
                handshake_server_connection(stream_b, Some(&public_key), "").await;
            let (stream0, stream1) = if peer_a.ip().to_string() == "127.0.0.3" {
                (stream_b, stream_a)
            } else {
                (stream_a, stream_b)
            };
            let mut transport0 = NaiveTcpTransport::from_stream(stream0);
            let mut transport1 = NaiveTcpTransport::from_stream(stream1);
            for transport in [&mut transport0, &mut transport1] {
                let ping = transport.recv().await.expect("discovery ping");
                assert!(
                    ping.header.flags & FLAG_PING != 0,
                    "expected PING as the session's first frame"
                );
                assert!(
                    ping.header.flags & FLAG_MULTIPATH_RECV != 0,
                    "multipath client must advertise FLAG_MULTIPATH_RECV"
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 3,
                            sequence: ping.header.sequence,
                            flags: FLAG_PONG,
                        },
                        payload: Bytes::new(),
                    })
                    .await
                    .expect("discovery pong should send");
            }

            let arrivals0 = arrivals_server.clone();
            let pump0 = tokio::spawn(async move {
                loop {
                    match transport0.recv().await {
                        Ok(frame) => {
                            if frame.header.flags & FLAG_PING != 0 {
                                let pong = SessionFrame {
                                    header: SessionHeader {
                                        connection_id: 3,
                                        sequence: frame.header.sequence,
                                        flags: FLAG_PONG,
                                    },
                                    payload: Bytes::new(),
                                };
                                if transport0.send(pong).await.is_err() {
                                    break;
                                }
                            } else if !frame.payload.is_empty() {
                                arrivals0
                                    .lock()
                                    .expect("arrivals lock")
                                    .push((0, frame.payload.to_vec()));
                                if transport0.send(frame).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            });

            // Path 1 pump: echoes, and right after echoing flow B it
            // sends an unsolicited downlink packet on this (non-active)
            // path — the client must surface it even though path 1 is
            // not the session's active transport. Ends on kill signal.
            let arrivals1 = arrivals_server.clone();
            let pump1 = async move {
                let mut kill_rx = kill_rx;
                let mut sent_downlink = false;
                loop {
                    tokio::select! {
                        _ = &mut kill_rx => break,
                        recv = transport1.recv() => {
                            match recv {
                                Ok(frame) => {
                                    if frame.header.flags & FLAG_PING != 0 {
                                        let pong = SessionFrame {
                                            header: SessionHeader {
                                                connection_id: 3,
                                                sequence: frame.header.sequence,
                                                flags: FLAG_PONG,
                                            },
                                            payload: Bytes::new(),
                                        };
                                        if transport1.send(pong).await.is_err() {
                                            break;
                                        }
                                    } else if !frame.payload.is_empty() {
                                        let is_flow_b =
                                            frame.payload.as_ref() == packet_b_server.as_slice();
                                        arrivals1
                                            .lock()
                                            .expect("arrivals lock")
                                            .push((1, frame.payload.to_vec()));
                                        if transport1.send(frame).await.is_err() {
                                            break;
                                        }
                                        if is_flow_b && !sent_downlink {
                                            sent_downlink = true;
                                            let downlink = SessionFrame {
                                                header: SessionHeader {
                                                    connection_id: 3,
                                                    sequence: 0,
                                                    flags: 0,
                                                },
                                                payload: Bytes::from(
                                                    downlink_server.clone(),
                                                ),
                                            };
                                            if transport1.send(downlink).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
                drop(transport1);
            };

            // Serve path 1 until the kill (a client disconnect ends it
            // early via a recv error instead).
            pump1.await;

            // After the kill, path 0 keeps serving (flow B's re-pinned
            // traffic arrives there) until the client disconnects; the
            // supervisor's re-dial attempts are accepted and handshaked
            // but their binding pings are never ponged, so the restored
            // path never rejoins mid-test.
            let mut pump0 = pump0;
            let accept_loop = async {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            let (_, stream) = handshake_server_connection(
                                stream,
                                Some(&public_key),
                                "",
                            )
                            .await;
                            let mut held = NaiveTcpTransport::from_stream(stream);
                            let _ = held.recv().await; // binding ping, never ponged
                            let _ = held.recv().await; // hold until close
                        }
                        Err(_) => break,
                    }
                }
            };
            tokio::select! {
                _ = &mut pump0 => {}
                _ = accept_loop => {}
            }
        });

        start_android_session(
            &addr.to_string(),
            "",
            "",
            "naive_tcp",
            2,
            "[\"127.0.0.2\",\"127.0.0.3\"]",
            false,
            "",
            "",
            4,
            0,
            false,
            900,
            0,
            storage_dir.to_string_lossy().as_ref(),
        )
        .expect("android session should start");

        // Wait for the two-path connected state.
        let mut connected = false;
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(200));
            if let Some(snapshot) = get_session_snapshot_json() {
                if snapshot.contains("\"state\":\"connected\"")
                    && snapshot.contains("\"transportCount\":2")
                {
                    connected = true;
                    break;
                }
            }
        }
        assert!(connected, "session should connect with two transports");

        // Uplink spreading: flow A must arrive on connection 0 and
        // flow B on connection 1 (pre-multipath, both would land on
        // the active connection 0).
        queue_outbound_packet(packet_a.clone());
        queue_outbound_packet(packet_b.clone());
        let mut saw_a = false;
        let mut saw_b = false;
        for _ in 0..100 {
            {
                let log = arrivals.lock().expect("arrivals lock");
                saw_a = log.iter().any(|(c, p)| *c == 0 && p == &packet_a);
                saw_b = log.iter().any(|(c, p)| *c == 1 && p == &packet_b);
            }
            if saw_a && saw_b {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(saw_a, "flow A should arrive on path 0: {arrivals:?}");
        assert!(saw_b, "flow B should arrive on path 1: {arrivals:?}");

        // Both echoes come back (B's returns on path 1), plus the
        // unsolicited downlink packet sent on path 1 — the client
        // receives on every path now.
        let mut received: Vec<Vec<u8>> = Vec::new();
        for _ in 0..100 {
            if received.len() >= 3 {
                break;
            }
            match poll_inbound_packet() {
                Some(packet) => received.push(packet),
                None => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        assert!(
            received.iter().any(|p| p == &packet_a),
            "echo of flow A should arrive: {received:?}"
        );
        assert!(
            received.iter().any(|p| p == &packet_b),
            "echo of flow B (on path 1) should arrive: {received:?}"
        );
        assert!(
            received.iter().any(|p| p == &downlink_marker),
            "unsolicited downlink on path 1 should arrive: {received:?}"
        );

        // Kill path 1 server-side. The worker's receive on it errors
        // immediately, so the path is evicted without waiting for
        // heartbeat timeouts, and flow B re-pins to path 0.
        let _ = kill_tx.send(());
        let mut evicted = false;
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(200));
            if let Some(snapshot) = get_session_snapshot_json() {
                assert!(
                    snapshot.contains("\"state\":\"connected\""),
                    "session must stay connected: {snapshot}"
                );
                if snapshot.contains("\"transportCount\":1") {
                    evicted = true;
                    break;
                }
            }
        }
        assert!(evicted, "killed path should be evicted from the worker");

        queue_outbound_packet(packet_b2.clone());
        let mut saw_b2_on_0 = false;
        for _ in 0..100 {
            {
                let log = arrivals.lock().expect("arrivals lock");
                saw_b2_on_0 = log.iter().any(|(c, p)| *c == 0 && p == &packet_b2);
            }
            if saw_b2_on_0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            saw_b2_on_0,
            "flow B should re-pin to path 0 after the kill: {arrivals:?}"
        );
        let echoed_b2 = (0..50).find_map(|_| {
            std::thread::sleep(Duration::from_millis(100));
            poll_inbound_packet()
        });
        assert_eq!(
            echoed_b2.as_deref(),
            Some(packet_b2.as_slice()),
            "re-pinned flow B echo should arrive"
        );

        stop_android_session();
        runtime
            .block_on(server_task)
            .expect("server task should join");
        let _ = fs::remove_dir_all(storage_dir);
    }
}
