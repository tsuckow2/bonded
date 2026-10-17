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
use bonded_core::session::{SessionHeader, SessionState, FLAG_PING, FLAG_PONG};
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
        let close_result =
            tokio::time::timeout(ANDROID_TRANSPORT_CLOSE_TIMEOUT, transport.close()).await;
        if let Err(err) = close_result {
            eprintln!(
                "[bonded-ffi] Timed out closing transport after {:?}: {}",
                ANDROID_TRANSPORT_CLOSE_TIMEOUT, err,
            );
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

    format!(
        "{{\"state\":\"{}\",\"serverAddress\":\"{}\",\"activeTransport\":\"{}\",\"transportCount\":{},\"peerRelayCount\":{},\"outboundPackets\":{},\"inboundPackets\":{},\"outboundBytes\":{},\"inboundBytes\":{},\"connectedAtMs\":{},\"lastError\":{},\"peerShareError\":{}}}",
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
    let peer_relay_count = transports
        .iter()
        .filter(|transport| matches!(transport, ClientTransport::PeerRelay { .. }))
        .count() as u32;
    update_snapshot(snapshot, |session_snapshot| {
        session_snapshot.active_transport = active_transport;
        session_snapshot.transport_count = transports.len() as u32;
        session_snapshot.peer_relay_count =
            peer_relay_count.max(session_snapshot.accepted_peer_relay_count);
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

    #[cfg(target_os = "android")]
    {
        let _ = set_android_tun_fd(-1);
    }
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
    storage_dir: &str,
) -> anyhow::Result<()> {
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
            alog_info!("Worker: establishing transport paths");
            let mut transports = match tokio::time::timeout(
                ANDROID_PATH_ESTABLISH_TIMEOUT,
                establish_transport_paths_with_observer(&config, path_count.max(1), |message| {
                    alog_info!("Worker: {message}");
                }),
            )
            .await
            {
                Ok(Ok(transports)) => {
                    alog_info!("Transport paths established: count={}", transports.len());
                    for (index, transport) in transports.iter().enumerate() {
                        let kind = client_transport_kind(transport);
                        alog_info!("  transport[{}] = {}", index, kind);
                    }
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    sync_transport_snapshot(&worker_snapshot, &transports, 0);
                    update_snapshot(&worker_snapshot, |session_snapshot| {
                        session_snapshot.state = "connected".to_owned();
                        session_snapshot.connected_at_ms = now_ms;
                        session_snapshot.last_error = None;
                    });
                    transports
                }
                Ok(Err(err)) => {
                    alog_error!("Failed to establish transport paths: {}", err);
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
            // exchange the session sent nothing until the 25s heartbeat,
            // and any teardown inside that window (e.g. the pre-129
            // peer-share failure path) closed the transports before the
            // server ever saw a frame — the server logged "failed to
            // receive initial session frame" and no session ever bound.
            let mut session_id: u32 = 0;
            let mut path_index = 0_usize;
            while path_index < transports.len() {
                let ping = SessionFrame {
                    header: SessionHeader {
                        connection_id: 0,
                        sequence: 0,
                        flags: FLAG_PING,
                    },
                    payload: Bytes::new(),
                };
                if let Err(err) = transports[path_index].send(ping).await {
                    alog_warn!(
                        "Worker: path {} failed during session discovery (send): {}",
                        path_index, err
                    );
                    transports.remove(path_index);
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
                    }
                    Err(_) => {
                        alog_warn!(
                            "Worker: path {} timed out during session discovery",
                            path_index
                        );
                        transports.remove(path_index);
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
            let mut active_index = 0_usize;
            let mut session = SessionState::new(session_id);
            let mut ping_sequence = 0u64;
            let mut last_ping_sent_ms: Option<u64> = None;
            let mut heartbeat = tokio::time::interval(Duration::from_secs(25));
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
                    peer_transport = peer_transport_rx.recv() => {
                        if let Some(transport) = peer_transport {
                            let kind = client_transport_kind(&transport);
                            transports.push(transport);
                            sync_transport_snapshot(&worker_snapshot, &transports, active_index);
                            alog_info!(
                                "Worker: added peer-share transport kind={} total={}",
                                kind,
                                transports.len()
                            );
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
                                let frame = session.create_outbound_frame(Bytes::from(packet), 0);
                                if let Err(err) = transports[active_index].send(frame).await {
                                    alog_warn!("Worker: send on transport[{}] failed: {}", active_index, err);
                                    if transports.len() == 1 {
                                        alog_error!("Worker: only one transport available, cannot failover");
                                        update_snapshot(&worker_snapshot, |session_snapshot| {
                                            session_snapshot.state = "error".to_owned();
                                            session_snapshot.last_error = Some(err.to_string());
                                        });
                                        break;
                                    }

                                    let old_index = active_index;
                                    transports.remove(active_index);
                                    if active_index >= transports.len() {
                                        active_index = 0;
                                    }
                                    sync_transport_snapshot(&worker_snapshot, &transports, active_index);
                                    alog_warn!("Worker: failover from transport[{}] to transport[{}]", old_index, active_index);
                                    continue;
                                }
                                update_snapshot(&worker_snapshot, |session_snapshot| {
                                    session_snapshot.outbound_packets = session_snapshot.outbound_packets.saturating_add(1);
                                    session_snapshot.outbound_bytes = session_snapshot.outbound_bytes.saturating_add(packet_len);
                                });
                            }
                            None => {
                                alog_info!("Worker: outbound channel closed");
                                break;
                            }
                        }
                    }
                    frame_result = transports[active_index].recv() => {
                        // Log which transport is receiving.
                        match frame_result {
                            Ok(frame) => {
                                // Handle heartbeat pong — don't feed it to the session reorder buffer.
                                if frame.header.flags & FLAG_PONG != 0 {
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
                                    });
                                }

                                // Drain all frames already buffered in the transport without
                                // yielding back to tokio::select!. Each select! iteration has
                                // scheduler overhead, so processing one frame per iteration
                                // limits download throughput when the server bursts many frames.
                                // timeout(ZERO) polls recv() once: if a full frame is already in
                                // the read buffer it completes immediately; otherwise it times out
                                // and we yield back to select! for fairness with outbound traffic.
                                while let Ok(Ok(next_frame)) = tokio::time::timeout(
                                    Duration::ZERO,
                                    transports[active_index].recv(),
                                )
                                .await
                                {
                                    if next_frame.header.flags & FLAG_PONG != 0 {
                                        continue;
                                    }
                                    if !next_frame.payload.is_empty() {
                                        let payload = next_frame.payload.to_vec();
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
                                        update_snapshot(
                                            &worker_snapshot,
                                            |session_snapshot| {
                                                session_snapshot.inbound_packets = session_snapshot.inbound_packets.saturating_add(1);
                                                session_snapshot.inbound_bytes = session_snapshot.inbound_bytes.saturating_add(payload_len);
                                            },
                                        );
                                    }
                                }
                            }
                            Err(err) => {
                                alog_warn!("Worker: recv on transport[{}] failed: {}", active_index, err);
                                if transports.len() == 1 {
                                    alog_error!("Worker: only one transport, cannot failover");
                                    update_snapshot(&worker_snapshot, |session_snapshot| {
                                        session_snapshot.state = "error".to_owned();
                                        session_snapshot.last_error = Some(err.to_string());
                                    });
                                    break;
                                }

                                let old_index = active_index;
                                transports.remove(active_index);
                                if active_index >= transports.len() {
                                    active_index = 0;
                                }
                                sync_transport_snapshot(&worker_snapshot, &transports, active_index);
                                alog_warn!("Worker: failover from recv error on transport[{}] to transport[{}]", old_index, active_index);
                            }
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
                                flags: FLAG_PING,
                            },
                            payload: Bytes::new(),
                        };
                        alog_info!("Sending heartbeat ping seq={}", ping_sequence);
                        if let Err(err) = transports[active_index].send(ping).await {
                            alog_warn!("Heartbeat ping send failed: {}", err);
                        } else {
                            last_ping_sent_ms = Some(now_ms);
                            ping_sequence = ping_sequence.wrapping_add(1);
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
        let mut transport = paths.remove(0);
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
    use super::{
        android_client_config, bonded_ffi_api_version, complete_pairing_session_binding,
        decode_frame_metadata, establish_naive_tcp_session, get_session_snapshot_json,
        poll_inbound_packet, queue_outbound_packet, start_android_session,
        stop_android_session,
    };
    use bonded_client::ClientTransport;
    use bonded_core::auth::{create_auth_challenge, verify_auth_challenge};
    use bonded_core::session::{SessionFrame, SessionHeader, FLAG_PING, FLAG_PONG};
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

    #[test]
    fn android_session_runtime_can_pair_and_exchange_packets() {
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
}
