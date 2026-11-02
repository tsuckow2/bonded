//! Bootstrap server: a single TCP listener that serves both the bootstrap REST
//! API (e.g. `GET /v1/bootstrap/cert-proof`) and WebSocket session upgrades on
//! the same port and TLS configuration.
//!
//! Flow for each inbound connection:
//! 1. Optionally terminate TLS with the configured acceptor.
//! 2. Read the HTTP request line and headers (up to `\r\n\r\n`).
//! 3. If the request carries an `Upgrade: websocket` header, replay the
//!    buffered bytes via a [`PrependedStream`] and hand off to the WebSocket
//!    session path.
//! 4. Otherwise, route by URL path to the appropriate REST handler.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use bonded_core::auth::verify_signature;
use bonded_core::auth::{sign_bytes, DeviceKeypair, MintInviteRequest};
use bonded_core::diagnostics::{
    diagnostics_device_dir_name, DiagnosticsUploadRequest, DIAGNOSTICS_FILES_PER_DEVICE,
    MAX_DIAGNOSTICS_LOG_BYTES,
};
use bonded_core::peer_share::{
    PeerShareIntroductionClaims, PeerShareIntroductionRequest, SignedPeerShareIntroduction,
};
use bonded_core::session::{
    decode_observed_address, encode_observed_address, parse_session_epoch, SessionFrame,
    SessionHeader, FLAG_PATH_RETIRE, FLAG_PING, FLAG_PONG,
};
use bonded_core::transport::{PrependedStream, Transport, WebSocketTlsTransport};
use http::StatusCode;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::{server::TlsStream as ServerTlsStream, TlsAcceptor};
use tracing::{error, info, warn};

use crate::auth_handshake::perform_websocket_auth_handshake;
use crate::authorized_keys::AuthorizedKeysStore;
use crate::peer_relay::resolve_session_binding;
use crate::session_registry::SessionRegistry;
use crate::smoltcp_forwarder::{SessionContext, SessionOutboundRouter, SmoltcpForwarder};
use crate::tunnel_pcap::TunnelPcapLogger;

/// Maximum bytes to read while searching for the end of HTTP request headers.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Maximum frames to drain from the forwarder response queue per scheduler turn.
const MAX_DRAIN: usize = 256;

type ForwarderRegistry = Arc<RwLock<HashMap<u64, Arc<SessionContext>>>>;

#[derive(Debug, Clone)]
pub(crate) struct AdvertisedBootstrapEndpoints {
    pub server_public_address: String,
    pub wireguard_public_addr: Option<String>,
}

// ── Bootstrap context ─────────────────────────────────────────────────────────

/// Shared context injected into every connection handler.
pub struct BootstrapContext {
    /// Stable server identity key.  Signs the TLS cert fingerprint for the
    /// cert-proof endpoint so clients can trust a self-signed TLS cert using
    /// the already-trusted QR-provisioned ed25519 key.
    pub server_identity: Arc<DeviceKeypair>,

    /// DER bytes of the leaf TLS certificate.  `None` when TLS is not
    /// configured — the cert-proof endpoint returns `501 Not Implemented` in
    /// that case since there is no cert to prove.
    pub tls_cert_der: Option<Arc<Vec<u8>>>,

    /// Public HTTPS/WSS endpoint (`hostname:port`), reported in capabilities.
    pub server_public_address: String,

    /// Server WireGuard keypair.  `Some` when the WireGuard endpoint is active.
    pub wireguard_keypair: Option<Arc<bonded_core::transport::WireGuardKeypair>>,

    /// WireGuard peer registry.  Populated via `POST /v1/bootstrap/wireguard/peer`.
    pub wireguard_peers: Option<Arc<crate::wireguard::WireGuardPeerRegistry>>,

    /// Public WireGuard endpoint (`hostname:port`), or `None` when WireGuard
    /// is not enabled.  Reported in capabilities alongside the provisioning URL.
    pub wireguard_public_addr: Option<String>,

    /// Lease duration advertised for provisioned WireGuard peer assignments.
    pub wireguard_peer_lease_secs: u64,

    /// Authorized device store used when the server vouches for peer-sharing
    /// introductions.
    pub authorized_keys: AuthorizedKeysStore,

    /// Root directory for uploaded client diagnostics, one subdirectory
    /// per device key. Created on first upload.
    pub diagnostics_dir: PathBuf,

    /// Invite tokens file. The mint-invite endpoint persists bound tokens
    /// here; the auth handshake redeem path reads the same file live.
    pub invite_tokens_file: PathBuf,
}

impl BootstrapContext {
    /// QUIC is available whenever a TLS certificate is configured.
    pub fn quic_enabled(&self) -> bool {
        self.tls_cert_der.is_some()
    }

    /// WireGuard is available whenever a keypair is present.
    pub fn wireguard_enabled(&self) -> bool {
        self.wireguard_keypair.is_some()
    }

    /// Compute the SHA-256 fingerprint of the TLS cert and return an ed25519
    /// signature over the string `"sha256:<hex>"` using the server identity key.
    /// Returns `None` when no TLS cert is configured.
    pub fn cert_proof(&self) -> Option<anyhow::Result<(String, String)>> {
        let der = self.tls_cert_der.as_ref()?;
        let digest = Sha256::digest(der.as_slice());
        let hex_str: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let fingerprint = format!("sha256:{hex_str}");
        let sig = sign_bytes(&self.server_identity, fingerprint.as_bytes());
        Some(sig.map(|s| (fingerprint, s)).map_err(anyhow::Error::from))
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

pub async fn run_bootstrap_websocket_server(
    bind: &str,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tls_acceptor: Arc<RwLock<Option<TlsAcceptor>>>,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
    ctx: Arc<BootstrapContext>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind bootstrap listener on {bind}"))?;
    info!(bind = %bind, tls = tls_acceptor.read().expect("tls slot lock").is_some(), "bootstrap listener bound");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(err) => {
                error!(error = %err, "failed to accept bootstrap connection");
                continue;
            }
        };

        let ctx = ctx.clone();
        // Read the current acceptor from the slot at accept time so a renewed
        // certificate is picked up by all subsequent connections.
        let tls_acceptor = tls_acceptor.read().expect("tls slot lock").clone();
        let invite_tokens_file = invite_tokens_file.to_owned();
        let authorized_keys = authorized_keys.clone();
        let sessions = sessions.clone();
        let forwarders = forwarders.clone();
        let tunnel_pcap = tunnel_pcap.clone();

        tokio::spawn(async move {
            let result = if let Some(acceptor) = tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        handle_tls_stream(
                            tls_stream,
                            peer,
                            &ctx,
                            &invite_tokens_file,
                            authorized_keys,
                            sessions,
                            forwarders,
                            tunnel_pcap,
                        )
                        .await
                    }
                    Err(err) => Err(anyhow::anyhow!("TLS handshake with {peer} failed: {err}")),
                }
            } else {
                handle_plain_connection(
                    stream,
                    peer,
                    &ctx,
                    &invite_tokens_file,
                    authorized_keys,
                    sessions,
                    forwarders,
                    tunnel_pcap,
                )
                .await
            };

            if let Err(err) = result {
                warn!(peer = %peer, error = %err, "bootstrap connection error");
            }
        });
    }
}

// ── Per-connection dispatch ───────────────────────────────────────────────────

async fn handle_tls_stream(
    tls_stream: ServerTlsStream<TcpStream>,
    peer: SocketAddr,
    ctx: &BootstrapContext,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
) -> anyhow::Result<()> {
    let (request_bytes, is_ws, tls_stream) = read_http_headers_tls(tls_stream).await?;

    if is_ws {
        let prepended = PrependedStream::new(request_bytes, tls_stream);
        let transport = WebSocketTlsTransport::from_routed_tls(prepended)
            .await
            .context("websocket upgrade failed on TLS stream")?;
        handle_websocket_session(
            transport,
            peer,
            ctx,
            invite_tokens_file,
            authorized_keys,
            sessions,
            forwarders,
            tunnel_pcap,
        )
        .await
    } else {
        let (method, path, body) = parse_request_parts(&request_bytes);
        let advertised_endpoints =
            advertised_endpoints_for_request(ctx, parse_host_header(&request_bytes).as_deref());
        handle_rest_request(
            path,
            method,
            body,
            ctx,
            Some(&advertised_endpoints),
            tls_stream,
        )
        .await
    }
}

async fn handle_plain_connection(
    stream: TcpStream,
    peer: SocketAddr,
    ctx: &BootstrapContext,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
) -> anyhow::Result<()> {
    let (request_bytes, is_ws, stream) = read_http_headers_plain(stream).await?;

    if is_ws {
        let prepended = PrependedStream::new(request_bytes, stream);
        let transport = WebSocketTlsTransport::from_routed_plain(prepended)
            .await
            .context("websocket upgrade failed on plain stream")?;
        handle_websocket_session(
            transport,
            peer,
            ctx,
            invite_tokens_file,
            authorized_keys,
            sessions,
            forwarders,
            tunnel_pcap,
        )
        .await
    } else {
        let (method, path, body) = parse_request_parts(&request_bytes);
        let advertised_endpoints =
            advertised_endpoints_for_request(ctx, parse_host_header(&request_bytes).as_deref());
        handle_rest_request(path, method, body, ctx, Some(&advertised_endpoints), stream).await
    }
}

// ── HTTP header reading ───────────────────────────────────────────────────────

async fn read_http_headers_tls(
    mut stream: ServerTlsStream<TcpStream>,
) -> anyhow::Result<(Vec<u8>, bool, ServerTlsStream<TcpStream>)> {
    let (buf, is_ws) = read_until_end_of_headers(&mut stream).await?;
    Ok((buf, is_ws, stream))
}

async fn read_http_headers_plain(
    mut stream: TcpStream,
) -> anyhow::Result<(Vec<u8>, bool, TcpStream)> {
    let (buf, is_ws) = read_until_end_of_headers(&mut stream).await?;
    Ok((buf, is_ws, stream))
}

/// Read bytes until the HTTP header terminator `\r\n\r\n` is found or
/// `MAX_HEADER_BYTES` is consumed.  Returns `(bytes_read, is_websocket_upgrade)`.
async fn read_until_end_of_headers<S: AsyncReadExt + Unpin>(
    stream: &mut S,
) -> anyhow::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 256];

    loop {
        if buf.len() >= MAX_HEADER_BYTES {
            anyhow::bail!("HTTP request headers exceeded {MAX_HEADER_BYTES} bytes");
        }
        let n = stream
            .read(&mut tmp)
            .await
            .context("error reading HTTP request headers")?;
        if n == 0 {
            anyhow::bail!("connection closed before HTTP request headers were complete");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let Some(header_end) = find_header_terminator(&buf) else {
        anyhow::bail!("HTTP request headers missing terminator");
    };

    let content_length = parse_content_length(&buf[..header_end]);
    let target_len = header_end + 4 + content_length;
    while buf.len() < target_len {
        let n = stream
            .read(&mut tmp)
            .await
            .context("error reading HTTP request body")?;
        if n == 0 {
            anyhow::bail!(
                "connection closed before HTTP request body was complete (expected {content_length} bytes)"
            );
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    let is_ws = is_websocket_upgrade(&buf);
    Ok((buf, is_ws))
}

fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> usize {
    let text = std::str::from_utf8(headers).unwrap_or("");
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

/// Return `true` if the buffered request contains an `Upgrade: websocket` header.
fn is_websocket_upgrade(headers: &[u8]) -> bool {
    let text = std::str::from_utf8(headers).unwrap_or("");
    text.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("upgrade:") && lower.contains("websocket")
    })
}

/// Parse the HTTP method, path, and request body from the raw request bytes.
///
/// The body is the text after the `\r\n\r\n` header separator.
fn parse_request_parts(headers: &[u8]) -> (&str, &str, &str) {
    let text = std::str::from_utf8(headers).unwrap_or("");
    let first_line = text.lines().next().unwrap_or("");
    let mut parts = first_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");

    // Find the body (after \r\n\r\n).
    let body = if let Some(idx) = text.find("\r\n\r\n") {
        &text[idx + 4..]
    } else {
        ""
    };
    (method, path, body)
}

fn parse_host_header(request: &[u8]) -> Option<String> {
    let header_end = find_header_terminator(request)?;
    let text = std::str::from_utf8(&request[..header_end]).ok()?;
    text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("host") {
            let authority = value.trim();
            if authority.is_empty() {
                None
            } else {
                Some(authority.to_owned())
            }
        } else {
            None
        }
    })
}

fn rewrite_endpoint_authority(configured_endpoint: &str, requested_authority: &str) -> String {
    let requested = requested_authority.parse::<http::uri::Authority>().ok();
    let configured = configured_endpoint.parse::<http::uri::Authority>().ok();

    let host = requested
        .as_ref()
        .map(http::uri::Authority::host)
        .filter(|host| !host.is_empty())
        .unwrap_or(configured_endpoint);
    let port = requested
        .as_ref()
        .and_then(http::uri::Authority::port_u16)
        .or_else(|| configured.as_ref().and_then(http::uri::Authority::port_u16));

    if host.contains(':') && !host.starts_with('[') {
        match port {
            Some(port) => format!("[{host}]:{port}"),
            None => format!("[{host}]"),
        }
    } else {
        match port {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        }
    }
}

pub(crate) fn advertised_endpoints_for_request(
    ctx: &BootstrapContext,
    requested_authority: Option<&str>,
) -> AdvertisedBootstrapEndpoints {
    match requested_authority.filter(|authority| !authority.trim().is_empty()) {
        Some(authority) => AdvertisedBootstrapEndpoints {
            server_public_address: rewrite_endpoint_authority(
                &ctx.server_public_address,
                authority,
            ),
            wireguard_public_addr: ctx
                .wireguard_public_addr
                .as_deref()
                .map(|endpoint| rewrite_endpoint_authority(endpoint, authority)),
        },
        None => AdvertisedBootstrapEndpoints {
            server_public_address: ctx.server_public_address.clone(),
            wireguard_public_addr: ctx.wireguard_public_addr.clone(),
        },
    }
}

// ── REST routing ─────────────────────────────────────────────────────────────

async fn handle_rest_request<S: AsyncWriteExt + Unpin>(
    path: &str,
    method: &str,
    body: &str,
    ctx: &BootstrapContext,
    advertised_endpoints: Option<&AdvertisedBootstrapEndpoints>,
    mut stream: S,
) -> anyhow::Result<()> {
    let (status, body_resp) =
        route_bootstrap_request(method, path, body, ctx, advertised_endpoints);
    let reason = status.canonical_reason().unwrap_or("Unknown");

    let response = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body_resp}",
        status.as_u16(),
        reason,
        body_resp.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    stream.shutdown().await?;
    Ok(())
}

pub(crate) fn route_bootstrap_request(
    method: &str,
    path: &str,
    body: &str,
    ctx: &BootstrapContext,
    advertised_endpoints: Option<&AdvertisedBootstrapEndpoints>,
) -> (StatusCode, String) {
    let path_no_query = path.split('?').next().unwrap_or(path);
    match (method, path_no_query) {
        (_, "/v1/bootstrap/cert-proof") => cert_proof_response(ctx),
        (_, "/v1/bootstrap/capabilities") => capabilities_response(ctx, advertised_endpoints),
        ("POST", "/v1/bootstrap/wireguard/peer") => wireguard_peer_response(ctx, body),
        ("POST", "/v1/bootstrap/peer-share/introduction") => {
            peer_share_introduction_response(ctx, body)
        }
        ("POST", "/v1/bootstrap/diagnostics") => diagnostics_upload_response(ctx, body),
        ("POST", "/v1/bootstrap/mint-invite") => mint_invite_response(ctx, body),
        _ => (StatusCode::NOT_FOUND, r#"{"error":"not found"}"#.to_owned()),
    }
}

fn cert_proof_response(ctx: &BootstrapContext) -> (StatusCode, String) {
    match ctx.cert_proof() {
        None => (
            StatusCode::NOT_IMPLEMENTED,
            r#"{"error":"TLS not configured on this server; cert-proof requires TLS"}"#.to_owned(),
        ),
        Some(Err(err)) => {
            error!(error = %err, "failed to generate cert-proof signature");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"failed to generate cert proof"}"#.to_owned(),
            )
        }
        Some(Ok((fingerprint, signature))) => {
            let body = serde_json::json!({
                "cert_fingerprint": fingerprint,
                "ed25519_signature": signature,
            })
            .to_string();
            (StatusCode::OK, body)
        }
    }
}

/// `GET /v1/bootstrap/capabilities`
///
/// Returns a JSON object describing which transport endpoints the server
/// currently offers.  Clients should call this after cert-proof to decide
/// which protocols to dial.
///
/// Example response when only WSS is active:
/// ```json
/// {
///   "transports": ["wss"],
///   "wss": { "endpoint": "1.2.3.4:8443" }
/// }
/// ```
fn capabilities_response(
    ctx: &BootstrapContext,
    advertised_endpoints: Option<&AdvertisedBootstrapEndpoints>,
) -> (StatusCode, String) {
    let endpoints = advertised_endpoints
        .cloned()
        .unwrap_or_else(|| advertised_endpoints_for_request(ctx, None));
    let mut transports: Vec<&str> = vec!["wss"];
    let mut obj = serde_json::json!({
        "wss": {
            "endpoint": endpoints.server_public_address,
        }
    });

    if ctx.quic_enabled() {
        transports.push("h3");
        obj["h3"] = serde_json::json!({
            "endpoint": endpoints.server_public_address,
        });
    }

    if ctx.wireguard_enabled() {
        transports.push("wireguard");
        let wg_endpoint = endpoints
            .wireguard_public_addr
            .as_deref()
            .unwrap_or(&endpoints.server_public_address);
        let provision_url = format!(
            "https://{}/v1/bootstrap/wireguard/peer",
            endpoints.server_public_address
        );
        let server_wg_pubkey = ctx
            .wireguard_keypair
            .as_ref()
            .map(|kp| kp.public_key_b64())
            .unwrap_or_default();
        obj["wireguard"] = serde_json::json!({
            "endpoint": wg_endpoint,
            "provision_endpoint": provision_url,
            "server_public_key": server_wg_pubkey,
            "peer_lease_seconds": ctx.wireguard_peer_lease_secs,
        });
    }

    obj["transports"] = serde_json::json!(transports);
    (StatusCode::OK, obj.to_string())
}

/// `POST /v1/bootstrap/wireguard/peer`
///
/// Request body (JSON):
/// ```json
/// {
///   "device_public_key": "<ed25519 key b64>",
///   "wg_public_key": "<x25519 key b64>"
/// }
/// ```
///
/// Response (JSON):
/// ```json
/// {
///   "server_wg_public_key": "...",
///   "peer_ip": "100.64.1.x/32",
///   "lease_expires_at": 1767225600
/// }
/// ```
fn wireguard_peer_response(ctx: &BootstrapContext, body: &str) -> (StatusCode, String) {
    let (Some(kp), Some(peers)) = (ctx.wireguard_keypair.as_ref(), ctx.wireguard_peers.as_ref())
    else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            r#"{"error":"WireGuard is not enabled on this server"}"#.to_owned(),
        );
    };

    let req: serde_json::Value = match serde_json::from_str(body.trim()) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid JSON body"}"#.to_owned(),
            )
        }
    };
    let device_pk = req
        .get("device_public_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let wg_pk = req
        .get("wg_public_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if device_pk.is_empty() || wg_pk.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            r#"{"error":"device_public_key and wg_public_key are required"}"#.to_owned(),
        );
    }

    let peer = peers.register_peer_lease(device_pk, wg_pk);
    let body = serde_json::json!({
        "server_wg_public_key": kp.public_key_b64(),
        "peer_ip": peer.peer_ip,
        "lease_expires_at": peer.lease_expires_at,
    })
    .to_string();
    (StatusCode::OK, body)
}

/// Store one device-signed diagnostics upload. Quiet on success (the
/// client's rule for this feature is that routine uploads leave no log
/// noise on either side); rejects and storage failures are logged.
fn diagnostics_upload_response(ctx: &BootstrapContext, body: &str) -> (StatusCode, String) {
    let request: DiagnosticsUploadRequest = match serde_json::from_str(body.trim()) {
        Ok(request) => request,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid JSON body"}"#.to_owned(),
            )
        }
    };

    if request.device_public_key.is_empty()
        || request.log_text.is_empty()
        || request.signature.is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            r#"{"error":"device_public_key, log_text, and signature are required"}"#.to_owned(),
        );
    }
    if request.log_text.len() > MAX_DIAGNOSTICS_LOG_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            r#"{"error":"log_text exceeds the diagnostics size limit"}"#.to_owned(),
        );
    }
    if !ctx.authorized_keys.is_authorized(&request.device_public_key) {
        warn!(
            device = %request.device_public_key,
            "diagnostics upload from unauthorized device"
        );
        return (
            StatusCode::FORBIDDEN,
            r#"{"error":"device is not authorized"}"#.to_owned(),
        );
    }
    let signed_payload = match request.signed_payload() {
        Ok(payload) => payload,
        Err(err) => {
            error!(error = %err, "failed to serialize diagnostics upload payload");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"failed to serialize diagnostics payload"}"#.to_owned(),
            );
        }
    };
    if let Err(err) = verify_signature(
        &request.device_public_key,
        &signed_payload,
        &request.signature,
    ) {
        warn!(error = %err, "diagnostics upload signature verification failed");
        return (
            StatusCode::UNAUTHORIZED,
            r#"{"error":"invalid device signature"}"#.to_owned(),
        );
    }

    match store_diagnostics_upload(&ctx.diagnostics_dir, &request) {
        Ok(()) => (StatusCode::OK, r#"{"status":"ok"}"#.to_owned()),
        Err(err) => {
            error!(error = %err, "failed to store diagnostics upload");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"failed to store diagnostics upload"}"#.to_owned(),
            )
        }
    }
}

/// `POST /v1/bootstrap/mint-invite`
///
/// A paired device asks the server to mint a single-use invite bound to
/// another device's key (the QR-pairing flow: a phone pairs its TV). The
/// request envelope mirrors the diagnostics upload: the minter's device
/// key must already be authorized, and the signature must verify over the
/// canonical payload. The minted token is bound, so intercepting it is
/// useless to anyone but the target device — this matters because the
/// phone delivers the token to the TV over plaintext LAN HTTP.
fn mint_invite_response(ctx: &BootstrapContext, body: &str) -> (StatusCode, String) {
    let request: MintInviteRequest = match serde_json::from_str(body.trim()) {
        Ok(request) => request,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid JSON body"}"#.to_owned(),
            )
        }
    };

    if request.device_public_key.is_empty()
        || request.target_device_public_key.is_empty()
        || request.signature.is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            r#"{"error":"device_public_key, target_device_public_key, and signature are required"}"#.to_owned(),
        );
    }
    if !ctx.authorized_keys.is_authorized(&request.device_public_key) {
        warn!(
            device = %request.device_public_key,
            "mint-invite from unauthorized device"
        );
        return (
            StatusCode::FORBIDDEN,
            r#"{"error":"device is not authorized"}"#.to_owned(),
        );
    }
    let signed_payload = match request.signed_payload() {
        Ok(payload) => payload,
        Err(err) => {
            error!(error = %err, "failed to serialize mint-invite payload");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"failed to serialize mint-invite payload"}"#.to_owned(),
            );
        }
    };
    if let Err(err) = verify_signature(
        &request.device_public_key,
        &signed_payload,
        &request.signature,
    ) {
        warn!(error = %err, "mint-invite signature verification failed");
        return (
            StatusCode::UNAUTHORIZED,
            r#"{"error":"invalid device signature"}"#.to_owned(),
        );
    }

    match crate::invite_tokens::mint_invite_token(
        &ctx.invite_tokens_file,
        &request.target_device_public_key,
        600,
    ) {
        Ok(created) => (
            StatusCode::OK,
            format!(r#"{{"invite_token":"{}"}}"#, created.token),
        ),
        Err(err) => {
            error!(error = %err, "failed to mint invite token");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"failed to mint invite token"}"#.to_owned(),
            )
        }
    }
}

fn store_diagnostics_upload(
    root: &std::path::Path,
    request: &DiagnosticsUploadRequest,
) -> std::io::Result<()> {
    let device_dir = root.join(diagnostics_device_dir_name(&request.device_public_key));
    std::fs::create_dir_all(&device_dir)?;
    let build: String = request
        .client_build
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let stem = format!("{}_{}", request.captured_at_unix, build);
    let mut path = device_dir.join(format!("{stem}.log"));
    let mut suffix = 2;
    while path.exists() {
        path = device_dir.join(format!("{stem}-{suffix}.log"));
        suffix += 1;
    }
    std::fs::write(&path, &request.log_text)?;
    prune_diagnostics_dir(&device_dir)
}

/// Keep only the newest [`DIAGNOSTICS_FILES_PER_DEVICE`] uploads in a
/// device directory. File names start with the capture timestamp, so a
/// lexicographic sort is chronological.
fn prune_diagnostics_dir(device_dir: &std::path::Path) -> std::io::Result<()> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(device_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "log"))
        .collect();
    files.sort();
    while files.len() > DIAGNOSTICS_FILES_PER_DEVICE {
        let oldest = files.remove(0);
        let _ = std::fs::remove_file(oldest);
    }
    Ok(())
}

fn peer_share_introduction_response(ctx: &BootstrapContext, body: &str) -> (StatusCode, String) {
    let request: PeerShareIntroductionRequest = match serde_json::from_str(body.trim()) {
        Ok(request) => request,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid JSON body"}"#.to_owned(),
            )
        }
    };

    if request.consumer_device_public_key.is_empty()
        || request.provider_device_public_key.is_empty()
        || request.provider_instance_nonce.is_empty()
        || request.provider_endpoint.is_empty()
        || request.listener_transport.is_empty()
        || request.listener_cert_fingerprint.is_empty()
        || request.consumer_signature.is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            r#"{"error":"consumer_device_public_key, provider_device_public_key, provider_instance_nonce, provider_endpoint, listener_transport, listener_cert_fingerprint, and consumer_signature are required"}"#.to_owned(),
        );
    }

    if !ctx
        .authorized_keys
        .is_authorized(&request.consumer_device_public_key)
        || !ctx
            .authorized_keys
            .is_authorized(&request.provider_device_public_key)
    {
        return (
            StatusCode::FORBIDDEN,
            r#"{"error":"peer introduction requires both devices to be authorized"}"#.to_owned(),
        );
    }

    let signed_payload = match request.signed_payload() {
        Ok(payload) => payload,
        Err(err) => {
            error!(error = %err, "failed to serialize peer introduction request payload");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"failed to serialize peer introduction request"}"#.to_owned(),
            );
        }
    };
    if let Err(err) = verify_signature(
        &request.consumer_device_public_key,
        &signed_payload,
        &request.consumer_signature,
    ) {
        warn!(error = %err, "peer introduction signature verification failed");
        return (
            StatusCode::UNAUTHORIZED,
            r#"{"error":"invalid consumer signature"}"#.to_owned(),
        );
    }

    let claims = PeerShareIntroductionClaims {
        consumer_device_public_key: request.consumer_device_public_key,
        provider_device_public_key: request.provider_device_public_key,
        provider_instance_nonce: request.provider_instance_nonce,
        provider_endpoint: request.provider_endpoint,
        listener_transport: request.listener_transport,
        listener_cert_fingerprint: request.listener_cert_fingerprint,
        expires_at: unix_timestamp_after(Duration::from_secs(300)).unwrap_or(0),
    };
    let claims_payload = match claims.signing_payload() {
        Ok(payload) => payload,
        Err(err) => {
            error!(error = %err, "failed to serialize peer introduction claims");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"failed to serialize peer introduction claims"}"#.to_owned(),
            );
        }
    };
    let server_signature = match sign_bytes(&ctx.server_identity, &claims_payload) {
        Ok(signature) => signature,
        Err(err) => {
            error!(error = %err, "failed to sign peer introduction claims");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"failed to sign peer introduction"}"#.to_owned(),
            );
        }
    };

    let response = SignedPeerShareIntroduction {
        introduction: claims,
        server_signature,
    };
    match serde_json::to_string(&response) {
        Ok(body) => (StatusCode::OK, body),
        Err(err) => {
            error!(error = %err, "failed to serialize peer introduction response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"failed to serialize peer introduction response"}"#.to_owned(),
            )
        }
    }
}

fn unix_timestamp_after(duration: Duration) -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .saturating_add(duration)
        .as_secs())
}

// WebSocket-specific entry point: performs auth handshake, then delegates
// to the generic transport session loop (testable with mock transports).
async fn handle_websocket_session(
    mut transport: WebSocketTlsTransport,
    peer: SocketAddr,
    ctx: &BootstrapContext,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
) -> anyhow::Result<()> {
    let public_key = match perform_websocket_auth_handshake(
        &mut transport,
        authorized_keys,
        std::path::Path::new(invite_tokens_file),
    )
    .await
    {
        Ok(pk) => pk,
        Err(err) => {
            warn!(peer = %peer, error = %err, "websocket client authentication failed");
            return Ok(());
        }
    };
    handle_transport_session(
        transport,
        peer,
        ctx,
        public_key,
        sessions,
        forwarders,
        tunnel_pcap,
    )
    .await
}

async fn handle_transport_session<T: Transport>(
    mut transport: T,
    peer: SocketAddr,
    ctx: &BootstrapContext,
    public_key: String,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
) -> anyhow::Result<()> {
    let binding = match resolve_session_binding(
        &mut transport,
        public_key.clone(),
        ctx.server_identity.as_ref(),
    )
    .await
    {
        Ok(binding) => binding,
        Err(err) => {
            warn!(peer = %peer, public_key = %public_key, error = %err, "failed to bind websocket session after authentication");
            return Ok(());
        }
    };

    let handle = sessions.register_client(binding.client_public_key.clone());
    info!(
        peer = %peer,
        public_key = %binding.client_public_key,
        authenticated_public_key = %public_key,
        relayed_via_provider = binding.relayed_via_provider,
        session_id = handle.session_id,
        "websocket client authenticated via bootstrap listener"
    );

    let (forward_tx, mut forward_rx) = mpsc::unbounded_channel::<SessionFrame>();
    let transport_id = crate::smoltcp_forwarder::alloc_transport_id();
    // Exactly one forwarding context per session, shared by every path: the
    // flow state and outbound sequence space must survive the death of any
    // single path for failover to work.
    // Avoid holding the forwarders write lock while creating the SessionContext
    // (which spawns threads) to prevent lock-ordering deadlocks.
    let session_ctx: Arc<SessionContext> = {
        // Fast path: check if session already exists (read lock)
        {
            let guard = forwarders
                .read()
                .expect("forwarder registry lock should not be poisoned");
            if let Some(existing) = guard.get(&handle.session_id) {
                existing.clone()
            } else {
                // Drop read lock before expensive creation
                drop(guard);
                // Create the context WITHOUT holding any forwarder lock
                let (router, fwd_tx) = SessionOutboundRouter::new();
                let forwarder = Arc::new(SmoltcpForwarder::new(
                    handle.session_id,
                    fwd_tx,
                    Arc::new(AtomicU64::new(0)),
                ));
                let ctx = Arc::new(SessionContext { forwarder, router });
                // Acquire write lock and insert (double-check for race)
                let mut guard = forwarders
                    .write()
                    .expect("forwarder registry lock should not be poisoned");
                if let Some(existing) = guard.get(&handle.session_id) {
                    // Another task created it concurrently, use theirs
                    // (the one we created will be dropped)
                    existing.clone()
                } else {
                    guard.insert(handle.session_id, ctx.clone());
                    ctx
                }
            }
        }
    };
    session_ctx.router.add_transport(transport_id, forward_tx);
    session_ctx.router.note_peer(transport_id, peer);
    tracing::info!(
        session_id = handle.session_id,
        transport_id = transport_id,
        relayed_via_provider = binding.relayed_via_provider,
        total_transports = session_ctx.router.transport_count(),
        "added transport to session router"
    );
    let forwarder: Arc<SmoltcpForwarder> = session_ctx.forwarder.clone();

    let mut pending_frame = binding.initial_frame;
    loop {
        // Send at most one queued frame before polling inbound; draining the full queue starves recv when the forwarder is chatty.
        if let Ok(frame) = forward_rx.try_recv() {
            log_tunnel_packet(&tunnel_pcap, &frame.payload);
            if let Err(err) = transport.send(frame.clone()).await {
                warn!(peer = %peer, session_id = handle.session_id, error = %err,
                    "failed to return drained websocket frame; requeueing on a live transport");
                session_ctx.router.remove_transport(transport_id);
                session_ctx.router.requeue(frame);
                break;
            }
        }

        if let Some(frame) = pending_frame.take() {
            log_tunnel_packet(&tunnel_pcap, &frame.payload);
            if frame.header.flags & FLAG_PING != 0
                && (frame.payload.is_empty()
                    || parse_session_epoch(&frame).is_some())
            {
                session_ctx.router.note_frame_flags(frame.header.flags);
                if let Some(epoch) = parse_session_epoch(&frame) {
                    session_ctx.router.adopt_epoch(transport_id, epoch);
                }
                let pong = SessionFrame {
                    header: SessionHeader {
                        connection_id: handle.session_id as u32,
                        sequence: frame.header.sequence,
                        flags: FLAG_PONG,
                    },
                    // Stamp the address this transport's peer presents
                    // from, so the client can show its per-path public
                    // (egress) address. Older clients ignore PONG
                    // payloads, so this is backward compatible.
                    payload: encode_observed_address(peer),
                };
                if let Err(err) = transport.send(pong).await {
                    warn!(peer = %peer, session_id = handle.session_id, error = %err,
                        "failed to send initial heartbeat pong");
                    break;
                }
            } else {
                session_ctx.router.note_frame(transport_id, frame.header.flags);
                forwarder.ingest_packet(frame);
            }
            continue;
        }

        tokio::select! {
            maybe_frame = forward_rx.recv() => {
                let Some(frame) = maybe_frame else {
                    warn!(peer = %peer, session_id = handle.session_id,
                        "websocket forwarder response queue closed");
                    break;
                };
                log_tunnel_packet(&tunnel_pcap, &frame.payload);
                if let Err(err) = transport.send(frame.clone()).await {
                    warn!(peer = %peer, session_id = handle.session_id, error = %err,
                        "failed to send websocket frame; requeueing on a live transport");
                    session_ctx.router.remove_transport(transport_id);
                    session_ctx.router.requeue(frame);
                    break;
                }
            }
            recv_result = tokio::time::timeout(std::time::Duration::from_secs(30), transport.recv()) => {
                let recv_result = match recv_result {
                    Ok(r) => r,
                    Err(_) => {
                        warn!(peer = %peer, session_id = handle.session_id, "transport recv timeout (30s), closing dead connection");
                        break;
                    }
                };
                match recv_result {
                    Ok(frame) => {
                        // Deep-dive: log frames arriving on relayed (provider) transports.
                        // This traces whether HTTP SYNs reach the server via the relay.
                        if binding.relayed_via_provider {
                            tracing::debug!(
                                session_id = handle.session_id,
                                flags = frame.header.flags,
                                payload_len = frame.payload.len(),
                                conn_id = frame.header.connection_id,
                                "relay transport received frame"
                            );
                        }
                        log_tunnel_packet(&tunnel_pcap, &frame.payload);
                        if frame.header.flags & FLAG_PATH_RETIRE != 0 {
                            match decode_observed_address(&frame.payload) {
                                Some(dead_peer) => {
                                    let retired =
                                        session_ctx.router.retire_by_peer(dead_peer);
                                    tracing::info!(
                                        session_id = handle.session_id,
                                        dead_peer = %dead_peer, retired = ?retired,
                                        "retired transports for dead path at client request"
                                    );
                                }
                                None => {
                                    tracing::warn!(
                                        session_id = handle.session_id,
                                        "path-retire frame with undecodable payload"
                                    );
                                }
                            }
                            continue;
                        }
                        if frame.header.flags & FLAG_PING != 0
                            && (frame.payload.is_empty()
                                || parse_session_epoch(&frame).is_some())
                        {
                            session_ctx.router.note_frame_flags(frame.header.flags);
                            if let Some(epoch) = parse_session_epoch(&frame) {
                                session_ctx.router.adopt_epoch(transport_id, epoch);
                            }
                            let pong = SessionFrame {
                                header: SessionHeader {
                                    connection_id: handle.session_id as u32,
                                    sequence: frame.header.sequence,
                                    flags: FLAG_PONG,
                                },
                                // Observed-address stamp: see the
                                // initial-frame pong above.
                                payload: encode_observed_address(peer),
                            };
                            if let Err(err) = transport.send(pong).await {
                                warn!(peer = %peer, session_id = handle.session_id, error = %err,
                                    "failed to send heartbeat pong");
                                break;
                            }
                            continue;
                        }
                        session_ctx.router.note_frame(transport_id, frame.header.flags);
                        forwarder.ingest_packet(frame);
                    }
                    Err(err) => {
                        info!(peer = %peer, public_key = %public_key,
                            session_id = handle.session_id, error = ?err,
                            "websocket client session ended");
                        break;
                    }
                }
            }
        }
    }

    session_ctx.router.remove_transport(transport_id);
    // Only tear down the session when its last path disconnects; otherwise
    // the surviving path keeps the flow state and sequence space alive.
    let remaining = session_ctx.router.transport_count();
    tracing::info!(
        session_id = handle.session_id,
        transport_id = ?transport_id,
        remaining_transports = remaining,
        relayed_via_provider = binding.relayed_via_provider,
        "transport session ended"
    );
    if remaining == 0 {
        tracing::warn!(
            session_id = handle.session_id,
            "tearing down session: last transport disconnected"
        );
        forwarder.clear_session();
        forwarders
            .write()
            .expect("forwarder registry lock should not be poisoned")
            .remove(&handle.session_id);
        sessions.unregister_client(&binding.client_public_key);
    }
    Ok(())
}

#[inline]
fn log_tunnel_packet(pcap: &Option<Arc<TunnelPcapLogger>>, payload: &bytes::Bytes) {
    if payload.is_empty() {
        return;
    }
    if let Some(logger) = pcap {
        logger.log_packet(payload);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorized_keys::{authorize_device_key, AuthorizedKeysStore};
    use bonded_core::auth::{sign_bytes, verify_signature, DeviceKeypair};
    use bonded_core::diagnostics::{
        DiagnosticsUploadRequest, DIAGNOSTICS_FILES_PER_DEVICE, MAX_DIAGNOSTICS_LOG_BYTES,
    };
    use bonded_core::peer_share::{PeerShareIntroductionRequest, SignedPeerShareIntroduction};
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Build a minimal `BootstrapContext` suitable for testing.
    /// No TLS cert is configured, so cert-proof returns 501.
    fn test_ctx() -> Arc<BootstrapContext> {
        Arc::new(BootstrapContext {
            server_identity: Arc::new(DeviceKeypair::generate()),
            tls_cert_der: None,
            server_public_address: "127.0.0.1:8443".to_owned(),
            wireguard_keypair: None,
            wireguard_peers: None,
            wireguard_public_addr: None,
            wireguard_peer_lease_secs: 3600,
            authorized_keys: AuthorizedKeysStore::default(),
            diagnostics_dir: std::env::temp_dir().join("bonded-diagnostics-test"),
            invite_tokens_file: std::env::temp_dir().join("bonded-invites-test.toml"),
        })
    }

    fn temp_auth_file(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("bonded-auth-{name}-{stamp}.toml"))
    }

    /// Start a plain-TCP bootstrap server on an ephemeral port and return the
    /// bound address.  The server task is spawned as a background task and
    /// will be dropped (and therefore stop accepting) when the returned
    /// `tokio::task::JoinHandle` is dropped.
    async fn start_plain_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        use crate::authorized_keys::AuthorizedKeysStore;
        use crate::session_registry::SessionRegistry;

        let ctx = test_ctx();
        let _authorized_keys = AuthorizedKeysStore::default();
        let _sessions = SessionRegistry::default();
        let _forwarders: ForwarderRegistry = Arc::new(RwLock::new(HashMap::new()));

        // Bind to an ephemeral port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");

        let handle = tokio::spawn(async move {
            // Re-use the private `run_bootstrap_websocket_server` logic by
            // directly calling `handle_connection` for each accepted connection.
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let ctx_inner = ctx.clone();
                        tokio::spawn(async move {
                            // No TLS — go straight to plain HTTP routing.
                            let result = handle_plain_connection(
                                stream,
                                peer,
                                &ctx_inner,
                                "unused-invites.toml",
                                AuthorizedKeysStore::default(),
                                SessionRegistry::default(),
                                Arc::new(RwLock::new(HashMap::new())),
                                None,
                            )
                            .await;
                            if let Err(e) = result {
                                eprintln!("[test] connection error: {e}");
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        (addr, handle)
    }

    /// Send a raw HTTP/1.1 GET to the given address and return the full response.
    async fn http_get(addr: SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to test server");
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("send request");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read response");
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn cert_proof_returns_501_when_no_tls() {
        let (addr, _handle) = start_plain_server().await;
        let response = http_get(addr, "/v1/bootstrap/cert-proof").await;
        assert!(
            response.starts_with("HTTP/1.1 501"),
            "expected 501, got: {response}"
        );
        assert!(response.contains("TLS not configured"));
    }

    #[tokio::test]
    async fn capabilities_returns_wss_transport() {
        let (addr, _handle) = start_plain_server().await;
        let response = http_get(addr, "/v1/bootstrap/capabilities").await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected 200, got: {response}"
        );
        let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
        let json: serde_json::Value = serde_json::from_str(body.trim()).expect("valid JSON body");
        let transports = json["transports"].as_array().expect("transports array");
        assert!(
            transports.iter().any(|t| t.as_str() == Some("wss")),
            "expected 'wss' in transports: {transports:?}"
        );
        assert_eq!(
            json["wss"]["endpoint"].as_str(),
            Some("localhost:8443"),
            "unexpected wss endpoint"
        );
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let (addr, _handle) = start_plain_server().await;
        let response = http_get(addr, "/v1/no-such-endpoint").await;
        assert!(
            response.starts_with("HTTP/1.1 404"),
            "expected 404, got: {response}"
        );
    }

    #[tokio::test]
    async fn capabilities_includes_h3_when_quic_enabled() {
        use crate::authorized_keys::AuthorizedKeysStore;
        use crate::session_registry::SessionRegistry;

        // tls_cert_der being Some triggers quic_enabled() = true.
        let ctx = Arc::new(BootstrapContext {
            server_identity: Arc::new(DeviceKeypair::generate()),
            tls_cert_der: Some(Arc::new(vec![0u8; 32])), // non-empty → QUIC on
            server_public_address: "10.0.0.1:9443".to_owned(),
            wireguard_keypair: None,
            wireguard_peers: None,
            wireguard_public_addr: None,
            wireguard_peer_lease_secs: 3600,
            authorized_keys: AuthorizedKeysStore::default(),
            diagnostics_dir: std::env::temp_dir().join("bonded-diagnostics-test"),
            invite_tokens_file: std::env::temp_dir().join("bonded-invites-test.toml"),
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let _handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let ctx_inner = ctx.clone();
                        tokio::spawn(async move {
                            let _ = handle_plain_connection(
                                stream,
                                peer,
                                &ctx_inner,
                                "unused.toml",
                                AuthorizedKeysStore::default(),
                                SessionRegistry::default(),
                                Arc::new(RwLock::new(HashMap::new())),
                                None,
                            )
                            .await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        let response = http_get(addr, "/v1/bootstrap/capabilities").await;
        let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
        let json: serde_json::Value = serde_json::from_str(body.trim()).expect("valid JSON");
        let transports = json["transports"].as_array().expect("transports array");
        assert!(
            transports.iter().any(|t| t.as_str() == Some("h3")),
            "expected 'h3' in transports when tls_cert_der is Some: {transports:?}"
        );
        // wireguard_keypair is None, so WireGuard should NOT appear
        assert!(
            !transports.iter().any(|t| t.as_str() == Some("wireguard")),
            "expected no 'wireguard' in transports when wireguard_keypair is None: {transports:?}"
        );
    }

    #[test]
    fn peer_share_introduction_requires_authorized_devices() {
        let consumer = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let request = PeerShareIntroductionRequest {
            consumer_device_public_key: consumer.public_key_b64.clone(),
            provider_device_public_key: provider.public_key_b64.clone(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:test-fingerprint".to_owned(),
            consumer_signature: sign_bytes(
                &consumer,
                &serde_json::to_vec(&serde_json::json!({
                    "consumer_device_public_key": consumer.public_key_b64,
                    "provider_device_public_key": provider.public_key_b64,
                    "provider_instance_nonce": "nonce-1",
                    "provider_endpoint": "192.168.1.20:54443",
                    "listener_transport": "quic",
                    "listener_cert_fingerprint": "sha256:test-fingerprint",
                }))
                .expect("request payload should serialize"),
            )
            .expect("request should sign"),
        };

        let (status, _) = route_bootstrap_request(
            "POST",
            "/v1/bootstrap/peer-share/introduction",
            &serde_json::to_string(&request).expect("request should serialize"),
            test_ctx().as_ref(),
            None,
        );

        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    fn diagnostics_test_ctx(
        authorized: &[&DeviceKeypair],
        name: &str,
    ) -> (Arc<BootstrapContext>, PathBuf) {
        let auth_path = temp_auth_file(name);
        for device in authorized {
            authorize_device_key(&auth_path, &device.public_key_b64)
                .expect("device key should authorize");
        }
        let authorized_keys =
            AuthorizedKeysStore::load(&auth_path).expect("authorized keys store should load");
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let diagnostics_dir = std::env::temp_dir().join(format!("bonded-diag-{name}-{stamp}"));
        let ctx = Arc::new(BootstrapContext {
            server_identity: Arc::new(DeviceKeypair::generate()),
            tls_cert_der: None,
            server_public_address: "127.0.0.1:8443".to_owned(),
            wireguard_keypair: None,
            wireguard_peers: None,
            wireguard_public_addr: None,
            wireguard_peer_lease_secs: 3600,
            authorized_keys,
            diagnostics_dir: diagnostics_dir.clone(),
            invite_tokens_file: std::env::temp_dir().join(format!("bonded-invites-{name}-{stamp}.toml")),
        });
        (ctx, diagnostics_dir)
    }

    fn signed_diagnostics_request(
        device: &DeviceKeypair,
        captured_at_unix: u64,
        log_text: &str,
    ) -> DiagnosticsUploadRequest {
        let mut request = DiagnosticsUploadRequest {
            device_public_key: device.public_key_b64.clone(),
            client_build: "146".to_owned(),
            captured_at_unix,
            log_text: log_text.to_owned(),
            signature: String::new(),
        };
        request.signature = sign_bytes(
            device,
            &request.signed_payload().expect("payload should serialize"),
        )
        .expect("request should sign");
        request
    }

    fn post_diagnostics(
        ctx: &BootstrapContext,
        request: &DiagnosticsUploadRequest,
    ) -> StatusCode {
        route_bootstrap_request(
            "POST",
            "/v1/bootstrap/diagnostics",
            &serde_json::to_string(request).expect("request should serialize"),
            ctx,
            None,
        )
        .0
    }

    #[test]
    fn diagnostics_upload_stores_authorized_signed_log() {
        let device = DeviceKeypair::generate();
        let (ctx, dir) = diagnostics_test_ctx(&[&device], "diag-ok");
        let request = signed_diagnostics_request(&device, 1_760_000_000, "hello diagnostics\n");

        assert_eq!(post_diagnostics(&ctx, &request), StatusCode::OK);

        let device_dir = dir.join(bonded_core::diagnostics::diagnostics_device_dir_name(
            &device.public_key_b64,
        ));
        let stored = fs::read_to_string(device_dir.join("1760000000_146.log"))
            .expect("upload should be stored under the device directory");
        assert_eq!(stored, "hello diagnostics\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn diagnostics_upload_rejects_unauthorized_device() {
        let device = DeviceKeypair::generate();
        let (ctx, dir) = diagnostics_test_ctx(&[], "diag-unauth");
        let request = signed_diagnostics_request(&device, 1_760_000_000, "nope\n");

        assert_eq!(post_diagnostics(&ctx, &request), StatusCode::FORBIDDEN);
        assert!(!dir.exists(), "rejected uploads must not be stored");
    }

    #[test]
    fn diagnostics_upload_rejects_bad_signature() {
        let device = DeviceKeypair::generate();
        let (ctx, dir) = diagnostics_test_ctx(&[&device], "diag-badsig");
        let mut request = signed_diagnostics_request(&device, 1_760_000_000, "original\n");
        request.log_text = "tampered\n".to_owned();

        assert_eq!(post_diagnostics(&ctx, &request), StatusCode::UNAUTHORIZED);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn diagnostics_upload_rejects_oversized_log() {
        let device = DeviceKeypair::generate();
        let (ctx, dir) = diagnostics_test_ctx(&[&device], "diag-big");
        let oversized = "x".repeat(MAX_DIAGNOSTICS_LOG_BYTES + 1);
        let request = signed_diagnostics_request(&device, 1_760_000_000, &oversized);

        assert_eq!(
            post_diagnostics(&ctx, &request),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let _ = fs::remove_dir_all(&dir);
    }

    fn signed_mint_request(
        device: &DeviceKeypair,
        target_key: &str,
    ) -> MintInviteRequest {
        let mut request = MintInviteRequest {
            device_public_key: device.public_key_b64.clone(),
            target_device_public_key: target_key.to_owned(),
            requested_at_unix: 1_760_000_000,
            signature: String::new(),
        };
        request.signature = sign_bytes(
            device,
            &request.signed_payload().expect("payload should serialize"),
        )
        .expect("request should sign");
        request
    }

    fn post_mint(
        ctx: &BootstrapContext,
        request: &MintInviteRequest,
    ) -> (StatusCode, String) {
        route_bootstrap_request(
            "POST",
            "/v1/bootstrap/mint-invite",
            &serde_json::to_string(request).expect("request should serialize"),
            ctx,
            None,
        )
    }

    #[test]
    fn mint_invite_mints_bound_token_redeemable_only_by_target() {
        let minter = DeviceKeypair::generate();
        let tv = DeviceKeypair::generate();
        let (ctx, dir) = diagnostics_test_ctx(&[&minter], "mint-ok");
        let request = signed_mint_request(&minter, &tv.public_key_b64);

        let (status, body) = post_mint(&ctx, &request);
        assert_eq!(status, StatusCode::OK);
        let token = serde_json::from_str::<serde_json::Value>(&body)
            .expect("mint body should be JSON")["invite_token"]
            .as_str()
            .expect("invite_token should be a string")
            .to_owned();
        assert!(!token.is_empty());

        // The minted token is bound: a wrong-key redeem fails WITHOUT
        // consuming it, and the target key then redeems it.
        assert!(
            !crate::invite_tokens::redeem_invite_token(
                &ctx.invite_tokens_file,
                &token,
                &minter.public_key_b64
            )
            .expect("wrong-key redeem should report false")
        );
        assert!(
            crate::invite_tokens::redeem_invite_token(
                &ctx.invite_tokens_file,
                &token,
                &tv.public_key_b64
            )
            .expect("right-key redeem should succeed")
        );

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_file(&ctx.invite_tokens_file);
    }

    #[test]
    fn mint_invite_rejects_unauthorized_device() {
        let device = DeviceKeypair::generate();
        let tv = DeviceKeypair::generate();
        let (ctx, dir) = diagnostics_test_ctx(&[], "mint-unauth");
        let request = signed_mint_request(&device, &tv.public_key_b64);

        assert_eq!(post_mint(&ctx, &request).0, StatusCode::FORBIDDEN);
        assert!(
            !ctx.invite_tokens_file.exists(),
            "rejected mint must not create a token"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mint_invite_rejects_bad_signature() {
        let device = DeviceKeypair::generate();
        let tv = DeviceKeypair::generate();
        let (ctx, dir) = diagnostics_test_ctx(&[&device], "mint-badsig");
        let mut request = signed_mint_request(&device, &tv.public_key_b64);
        request.target_device_public_key = "tampered".to_owned();

        assert_eq!(post_mint(&ctx, &request).0, StatusCode::UNAUTHORIZED);
        assert!(!ctx.invite_tokens_file.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn diagnostics_store_prunes_to_retention_cap() {
        let device = DeviceKeypair::generate();
        let dir = std::env::temp_dir().join(format!(
            "bonded-diag-prune-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        ));
        for index in 0..(DIAGNOSTICS_FILES_PER_DEVICE + 3) {
            let request =
                signed_diagnostics_request(&device, 1_760_000_000 + index as u64, "log\n");
            store_diagnostics_upload(&dir, &request).expect("store should succeed");
        }
        let device_dir = dir.join(bonded_core::diagnostics::diagnostics_device_dir_name(
            &device.public_key_b64,
        ));
        let mut names: Vec<String> = fs::read_dir(&device_dir)
            .expect("device dir should exist")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names.len(), DIAGNOSTICS_FILES_PER_DEVICE);
        assert!(
            names[0].starts_with("1760000003_"),
            "the three oldest uploads should be pruned, got {names:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_share_introduction_returns_server_signed_claims() {
        let consumer = DeviceKeypair::generate();
        let provider = DeviceKeypair::generate();
        let auth_path = temp_auth_file("peer-intro");
        authorize_device_key(&auth_path, &consumer.public_key_b64)
            .expect("consumer key should authorize");
        authorize_device_key(&auth_path, &provider.public_key_b64)
            .expect("provider key should authorize");
        let authorized_keys =
            AuthorizedKeysStore::load(&auth_path).expect("authorized keys store should load");
        let server_identity = Arc::new(DeviceKeypair::generate());
        let ctx = Arc::new(BootstrapContext {
            server_identity: server_identity.clone(),
            tls_cert_der: None,
            server_public_address: "127.0.0.1:8443".to_owned(),
            wireguard_keypair: None,
            wireguard_peers: None,
            wireguard_public_addr: None,
            wireguard_peer_lease_secs: 3600,
            authorized_keys,
            diagnostics_dir: std::env::temp_dir().join("bonded-diagnostics-test"),
            invite_tokens_file: std::env::temp_dir().join("bonded-invites-test.toml"),
        });

        let unsigned = serde_json::json!({
            "consumer_device_public_key": consumer.public_key_b64.clone(),
            "provider_device_public_key": provider.public_key_b64.clone(),
            "provider_instance_nonce": "nonce-2",
            "provider_endpoint": "192.168.1.21:54443",
            "listener_transport": "quic",
            "listener_cert_fingerprint": "sha256:listener-fingerprint",
        });
        let request = PeerShareIntroductionRequest {
            consumer_device_public_key: unsigned["consumer_device_public_key"]
                .as_str()
                .expect("consumer key should exist")
                .to_owned(),
            provider_device_public_key: unsigned["provider_device_public_key"]
                .as_str()
                .expect("provider key should exist")
                .to_owned(),
            provider_instance_nonce: "nonce-2".to_owned(),
            provider_endpoint: "192.168.1.21:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:listener-fingerprint".to_owned(),
            consumer_signature: sign_bytes(
                &consumer,
                &serde_json::to_vec(&unsigned).expect("request payload should serialize"),
            )
            .expect("request should sign"),
        };

        let (status, body) = route_bootstrap_request(
            "POST",
            "/v1/bootstrap/peer-share/introduction",
            &serde_json::to_string(&request).expect("request should serialize"),
            ctx.as_ref(),
            None,
        );

        assert_eq!(status, StatusCode::OK);
        let response: SignedPeerShareIntroduction =
            serde_json::from_str(&body).expect("response should parse");
        assert_eq!(
            response.introduction.provider_device_public_key,
            provider.public_key_b64
        );
        assert_eq!(response.introduction.listener_transport, "quic");
        assert_eq!(
            response.introduction.listener_cert_fingerprint,
            "sha256:listener-fingerprint"
        );
        assert!(response.introduction.expires_at > 0);
        verify_signature(
            &server_identity.public_key_b64,
            &response
                .introduction
                .signing_payload()
                .expect("claims should serialize"),
            &response.server_signature,
        )
        .expect("server signature should verify");
        let _ = fs::remove_file(auth_path);
    }

    #[test]
    fn capabilities_response_prefers_request_authority() {
        let ctx = test_ctx();
        let advertised =
            advertised_endpoints_for_request(ctx.as_ref(), Some("charter.codingwell.net:443"));

        let (status, body) = route_bootstrap_request(
            "GET",
            "/v1/bootstrap/capabilities",
            "",
            ctx.as_ref(),
            Some(&advertised),
        );

        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value =
            serde_json::from_str(&body).expect("capabilities should parse");
        assert_eq!(json["wss"]["endpoint"], "charter.codingwell.net:443");
    }

    // ── MockTransport for testing the session loop ────────────────────────────

    use bonded_core::transport::TransportKind;

    /// In-memory mock transport for unit-testing handle_transport_session.
    struct MockTransport {
        inbound_rx: mpsc::UnboundedReceiver<SessionFrame>,
        outbound_tx: mpsc::UnboundedSender<SessionFrame>,
    }

    impl MockTransport {
        fn new() -> (
            Self,
            mpsc::UnboundedSender<SessionFrame>,
            mpsc::UnboundedReceiver<SessionFrame>,
        ) {
            let (in_tx, in_rx) = mpsc::unbounded_channel();
            let (out_tx, out_rx) = mpsc::unbounded_channel();
            let mock = Self {
                inbound_rx: in_rx,
                outbound_tx: out_tx,
            };
            (mock, in_tx, out_rx)
        }
    }
    #[async_trait::async_trait]
    impl Transport for MockTransport {
        async fn send(&mut self, frame: SessionFrame) -> anyhow::Result<()> {
            self.outbound_tx
                .send(frame)
                .map_err(|_| anyhow::anyhow!("mock outbound closed"))?;
            Ok(())
        }

        async fn recv(&mut self) -> anyhow::Result<SessionFrame> {
            self.inbound_rx
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("mock inbound closed"))
        }

        fn kind(&self) -> TransportKind {
            TransportKind::WebSocketTls
        }
    }

    fn test_session_frame(flags: u32, payload_len: usize) -> SessionFrame {
        SessionFrame {
            header: SessionHeader {
                connection_id: 0,
                sequence: 0,
                flags,
            },
            payload: bytes::Bytes::from(vec![0u8; payload_len]),
        }
    }

    /// Regression test for data-plane recv starvation.
    #[tokio::test]
    async fn transport_session_delivers_data_frame_to_forwarder() {
        let ctx = test_ctx();
        let sessions = SessionRegistry::default();
        let forwarders: ForwarderRegistry =
            Arc::new(RwLock::new(std::collections::HashMap::new()));

        let (mock, inbound_tx, mut outbound_rx) = MockTransport::new();
        let peer: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let public_key = "test-public-key".to_owned();

        let sessions_clone = sessions.clone();
        let forwarders_clone = forwarders.clone();
        let handle = tokio::spawn(async move {
            handle_transport_session(
                mock, peer, ctx.as_ref(), public_key, sessions_clone, forwarders_clone, None,
            )
            .await
        });

        // Send PING for session binding
        inbound_tx
            .send(test_session_frame(FLAG_PING, 0))
            .expect("send ping");

        // Wait for PONG (proves binding completed)
        let pong = tokio::time::timeout(std::time::Duration::from_secs(2), outbound_rx.recv())
            .await
            .expect("timeout waiting for PONG")
            .expect("outbound closed");
        assert!(
            pong.header.flags & bonded_core::session::FLAG_PONG != 0,
            "expected PONG, got flags={}",
            pong.header.flags
        );

        // Send a data frame (60-byte payload like a TCP SYN)
        inbound_tx
            .send(test_session_frame(0, 60))
            .expect("send data frame");

        // Give the server time to process
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Handler should still be running
        assert!(!handle.is_finished(), "session handler exited unexpectedly");

        // Cleanup
        drop(inbound_tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }
    /// Build a well-formed IPv4 TCP SYN packet (20B IP + 20B TCP = 40B).
    /// Mirrors the 60-byte TUN SYNs seen in production (20B IP + 40B TCP with options;
    /// we use the minimal 20B TCP header here).
    fn build_tcp_syn_packet() -> bytes::Bytes {
        let mut pkt = vec![0u8; 40];
        // IPv4 header (20 bytes)
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[1] = 0x00; // DSCP/ECN
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes()); // total length
        pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // identification
        pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags (DF)
        pkt[8] = 64; // TTL
        pkt[9] = 6; // protocol: TCP
        // checksum: zero (smoltcp skips Rx checksum verification)
        pkt[12..16].copy_from_slice(&[10, 210, 0, 12]); // src: 10.210.0.12 (client TUN)
        pkt[16..20].copy_from_slice(&[10, 220, 0, 99]); // dst: 10.220.0.99 (target)
        // TCP header (20 bytes)
        pkt[20..22].copy_from_slice(&44615u16.to_be_bytes()); // src port
        pkt[22..24].copy_from_slice(&18080u16.to_be_bytes()); // dst port
        pkt[24..28].copy_from_slice(&0x01020304u32.to_be_bytes()); // seq num
        pkt[28..32].copy_from_slice(&0u32.to_be_bytes()); // ack num (0 for SYN)
        pkt[32] = 0x50; // data offset 5 (20 bytes), reserved
        pkt[33] = 0x02; // flags: SYN set, ACK clear
        pkt[34..36].copy_from_slice(&64240u16.to_be_bytes()); // window
        // checksum and urgent pointer: zero
        bytes::Bytes::from(pkt)
    }

    fn test_data_frame(payload: bytes::Bytes) -> SessionFrame {
        SessionFrame {
            header: SessionHeader {
                connection_id: 0,
                sequence: 1,
                flags: 0, // not a PING: data frame
            },
            payload,
        }
    }

    /// Strengthened regression test: PROVES a data frame reaching the server's
    /// session loop is delivered to SmoltcpForwarder::ingest_packet.
    ///
    /// Requires the observability hook (AtomicU64 ingested_packets counter)
    /// from /tmp/observability_hook.diff.
    ///
    /// Splice location: inside `mod tests` in crates/bonded-server/src/bootstrap.rs,
    /// after the existing `transport_session_delivers_data_frame_to_forwarder` test
    /// (which only asserts the handler doesn't crash).
    #[tokio::test]
    async fn transport_session_delivers_syn_to_forwarder() {
        let ctx = test_ctx();
        let sessions = SessionRegistry::default();
        let forwarders: ForwarderRegistry =
            Arc::new(RwLock::new(std::collections::HashMap::new()));

        let (mock, inbound_tx, mut outbound_rx) = MockTransport::new();
        let peer: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let public_key = "test-public-key".to_owned();

        let sessions_clone = sessions.clone();
        let forwarders_clone = forwarders.clone();
        let handle = tokio::spawn(async move {
            handle_transport_session(
                mock, peer, ctx.as_ref(), public_key, sessions_clone, forwarders_clone, None,
            )
            .await
        });

        // 1. Send PING as the first frame (goes through resolve_session_binding
        //    -> initial_frame -> pending_frame -> PONG with connection_id = session_id).
        inbound_tx
            .send(test_session_frame(FLAG_PING, 0))
            .expect("send ping");

        // 2. Wait for PONG. The PONG's connection_id IS the session_id
        //    (see pending_frame handling in handle_transport_session).
        let pong = tokio::time::timeout(std::time::Duration::from_secs(2), outbound_rx.recv())
            .await
            .expect("timeout waiting for PONG")
            .expect("outbound closed");
        assert!(
            pong.header.flags & bonded_core::session::FLAG_PONG != 0,
            "expected PONG, got flags={}",
            pong.header.flags
        );
        let session_id = pong.header.connection_id as u64;

        // 3. Look up the forwarder from the registry using the session_id.
        //    This proves the session was registered and the forwarder exists.
        let forwarder: Arc<crate::smoltcp_forwarder::SmoltcpForwarder> = {
            let guard = forwarders
                .read()
                .expect("forwarder registry lock should not be poisoned");
            guard
                .get(&session_id)
                .expect("forwarder should be registered for session")
                .forwarder
                .clone()
        };

        // 4. Record baseline counter.
        let baseline = forwarder.ingested_packet_count();

        // 5. Send a well-formed TCP SYN data frame.
        //    If the select! loop starves transport.recv(), this frame will
        //    never reach ingest_packet and the timeout below will fire.
        inbound_tx
            .send(test_data_frame(build_tcp_syn_packet()))
            .expect("send SYN frame");

        // 6. Wait (with timeout) for the forwarder to observe the packet.
        //    This is the PROOF: the counter increments if and only if
        //    handle_transport_session called forwarder.ingest_packet(frame).
        let observed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if forwarder.ingested_packet_count() > baseline {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            observed.is_ok(),
            "forwarder did not ingest the SYN frame within 5s; \
             the session loop is not delivering data frames to the forwarding layer"
        );

        // 7. Verify exactly one packet was ingested (no duplicates, no drops).
        assert_eq!(
            forwarder.ingested_packet_count(),
            baseline + 1,
            "expected exactly one ingested packet"
        );

        // 8. Cleanup: close the mock, handler should exit.
        drop(inbound_tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }
}
