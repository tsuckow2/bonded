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
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use bonded_core::auth::verify_signature;
use bonded_core::auth::{sign_bytes, DeviceKeypair};
use bonded_core::peer_share::{
    PeerShareIntroductionClaims, PeerShareIntroductionRequest, SignedPeerShareIntroduction,
};
use bonded_core::session::{SessionFrame, SessionHeader, FLAG_PING, FLAG_PONG};
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
    let session_ctx: Arc<SessionContext> = {
        let mut guard = forwarders
            .write()
            .expect("forwarder registry lock should not be poisoned");
        if let Some(existing) = guard.get(&handle.session_id) {
            existing.clone()
        } else {
            let (router, fwd_tx) = SessionOutboundRouter::new();
            let forwarder = Arc::new(SmoltcpForwarder::new(
                handle.session_id,
                fwd_tx,
                Arc::new(AtomicU64::new(0)),
            ));
            let ctx = Arc::new(SessionContext { forwarder, router });
            guard.insert(handle.session_id, ctx.clone());
            ctx
        }
    };
    session_ctx.router.add_transport(transport_id, forward_tx);
    let forwarder: Arc<SmoltcpForwarder> = session_ctx.forwarder.clone();

    let mut pending_frame = binding.initial_frame;
    loop {
        // Drain queued response frames before blocking in select! to avoid
        // serialising bursty traffic to one frame per scheduler turn.
        for _ in 0..MAX_DRAIN {
            let frame = match forward_rx.try_recv() {
                Ok(f) => f,
                Err(_) => break,
            };
            log_tunnel_packet(&tunnel_pcap, &frame.payload);
            if let Err(err) = transport.send(frame).await {
                warn!(peer = %peer, session_id = handle.session_id, error = %err,
                    "failed to return drained websocket frame");
                break;
            }
        }

        if let Some(frame) = pending_frame.take() {
            log_tunnel_packet(&tunnel_pcap, &frame.payload);
            if frame.header.flags & FLAG_PING != 0 && frame.payload.is_empty() {
                let pong = SessionFrame {
                    header: SessionHeader {
                        connection_id: handle.session_id as u32,
                        sequence: frame.header.sequence,
                        flags: FLAG_PONG,
                    },
                    payload: frame.payload,
                };
                if let Err(err) = transport.send(pong).await {
                    warn!(peer = %peer, session_id = handle.session_id, error = %err,
                        "failed to send initial heartbeat pong");
                    break;
                }
            } else {
                session_ctx.router.mark_active(transport_id);
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
                if let Err(err) = transport.send(frame).await {
                    warn!(peer = %peer, session_id = handle.session_id, error = %err,
                        "failed to send websocket frame");
                    break;
                }
            }
            recv_result = transport.recv() => {
                match recv_result {
                    Ok(frame) => {
                        log_tunnel_packet(&tunnel_pcap, &frame.payload);
                        if frame.header.flags & FLAG_PING != 0 && frame.payload.is_empty() {
                            let pong = SessionFrame {
                                header: SessionHeader {
                                    connection_id: frame.header.connection_id,
                                    sequence: frame.header.sequence,
                                    flags: FLAG_PONG,
                                },
                                payload: frame.payload,
                            };
                            if let Err(err) = transport.send(pong).await {
                                warn!(peer = %peer, session_id = handle.session_id, error = %err,
                                    "failed to send heartbeat pong");
                                break;
                            }
                            continue;
                        }
                        session_ctx.router.mark_active(transport_id);
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
    if session_ctx.router.transport_count() == 0 {
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
}
