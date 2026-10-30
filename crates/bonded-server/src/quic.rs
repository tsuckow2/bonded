//! QUIC (HTTP/3) server endpoint.
//!
//! Runs a `quinn::Endpoint` bound to the same address as the WebSocket TLS
//! server (or a configurable separate address) and accepts inbound QUIC
//! connections.  For each connection it accepts the first bidirectional stream
//! and treats it as a [`QuicTransport`] session, running the same auth
//! handshake as the WebSocket path.
//!
//! ## TLS sharing
//!
//! The QUIC endpoint reuses the same TLS certificate and private key as the
//! bootstrap WebSocket listener so clients can use the same pinned fingerprint
//! for both WSS and QUIC connections.
//!
//! ## Design constraints
//! - QUIC runs over UDP; sockets must be "protected" on Android before use.
//! - Only one bidirectional stream per connection is accepted; multiplexing is
//!   a Phase 7 concern.
//! - Authentication uses the same challenge-response handshake as WSS.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};

use anyhow::Context as _;
use bonded_core::session::{
    decode_observed_address, encode_observed_address, parse_session_epoch, SessionFrame,
    SessionHeader, FLAG_PATH_RETIRE, FLAG_PING, FLAG_PONG,
};
use bonded_core::transport::{QuicTransport, Transport as _};
use bytes::{Buf, Bytes};
use h3::server;
use quinn::{Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::auth_handshake::perform_quic_auth_handshake;
use crate::authorized_keys::AuthorizedKeysStore;
use crate::bootstrap::{
    advertised_endpoints_for_request, route_bootstrap_request, BootstrapContext,
};
use crate::peer_relay::resolve_session_binding;
use crate::session_registry::SessionRegistry;
use crate::smoltcp_forwarder::{SessionContext, SessionOutboundRouter, SmoltcpForwarder};

/// Maximum frames to drain from the forwarder response queue per scheduler turn.
const MAX_DRAIN: usize = 256;
const RAW_QUIC_ALPN: &[u8] = b"bonded-quic";
const H3_ALPN: &[u8] = b"h3";

type ForwarderRegistry = Arc<RwLock<HashMap<u64, Arc<SessionContext>>>>;

/// Build a QUIC `ServerConfig` from DER-encoded certificate and private key
/// bytes (both in DER / PKCS#8 format).  Called by `main.rs` when it has
/// already loaded a TLS cert for the bootstrap server.
pub fn build_quic_server_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> anyhow::Result<ServerConfig> {
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::try_from(key_der)
        .map_err(|e| anyhow::anyhow!("invalid QUIC private key DER: {e}"))?;

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("failed to build QUIC TLS config")?;
    let mut tls_config = tls_config;
    tls_config.alpn_protocols = vec![RAW_QUIC_ALPN.to_vec(), H3_ALPN.to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .context("failed to build QUIC server crypto config")?,
    ));

    // Allow some concurrent bidirectional streams per connection.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4u32.into());
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

/// Start the QUIC endpoint and accept sessions until the endpoint is closed.
pub async fn run_quic_server(
    bind: &str,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    invite_tokens_file: String,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    bootstrap_ctx: Arc<BootstrapContext>,
) -> anyhow::Result<()> {
    let server_config = build_quic_server_config(cert_der, key_der)?;

    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid QUIC bind address: {bind}"))?;

    let endpoint = Endpoint::server(server_config, addr)
        .with_context(|| format!("failed to bind QUIC endpoint on {bind}"))?;

    info!(bind = %bind, "QUIC endpoint bound");

    loop {
        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => {
                info!("QUIC endpoint closed");
                break;
            }
        };

        let invite_tokens_file = invite_tokens_file.clone();
        let authorized_keys = authorized_keys.clone();
        let sessions = sessions.clone();
        let forwarders = forwarders.clone();
        let bootstrap_ctx = bootstrap_ctx.clone();

        tokio::spawn(async move {
            let remote = incoming.remote_address();
            match incoming.await {
                Err(err) => {
                    warn!(peer = %remote, error = ?err, "QUIC handshake failed");
                }
                Ok(connection) => {
                    let protocol = negotiated_alpn(&connection);
                    let result = if protocol.as_deref() == Some(H3_ALPN) {
                        handle_h3_connection(connection, bootstrap_ctx).await
                    } else {
                        handle_quic_connection(
                            connection,
                            &invite_tokens_file,
                            authorized_keys,
                            sessions,
                            forwarders,
                            bootstrap_ctx,
                        )
                        .await
                    };
                    if let Err(err) = result {
                        warn!(peer = %remote, error = ?err, "QUIC session error");
                    }
                }
            }
        });
    }

    Ok(())
}

fn negotiated_alpn(connection: &quinn::Connection) -> Option<Vec<u8>> {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol)
}

async fn handle_h3_connection(
    connection: quinn::Connection,
    bootstrap_ctx: Arc<BootstrapContext>,
) -> anyhow::Result<()> {
    let peer = connection.remote_address();
    info!(peer = %peer, "HTTP/3 bootstrap connection established");

    let mut h3_conn = server::builder()
        .build(h3_quinn::Connection::new(connection))
        .await
        .context("failed to build HTTP/3 server connection")?;

    loop {
        let Some(resolver) = h3_conn.accept().await.context("HTTP/3 accept failed")? else {
            break;
        };
        let (request, mut stream) = resolver
            .resolve_request()
            .await
            .context("failed to resolve HTTP/3 request")?;
        let path = request
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or_else(|| request.uri().path());
        let advertised_endpoints = advertised_endpoints_for_request(
            bootstrap_ctx.as_ref(),
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str()),
        );

        let mut body = Vec::new();
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .context("failed to read HTTP/3 request body")?
        {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        let body = std::str::from_utf8(&body).unwrap_or("");
        let (status, response_body) = route_bootstrap_request(
            request.method().as_str(),
            path,
            body,
            bootstrap_ctx.as_ref(),
            Some(&advertised_endpoints),
        );

        let response = http::Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(())
            .expect("HTTP/3 bootstrap response should build");
        stream
            .send_response(response)
            .await
            .context("failed to send HTTP/3 response headers")?;
        stream
            .send_data(Bytes::from(response_body))
            .await
            .context("failed to send HTTP/3 response body")?;
        stream
            .finish()
            .await
            .context("failed to finish HTTP/3 response")?;
    }

    Ok(())
}

async fn handle_quic_connection(
    connection: quinn::Connection,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    bootstrap_ctx: Arc<BootstrapContext>,
) -> anyhow::Result<()> {
    let peer = connection.remote_address();
    info!(peer = %peer, "QUIC connection established");

    let mut transport = QuicTransport::from_server_connection(connection).await?;

    let public_key =
        match perform_quic_auth_handshake(&mut transport, invite_tokens_file, &authorized_keys)
            .await
        {
            Ok(pk) => pk,
            Err(err) => {
                warn!(peer = %peer, error = %err, "QUIC client authentication failed");
                return Ok(());
            }
        };

    let binding = match resolve_session_binding(
        &mut transport,
        public_key.clone(),
        bootstrap_ctx.server_identity.as_ref(),
    )
    .await
    {
        Ok(binding) => binding,
        Err(err) => {
            warn!(peer = %peer, public_key = %public_key, error = %err, "failed to bind QUIC session after authentication");
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
        "QUIC client authenticated"
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
    session_ctx.router.note_peer(transport_id, peer);
    let forwarder: Arc<SmoltcpForwarder> = session_ctx.forwarder.clone();

    let mut pending_frame = binding.initial_frame;
    'session: loop {
        // Drain queued response frames before blocking.
        for _ in 0..MAX_DRAIN {
            let frame = match forward_rx.try_recv() {
                Ok(f) => f,
                Err(_) => break,
            };
            if let Err(err) = transport.send(frame.clone()).await {
                warn!(peer = %peer, session_id = handle.session_id, error = %err,
                    "QUIC: failed to send drained response frame; requeueing on a live transport");
                session_ctx.router.remove_transport(transport_id);
                session_ctx.router.requeue(frame);
                break 'session;
            }
        }

        if let Some(frame) = pending_frame.take() {
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
                    // Observed-address stamp: the client shows this as
                    // the path's public (egress) address. Older clients
                    // ignore PONG payloads: backward compatible.
                    payload: encode_observed_address(peer),
                };
                if let Err(err) = transport.send(pong).await {
                    warn!(peer = %peer, session_id = handle.session_id,
                        error = %err, "QUIC: failed to send initial heartbeat pong");
                    break 'session;
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
                        "QUIC: forwarder response queue closed");
                    break;
                };
                if let Err(err) = transport.send(frame.clone()).await {
                    warn!(peer = %peer, session_id = handle.session_id, error = %err,
                        "QUIC: failed to send response frame; requeueing on a live transport");
                    session_ctx.router.remove_transport(transport_id);
                    session_ctx.router.requeue(frame);
                    break;
                }
            }
            recv_result = transport.recv() => {
                match recv_result {
                    Ok(frame) => {
                        if frame.header.flags & FLAG_PATH_RETIRE != 0 {
                            // A live session retiring one dead path:
                            // drop every transport whose peer matches
                            // the stamped address, so no flow hashes
                            // to it while its handler idles out. No
                            // PONG: QUIC delivery is reliable.
                            match decode_observed_address(&frame.payload) {
                                Some(dead_peer) => {
                                    let retired =
                                        session_ctx.router.retire_by_peer(dead_peer);
                                    info!(peer = %peer, session_id = handle.session_id,
                                        dead_peer = %dead_peer, retired = ?retired,
                                        "retired transports for dead path at client request");
                                }
                                None => {
                                    warn!(peer = %peer, session_id = handle.session_id,
                                        "path-retire frame with undecodable payload");
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
                                    connection_id: frame.header.connection_id,
                                    sequence: frame.header.sequence,
                                    flags: FLAG_PONG,
                                },
                                // Observed-address stamp: see above.
                                payload: encode_observed_address(peer),
                            };
                            if let Err(err) = transport.send(pong).await {
                                warn!(peer = %peer, session_id = handle.session_id,
                                    error = %err, "QUIC: failed to send heartbeat pong");
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
                            "QUIC client session ended");
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

