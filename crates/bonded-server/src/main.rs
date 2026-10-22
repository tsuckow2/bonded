use std::collections::HashMap;
use std::path::PathBuf;

mod acme;
mod auth_handshake;
mod authorized_keys;
mod bootstrap;
mod health;
mod invite_tokens;
mod network_runtime;
mod pairing_qr;
mod peer_relay;
mod quic;
mod session_registry;
mod smoltcp_forwarder;
mod status;
mod tun_bridge;
mod tunnel_pcap;
mod wireguard;

#[cfg(test)]
mod server_integration;

#[cfg(test)]
mod channel_tests {
    #[tokio::test]
    async fn test_channel_batch_drain_completes_before_blocking() {
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::unbounded_channel::<u32>();

        for i in 0..256u32 {
            tx.send(i).ok();
        }

        let mut drained = 0usize;
        loop {
            match rx.try_recv() {
                Ok(_) => drained += 1,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        assert_eq!(drained, 256, "all 256 items must drain before blocking");
    }
}

use auth_handshake::perform_auth_handshake;
use authorized_keys::{AuthorizedKeysStore, AuthorizedKeysWatcher};

use anyhow::Context as _;
use bonded_core::config::{load_server_config, ServerConfig, DEFAULT_SERVER_CONFIG_PATH};
use bonded_core::session::{SessionFrame, SessionHeader, FLAG_PING, FLAG_PONG};
use bonded_core::transport::{NaiveTcpTransport, Transport};
use clap::Parser;
use health::run_health_server;
use invite_tokens::ensure_startup_invite;
use network_runtime::NetworkRuntime;
use pairing_qr::emit_pairing_qr;
use peer_relay::resolve_session_binding;
use rcgen;
use session_registry::SessionRegistry;
use smoltcp_forwarder::{SessionContext, SmoltcpForwarder};
use status::run_status_server;
use std::io::BufReader;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn, Level};
use tun_bridge::TunBridge;
use tunnel_pcap::TunnelPcapLogger;

type ForwarderRegistry = Arc<RwLock<HashMap<u64, Arc<SessionContext>>>>;

const MAX_RESPONSE_DRAIN_PER_CYCLE: usize = 256;
const TUNNEL_PCAP_MAX_MB_ENV: &str = "BONDED_TUNNEL_PCAP_MAX_MB";

#[derive(Debug, Parser)]
#[command(name = "bonded-server")]
struct Args {
    #[arg(long, env = "BONDED_CONFIG", default_value = DEFAULT_SERVER_CONFIG_PATH)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // ignore error if already installed

    let args = Args::parse();

    let mut cfg = match load_server_config(&args.config) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!(
                "failed to load server config at {} ({err}); using defaults",
                args.config.display()
            );
            ServerConfig::default()
        }
    };

    apply_env_overrides(&mut cfg, |key| std::env::var(key).ok());
    init_tracing_from_level(&cfg.server.log_level);
    let tunnel_pcap = TunnelPcapLogger::from_env(TUNNEL_PCAP_MAX_MB_ENV)?;
    ensure_server_state_files(&cfg)?;
    let mut network_runtime = match NetworkRuntime::setup(&cfg.server) {
        Ok(runtime) => runtime,
        Err(err) => {
            error!(
                forwarding_mode = %cfg.server.forwarding_mode,
                tun_name = %cfg.server.tun_name,
                tun_cidr = %cfg.server.tun_cidr,
                tun_mtu = cfg.server.tun_mtu,
                tun_egress_interface = %cfg.server.tun_egress_interface,
                error = %err,
                "failed to initialize network runtime"
            );
            return Err(err);
        }
    };
    let tun_bridge = if network_runtime.is_tun_mode() {
        let device = network_runtime.take_tun_device().ok_or_else(|| {
            anyhow::anyhow!("forwarding_mode=tun active but no TUN device was created")
        })?;
        info!(
            tun_name = %cfg.server.tun_name,
            tun_cidr = %cfg.server.tun_cidr,
            tun_mtu = cfg.server.tun_mtu,
            "TUN forwarding mode enabled"
        );
        Some(TunBridge::new(device))
    } else {
        None
    };

    let authorized_keys = AuthorizedKeysStore::load(&cfg.server.authorized_keys_file)?;
    info!(
        path = %cfg.server.authorized_keys_file,
        devices = authorized_keys.device_count(),
        "authorized keys loaded"
    );
    let _authorized_keys_watcher = AuthorizedKeysWatcher::spawn(authorized_keys.clone())?;
    let invite = ensure_startup_invite(&cfg.server.invite_tokens_file)?;
    info!(
        path = %cfg.server.invite_tokens_file,
        token = %invite.token,
        "startup invite token ready"
    );
    let server_identity = Arc::new(bonded_core::auth::load_or_create_keypair(Path::new(
        &cfg.server.identity_key_file,
    ))?);
    let _ = emit_pairing_qr(
        &cfg.server.https_public_addr(),
        &invite,
        &server_identity.public_key_b64,
    );

    let health_bind = cfg.server.health_bind.clone();
    tokio::spawn(async move {
        if let Err(err) = run_health_server(&health_bind).await {
            error!(bind = %health_bind, error = %err, "health listener terminated");
        }
    });

    let sessions = SessionRegistry::default();
    let forwarders: ForwarderRegistry = Arc::new(RwLock::new(HashMap::new()));

    let status_bind = cfg.server.status_bind.clone();
    let status_sessions = sessions.clone();
    let status_forwarders = forwarders.clone();
    tokio::spawn(async move {
        if let Err(err) = run_status_server(&status_bind, status_sessions, status_forwarders).await
        {
            error!(bind = %status_bind, error = %err, "status listener terminated");
        }
    });

    info!(bind = %cfg.server.https_bind, "bonded-server starting");
    let https_bind = cfg.server.https_bind.clone();
    let acme_slot = acme::AcmeChallengeSlot::new();
    let websocket_invites = cfg.server.invite_tokens_file.clone();
    let websocket_sessions = sessions.clone();
    let websocket_forwarders = forwarders.clone();
    let websocket_keys = authorized_keys.clone();
    let websocket_tunnel_pcap = tunnel_pcap.clone();
    let (initial_tls_acceptor, tls_cert_der, tls_key_der) = load_tls_acceptor(
        &cfg.server.tls_cert_file,
        &cfg.server.tls_key_file,
        &cfg.server.hostname,
        acme_slot.clone(),
    )?;
    // Shared slot so the ACME renewal callback can hot-swap the acceptor without
    // restarting the bootstrap listener.  Each accepted connection reads the
    // current acceptor from the slot at accept time.
    let tls_slot: Arc<RwLock<Option<TlsAcceptor>>> = Arc::new(RwLock::new(initial_tls_acceptor));
    let quic_cert_der = tls_cert_der.clone();
    let quic_key_der = tls_key_der.clone();

    // WireGuard server keypair and peer registry.  Enabled when wireguard_bind is set.
    let (wg_keypair, wg_peer_registry) = if cfg.server.wireguard_bind.is_some() {
        let key_path = cfg
            .server
            .wireguard_key_file
            .as_deref()
            .unwrap_or("bonded-server-wg.key");
        let kp = wireguard::load_or_generate_wg_keypair(key_path)?;
        let peers_path = cfg
            .server
            .wireguard_peers_file
            .clone()
            .unwrap_or_else(|| bonded_core::config::DEFAULT_WIREGUARD_PEERS_PATH.to_owned());
        let registry = Arc::new(wireguard::WireGuardPeerRegistry::load_with_lease(
            &peers_path,
            std::time::Duration::from_secs(cfg.server.wireguard_peer_lease_secs),
        )?);
        (Some(kp), Some(registry))
    } else {
        (None, None)
    };

    // ACME Let's Encrypt certificate automation.  Enabled when acme_domain is set.
    // Writes renewed certs to the same tls_cert_file / tls_key_file paths used by
    // the TLS listener so the reload path is trivial.
    if let Some(domain) = cfg.server.acme_domain.as_deref() {
        let email = cfg
            .server
            .acme_email
            .clone()
            .unwrap_or_else(|| format!("admin@{domain}"));
        let acme_cfg = acme::AcmeConfig {
            domain: domain.to_owned(),
            email,
            tls_cert_file: cfg.server.tls_cert_file.clone(),
            tls_key_file: cfg.server.tls_key_file.clone(),
            staging: cfg.server.acme_staging,
        };
        // Capture everything the reload closure needs before moving acme_slot
        // into spawn_acme_renewal_loop.
        let tls_cert_file_r = cfg.server.tls_cert_file.clone();
        let tls_key_file_r = cfg.server.tls_key_file.clone();
        let hostname_r = cfg.server.hostname.clone();
        let acme_slot_r = acme_slot.clone();
        let tls_slot_r = tls_slot.clone();
        acme::spawn_acme_renewal_loop(acme_cfg, acme_slot, move || {
            match load_tls_acceptor(
                &tls_cert_file_r,
                &tls_key_file_r,
                &hostname_r,
                acme_slot_r.clone(),
            ) {
                Ok((new_acceptor, _, _)) => {
                    *tls_slot_r.write().expect("tls slot lock") = new_acceptor;
                    info!("TLS acceptor reloaded after ACME certificate renewal");
                }
                Err(e) => {
                    error!("Failed to reload TLS acceptor after ACME renewal: {e:#}");
                }
            }
        })
        .await;
    }

    let bootstrap_ctx = Arc::new(bootstrap::BootstrapContext {
        server_identity: server_identity.clone(),
        tls_cert_der: tls_cert_der.map(Arc::new),
        server_public_address: cfg.server.https_public_addr(),
        wireguard_keypair: wg_keypair,
        wireguard_peers: wg_peer_registry,
        wireguard_public_addr: cfg.server.wireguard_public_addr(),
        wireguard_peer_lease_secs: cfg.server.wireguard_peer_lease_secs,
        authorized_keys: authorized_keys.clone(),
        diagnostics_dir: std::path::Path::new(&cfg.server.authorized_keys_file)
            .parent()
            .map(|parent| parent.join("diagnostics"))
            .unwrap_or_else(|| std::path::PathBuf::from("diagnostics")),
    });
    if let (Some(wireguard_bind), Some(wireguard_keypair), Some(wireguard_peers)) = (
        cfg.server.wireguard_bind.clone(),
        bootstrap_ctx.wireguard_keypair.clone(),
        bootstrap_ctx.wireguard_peers.clone(),
    ) {
        let wireguard_sessions = sessions.clone();
        let wireguard_forwarders = forwarders.clone();
        let wireguard_tun_bridge = tun_bridge.clone();
        let wireguard_tunnel_pcap = tunnel_pcap.clone();
        tokio::spawn(async move {
            if let Err(err) = wireguard::run_wireguard_server(
                &wireguard_bind,
                wireguard_keypair,
                wireguard_peers,
                wireguard_sessions,
                wireguard_forwarders,
                wireguard_tun_bridge,
                wireguard_tunnel_pcap,
            )
            .await
            {
                error!(bind = %wireguard_bind, error = %err, "wireguard listener terminated");
            }
        });
    }
    if tun_bridge.is_none() {
        let bootstrap_bind = https_bind.clone();
        let websocket_bootstrap_ctx = bootstrap_ctx.clone();
        tokio::spawn(async move {
            if let Err(err) = bootstrap::run_bootstrap_websocket_server(
                &bootstrap_bind,
                &websocket_invites,
                websocket_keys,
                websocket_sessions,
                websocket_forwarders,
                tls_slot.clone(),
                websocket_tunnel_pcap,
                websocket_bootstrap_ctx,
            )
            .await
            {
                error!(bind = %bootstrap_bind, error = %err, "bootstrap listener terminated");
            }
        });

        // Start the QUIC endpoint on the same bind address as the HTTPS/WSS
        // listener (UDP) whenever TLS is configured — no explicit flag needed.
        if let (Some(cert_der), Some(key_der)) = (quic_cert_der, quic_key_der) {
            let quic_bind = https_bind.clone();
            let quic_invites = cfg.server.invite_tokens_file.clone();
            let quic_keys = authorized_keys.clone();
            let quic_sessions = sessions.clone();
            let quic_forwarders = forwarders.clone();
            let quic_bootstrap_ctx = bootstrap_ctx.clone();
            tokio::spawn(async move {
                if let Err(err) = quic::run_quic_server(
                    &quic_bind,
                    cert_der,
                    key_der,
                    quic_invites,
                    quic_keys,
                    quic_sessions,
                    quic_forwarders,
                    quic_bootstrap_ctx,
                )
                .await
                {
                    error!(bind = %quic_bind, error = %err, "QUIC listener terminated");
                }
            });
        }
    } else {
        warn!("forwarding_mode=tun currently supports naive-tcp transport only; bootstrap listener not started");
    }

    // NaiveTCP debug listener: only started when tcp_bind is configured.
    if let Some(tcp_bind) = cfg.server.tcp_bind.clone() {
        tokio::select! {
            result = run_server(
                &tcp_bind,
                &cfg.server.invite_tokens_file,
                server_identity,
                authorized_keys,
                sessions,
                forwarders,
                tun_bridge,
                tunnel_pcap,
            ) => result,
            signal_result = signal::ctrl_c() => {
                match signal_result {
                    Ok(()) => {
                        info!("shutdown signal received, cleaning up network runtime");
                        Ok(())
                    }
                    Err(err) => Err(err.into()),
                }
            }
        }
    } else {
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("shutdown signal received, cleaning up network runtime");
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }
}

fn ensure_server_state_files(cfg: &ServerConfig) -> anyhow::Result<()> {
    ensure_state_file(
        &cfg.server.authorized_keys_file,
        "devices = []\n",
        "authorized keys",
    )?;
    ensure_state_file(
        &cfg.server.invite_tokens_file,
        "tokens = []\n",
        "invite tokens",
    )?;
    if let Some(path) = cfg.server.wireguard_peers_file.as_deref() {
        ensure_state_file(path, "peers = []\n", "wireguard peers")?;
    }

    Ok(())
}

fn ensure_state_file(path: &str, default_contents: &str, description: &str) -> anyhow::Result<()> {
    let path = Path::new(path);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if !path.exists() {
        std::fs::write(path, default_contents)?;
        info!(
            path = %path.display(),
            file = %description,
            "created missing server state file"
        );
    }

    Ok(())
}

/// Build a TLS acceptor from on-disk PEM cert and key files.
///
/// The acceptor uses a `DynamicCertResolver` that routes connections with
/// ALPN `"acme-tls/1"` to the ACME challenge cert (when one is loaded in
/// `acme_slot`) and all other connections to the main server cert.
///
/// Returns `(None, None, None)` when either path is empty (TLS disabled).
/// If both `cert_file` and `key_file` are configured but neither file exists yet,
/// write a self-signed certificate so the server can start without manual TLS setup.
fn ensure_self_signed_cert(cert_file: &str, key_file: &str, hostname: &str) -> anyhow::Result<()> {
    if Path::new(cert_file).exists() && Path::new(key_file).exists() {
        return Ok(());
    }
    info!("TLS files not found — generating self-signed certificate");
    let san = if hostname.is_empty() {
        "localhost"
    } else {
        hostname
    };
    let key_pair = rcgen::KeyPair::generate().context("self-signed: generate key pair")?;
    let params = rcgen::CertificateParams::new(vec![san.to_string()])
        .context("self-signed: build params")?;
    let cert = params
        .self_signed(&key_pair)
        .context("self-signed: sign certificate")?;
    for path in [cert_file, key_file] {
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create dirs for {path}"))?;
            }
        }
    }
    std::fs::write(cert_file, cert.pem())
        .with_context(|| format!("write self-signed cert to {cert_file}"))?;
    std::fs::write(key_file, key_pair.serialize_pem())
        .with_context(|| format!("write self-signed key to {key_file}"))?;
    info!("Self-signed certificate written to {cert_file} and {key_file}");
    Ok(())
}

fn load_tls_acceptor(
    cert_file: &str,
    key_file: &str,
    hostname: &str,
    acme_slot: acme::AcmeChallengeSlot,
) -> anyhow::Result<(Option<TlsAcceptor>, Option<Vec<u8>>, Option<Vec<u8>>)> {
    if cert_file.trim().is_empty() || key_file.trim().is_empty() {
        return Ok((None, None, None));
    }
    ensure_self_signed_cert(cert_file, key_file, hostname)?;

    let cert_reader = std::fs::File::open(cert_file)?;
    let mut cert_reader = BufReader::new(cert_reader);
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    if cert_chain.is_empty() {
        anyhow::bail!("no certificates found in tls cert file");
    }

    // Capture the DER bytes of the leaf certificate so the bootstrap server can
    // sign a cert-proof for clients that connect with TLS verify disabled.
    let leaf_der: Vec<u8> = cert_chain[0].to_vec();

    let key = load_private_key(key_file)?;

    // Capture raw key DER bytes for the QUIC endpoint (needs its own TLS config).
    let key_der: Vec<u8> = key.secret_der().to_vec();

    // Build a CertifiedKey for the DynamicCertResolver.
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .context("failed to load TLS signing key")?;
    let main_cert = Arc::new(rustls::sign::CertifiedKey::new(cert_chain, signing_key));

    let resolver = Arc::new(acme::DynamicCertResolver {
        main_cert,
        acme_slot,
    });
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    // Advertise "acme-tls/1" so rustls selects it during the TLS-ALPN-01
    // handshake.  RFC 8737 §4.2 requires the server's ServerHello to include
    // the selected "acme-tls/1" protocol; if it's absent Let's Encrypt marks
    // the challenge as failed.
    //
    // IMPORTANT: when alpn_protocols is non-empty rustls enforces strict
    // negotiation — any client that offers an ALPN list containing none of
    // these values gets a fatal "no_application_protocol" alert (TLS alert
    // 120).  The server only implements HTTP/1.1 framing, so we must NOT
    // advertise "h2": a client that negotiates HTTP/2 via ALPN will immediately
    // send a SETTINGS frame and fail when it receives an HTTP/1.1 response.
    // Browsers/curl fall back to HTTP/1.1 cleanly when it is the only option.
    config.alpn_protocols = vec![b"acme-tls/1".to_vec(), b"http/1.1".to_vec()];

    Ok((
        Some(TlsAcceptor::from(Arc::new(config))),
        Some(leaf_der),
        Some(key_der),
    ))
}

fn load_private_key(path: &str) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let pkcs8_file = std::fs::File::open(path)?;
    let mut pkcs8_reader = BufReader::new(pkcs8_file);
    let mut pkcs8_keys: Vec<rustls::pki_types::PrivatePkcs8KeyDer<'static>> =
        rustls_pemfile::pkcs8_private_keys(&mut pkcs8_reader).collect::<Result<Vec<_>, _>>()?;
    if let Some(key) = pkcs8_keys.pop() {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
    }

    let rsa_file = std::fs::File::open(path)?;
    let mut rsa_reader = BufReader::new(rsa_file);
    let mut rsa_keys: Vec<rustls::pki_types::PrivatePkcs1KeyDer<'static>> =
        rustls_pemfile::rsa_private_keys(&mut rsa_reader).collect::<Result<Vec<_>, _>>()?;
    if let Some(key) = rsa_keys.pop() {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key));
    }

    anyhow::bail!("no supported private key found in tls key file");
}

async fn run_server(
    bind: &str,
    invite_tokens_file: &str,
    server_identity: Arc<bonded_core::auth::DeviceKeypair>,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tun_bridge: Option<TunBridge>,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(bind = %bind, "naive tcp listener bound");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => {
                error!(error = %err, "failed to accept incoming connection");
                continue;
            }
        };

        let authorized_keys = authorized_keys.clone();
        let sessions = sessions.clone();
        let forwarders = forwarders.clone();
        let tun_bridge = tun_bridge.clone();
        let tunnel_pcap = tunnel_pcap.clone();
        let server_identity = server_identity.clone();
        let invite_tokens_file = invite_tokens_file.to_owned();
        tokio::spawn(async move {
            match perform_auth_handshake(
                stream,
                authorized_keys,
                std::path::Path::new(&invite_tokens_file),
            )
            .await
            {
                Ok((public_key, stream)) => {
                    let mut transport = NaiveTcpTransport::from_stream(stream);
                    let binding = match resolve_session_binding(
                        &mut transport,
                        public_key.clone(),
                        server_identity.as_ref(),
                    )
                    .await
                    {
                        Ok(binding) => binding,
                        Err(err) => {
                            warn!(peer = %peer, public_key = %public_key, error = %err, "failed to bind session after authentication");
                            return;
                        }
                    };

                    let handle = sessions.register_client(binding.client_public_key.clone());
                    info!(
                        peer = %peer,
                        public_key = %binding.client_public_key,
                        authenticated_public_key = %public_key,
                        relayed_via_provider = binding.relayed_via_provider,
                        session_id = handle.session_id,
                        active_sessions = sessions.active_sessions(),
                        "client authenticated"
                    );
                    info!(
                        peer = %peer,
                        session_id = handle.session_id,
                        "starting frame receive loop"
                    );
                    let use_tun_bridge = tun_bridge.is_some();
                    let (forward_tx, mut forward_rx) = mpsc::unbounded_channel();
                    let transport_id = smoltcp_forwarder::alloc_transport_id();
                    // Exactly one forwarding context per session, shared by every
                    // path: the flow state and outbound sequence space must survive
                    // the death of any single path for failover to work.
                    let session_ctx: Option<Arc<SessionContext>> = if use_tun_bridge {
                        None
                    } else {
                        let ctx = {
                            let mut guard = forwarders
                                .write()
                                .expect("forwarder registry lock should not be poisoned");
                            if let Some(existing) = guard.get(&handle.session_id) {
                                existing.clone()
                            } else {
                                let (router, fwd_tx) =
                                    smoltcp_forwarder::SessionOutboundRouter::new();
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
                        ctx.router.add_transport(transport_id, forward_tx);
                        Some(ctx)
                    };
                    let forwarder: Option<Arc<SmoltcpForwarder>> =
                        session_ctx.as_ref().map(|ctx| ctx.forwarder.clone());

                    let (tun_tx, mut tun_rx) = mpsc::unbounded_channel::<SessionFrame>();
                    if let Some(bridge) = &tun_bridge {
                        bridge.register_session(handle.session_id, tun_tx).await;
                    }
                    let mut pending_frame = binding.initial_frame;
                    loop {
                        // Drain queued response frames before blocking in select! so bursty
                        // server->client traffic is not throttled by select scheduling.
                        for _ in 0..MAX_RESPONSE_DRAIN_PER_CYCLE {
                            let maybe_tun_frame = match tun_rx.try_recv() {
                                Ok(frame) => Some(frame),
                                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
                                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                    break;
                                }
                            };

                            let Some(tun_frame) = maybe_tun_frame else {
                                break;
                            };

                            maybe_log_tunnel_packet(&tunnel_pcap, &tun_frame.payload);
                            if let Err(err) = transport.send(tun_frame).await {
                                warn!(
                                    peer = %peer,
                                    public_key = %public_key,
                                    session_id = handle.session_id,
                                    error = %err,
                                    "failed to send drained TUN return packet to client"
                                );
                                break;
                            }
                        }

                        if !use_tun_bridge {
                            for _ in 0..MAX_RESPONSE_DRAIN_PER_CYCLE {
                                let maybe_forwarded_frame = match forward_rx.try_recv() {
                                    Ok(frame) => Some(frame),
                                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
                                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                        break;
                                    }
                                };

                                let Some(forwarded_frame) = maybe_forwarded_frame else {
                                    break;
                                };

                                maybe_log_tunnel_packet(&tunnel_pcap, &forwarded_frame.payload);
                                if let Err(err) = transport.send(forwarded_frame).await {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        error = %err,
                                        "failed to return drained forwarded frame"
                                    );
                                    break;
                                }
                            }
                        }

                        if let Some(frame) = pending_frame.take() {
                            maybe_log_tunnel_packet(&tunnel_pcap, &frame.payload);
                            if frame.header.flags & FLAG_PING != 0 && frame.payload.is_empty() {
                                if let Some(ctx) = &session_ctx {
                                    ctx.router.note_frame_flags(frame.header.flags);
                                }
                                info!(
                                    peer = %peer,
                                    session_id = handle.session_id,
                                    sequence = frame.header.sequence,
                                    "initial heartbeat ping received, sending pong"
                                );
                                let pong = SessionFrame {
                                    header: SessionHeader {
                                        connection_id: handle.session_id as u32,
                                        sequence: frame.header.sequence,
                                        flags: FLAG_PONG,
                                    },
                                    payload: frame.payload,
                                };
                                if let Err(err) = transport.send(pong).await {
                                    warn!(
                                        peer = %peer,
                                        session_id = handle.session_id,
                                        error = %err,
                                        "failed to send initial heartbeat pong"
                                    );
                                    break;
                                }
                            } else {
                                if frame.header.flags & FLAG_PING != 0 {
                                    warn!(
                                        peer = %peer,
                                        session_id = handle.session_id,
                                        sequence = frame.header.sequence,
                                        flags = frame.header.flags,
                                        payload_len = frame.payload.len(),
                                        "initial frame has ping flag with payload; forwarding as data"
                                    );
                                }
                                if let Some(bridge) = &tun_bridge {
                                    if let Err(err) =
                                        bridge.submit_client_frame(handle.session_id, frame)
                                    {
                                        warn!(peer = %peer, public_key = %binding.client_public_key, session_id = handle.session_id, error = %err, "failed to enqueue initial frame into TUN bridge");
                                        break;
                                    }
                                } else if let Some(f) = &forwarder {
                                    if let Some(ctx) = &session_ctx {
                                        ctx.router
                                            .note_frame(transport_id, frame.header.flags);
                                    }
                                    f.ingest_packet(frame);
                                }
                            }
                            continue;
                        }

                        tokio::select! {
                            maybe_tun_frame = tun_rx.recv() => {
                                let Some(tun_frame) = maybe_tun_frame else {
                                    break;
                                };

                                maybe_log_tunnel_packet(&tunnel_pcap, &tun_frame.payload);
                                if let Err(err) = transport.send(tun_frame).await {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        error = %err,
                                        "failed to send TUN return packet to client"
                                    );
                                    break;
                                }
                            }
                            maybe_forwarded_frame = forward_rx.recv() => {
                                if use_tun_bridge {
                                    continue;
                                }
                                let Some(forwarded_frame) = maybe_forwarded_frame else {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        "forward response queue closed"
                                    );
                                    break;
                                };

                                maybe_log_tunnel_packet(&tunnel_pcap, &forwarded_frame.payload);
                                if let Err(err) = transport.send(forwarded_frame).await {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        error = %err,
                                        "failed to return forwarded frame"
                                    );
                                    break;
                                }
                            }
                            recv_result = transport.recv() => {
                                match recv_result {
                                    Ok(frame) => {
                                        info!(
                                            peer = %peer,
                                            session_id = handle.session_id,
                                            flags = frame.header.flags,
                                            seq = frame.header.sequence,
                                            payload_len = frame.payload.len(),
                                            "FRAME RECEIVED"
                                        );
                                        maybe_log_tunnel_packet(&tunnel_pcap, &frame.payload);
                                        // Respond to heartbeat pings without forwarding them.
                                        // Only treat ping-bit frames as control heartbeats when
                                        // they carry no payload; otherwise keep forwarding.
                                        if frame.header.flags & FLAG_PING != 0 && frame.payload.is_empty() {
                                            if let Some(ctx) = &session_ctx {
                                                ctx.router
                                                    .note_frame_flags(frame.header.flags);
                                            }
                                            info!(
                                                peer = %peer,
                                                session_id = handle.session_id,
                                                sequence = frame.header.sequence,
                                                "heartbeat ping received, sending pong"
                                            );
                                            let pong = SessionFrame {
                                                header: SessionHeader {
                                                    connection_id: frame.header.connection_id,
                                                    sequence: frame.header.sequence,
                                                    flags: FLAG_PONG,
                                                },
                                                payload: frame.payload,
                                            };
                                            if let Err(err) = transport.send(pong).await {
                                                warn!(
                                                    peer = %peer,
                                                    session_id = handle.session_id,
                                                    error = %err,
                                                    "failed to send heartbeat pong"
                                                );
                                                break;
                                            }
                                            continue;
                                        }

                                        if frame.header.flags & FLAG_PING != 0 {
                                            warn!(
                                                peer = %peer,
                                                session_id = handle.session_id,
                                                sequence = frame.header.sequence,
                                                flags = frame.header.flags,
                                                payload_len = frame.payload.len(),
                                                "frame has ping flag with payload; forwarding as data"
                                            );
                                        }

                                        if let Some(bridge) = &tun_bridge {
                                            if let Err(err) = bridge.submit_client_frame(handle.session_id, frame) {
                                                warn!(
                                                    peer = %peer,
                                                    public_key = %public_key,
                                                    session_id = handle.session_id,
                                                    error = %err,
                                                    "failed to enqueue frame into TUN bridge"
                                                );
                                                break;
                                            }
                                            continue;
                                        }
                                        if let Some(f) = &forwarder {
                                            // Track the last transport that delivered inbound
                                            // traffic so the outbound router sends replies on
                                            // the currently-live path (failover).
                                            if let Some(ctx) = &session_ctx {
                                                ctx.router.note_frame(
                                                    transport_id,
                                                    frame.header.flags,
                                                );
                                            }
                                            debug!(
                                                peer = %peer,
                                                session_id = handle.session_id,
                                                payload_len = frame.payload.len(),
                                                sequence = frame.header.sequence,
                                                "ingesting data frame into forwarder"
                                            );
                                            f.ingest_packet(frame);
                                        }
                                    }
                                    Err(err) => {
                                        info!(
                                            peer = %peer,
                                            public_key = %public_key,
                                            session_id = handle.session_id,
                                            error = ?err,
                                            "client session ended - recv error"
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if let Some(bridge) = &tun_bridge {
                        bridge.unregister_session(handle.session_id).await;
                        sessions.unregister_client(&binding.client_public_key);
                    }
                    if let Some(ctx) = session_ctx {
                        ctx.router.remove_transport(transport_id);
                        // Only tear down the session when its last path
                        // disconnects; otherwise the surviving path keeps the
                        // flow state and sequence space alive for failover.
                        if ctx.router.transport_count() == 0 {
                            ctx.forwarder.clear_session();
                            forwarders
                                .write()
                                .expect("forwarder registry lock should not be poisoned")
                                .remove(&handle.session_id);
                            sessions.unregister_client(&binding.client_public_key);
                        }
                    }
                }
                Err(err) => {
                    warn!(peer = %peer, error = %err, "client authentication failed");
                }
            }
        });
    }
}

fn maybe_log_tunnel_packet(tunnel_pcap: &Option<Arc<TunnelPcapLogger>>, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    if let Some(writer) = tunnel_pcap {
        writer.log_packet(payload);
    }
}

#[cfg(test)]
fn is_ipv4_icmp_echo_frame(packet: &[u8]) -> bool {
    if packet.len() < 28 {
        return false;
    }

    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 {
        return false;
    }

    let header_len = ihl * 4;
    if packet.len() < header_len + 8 {
        return false;
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len + 8 || total_len > packet.len() {
        return false;
    }

    if packet[9] != 1 {
        return false;
    }

    let icmp_start = header_len;
    packet[icmp_start] == 8 && packet[icmp_start + 1] == 0
}

fn apply_env_overrides<F>(cfg: &mut ServerConfig, mut read_env: F)
where
    F: FnMut(&str) -> Option<String>,
{
    if let Some(v) = read_env("BONDED_HOSTNAME") {
        cfg.server.hostname = v;
    }
    if let Some(v) = read_env("BONDED_HTTPS_BIND") {
        cfg.server.https_bind = v;
    }
    if let Some(v) = read_env("BONDED_HTTPS_PUBLIC") {
        if let Ok(port) = v.parse::<u16>() {
            cfg.server.https_public = port;
        }
    }
    if let Some(v) = read_env("BONDED_TLS_CERT_FILE") {
        cfg.server.tls_cert_file = v;
    }
    if let Some(v) = read_env("BONDED_TLS_KEY_FILE") {
        cfg.server.tls_key_file = v;
    }
    if let Some(v) = read_env("BONDED_WIREGUARD_BIND") {
        cfg.server.wireguard_bind = Some(v);
    }
    if let Some(v) = read_env("BONDED_WIREGUARD_PUBLIC") {
        if let Ok(port) = v.parse::<u16>() {
            cfg.server.wireguard_public = Some(port);
        }
    }
    if let Some(v) = read_env("BONDED_WIREGUARD_KEY_FILE") {
        cfg.server.wireguard_key_file = Some(v);
    }
    if let Some(v) = read_env("BONDED_WIREGUARD_PEERS_FILE") {
        cfg.server.wireguard_peers_file = Some(v);
    }
    if let Some(v) = read_env("BONDED_WIREGUARD_PEER_LEASE_SECS") {
        if let Ok(value) = v.parse::<u64>() {
            cfg.server.wireguard_peer_lease_secs = value;
        }
    }
    if let Some(v) = read_env("BONDED_TCP_BIND") {
        cfg.server.tcp_bind = Some(v);
    }
    if let Some(v) = read_env("BONDED_TCP_PUBLIC") {
        if let Ok(port) = v.parse::<u16>() {
            cfg.server.tcp_public = Some(port);
        }
    }
    if let Some(v) = read_env("BONDED_STATUS_BIND") {
        cfg.server.status_bind = v;
    }
    if let Some(v) = read_env("BONDED_HEALTH_BIND") {
        cfg.server.health_bind = v;
    }
    if let Some(v) = read_env("BONDED_LOG_LEVEL") {
        cfg.server.log_level = v;
    }
    if let Some(v) = read_env("BONDED_FORWARDING_MODE") {
        cfg.server.forwarding_mode = v;
    }
    if let Some(v) = read_env("BONDED_TUN_NAME") {
        cfg.server.tun_name = v;
    }
    if let Some(v) = read_env("BONDED_TUN_CIDR") {
        cfg.server.tun_cidr = v;
    }
    if let Some(v) = read_env("BONDED_TUN_MTU") {
        if let Ok(value) = v.parse::<u16>() {
            cfg.server.tun_mtu = value;
        }
    }
    if let Some(v) = read_env("BONDED_TUN_EGRESS_INTERFACE") {
        cfg.server.tun_egress_interface = v;
    }
    if let Some(v) = read_env("BONDED_AUTHORIZED_KEYS_FILE") {
        cfg.server.authorized_keys_file = v;
    }
    if let Some(v) = read_env("BONDED_INVITE_TOKENS_FILE") {
        cfg.server.invite_tokens_file = v;
    }
}

fn init_tracing_from_level(level: &str) {
    let parsed = match level.to_ascii_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    tracing_subscriber::fmt().with_max_level(parsed).init();
}

#[cfg(test)]
mod tests {
    use super::{apply_env_overrides, ensure_server_state_files, is_ipv4_icmp_echo_frame};
    use bonded_core::config::ServerConfig;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_state_path(name: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("bonded-{name}-{stamp}"))
    }

    #[test]
    fn env_overrides_replace_server_fields() {
        let mut cfg = ServerConfig::default();
        let env = [
            ("BONDED_HOSTNAME", "vpn.example.com"),
            ("BONDED_HTTPS_BIND", "0.0.0.0:8443"),
            ("BONDED_HTTPS_PUBLIC", "443"),
            ("BONDED_TLS_CERT_FILE", "/etc/bonded/server.crt"),
            ("BONDED_TLS_KEY_FILE", "/etc/bonded/server.key"),
            ("BONDED_WIREGUARD_BIND", "0.0.0.0:51820"),
            ("BONDED_WIREGUARD_PUBLIC", "51820"),
            ("BONDED_WIREGUARD_PEERS_FILE", "/tmp/wg-peers.toml"),
            ("BONDED_WIREGUARD_PEER_LEASE_SECS", "3600"),
            ("BONDED_TCP_BIND", "0.0.0.0:8000"),
            ("BONDED_TCP_PUBLIC", "8000"),
            ("BONDED_STATUS_BIND", "127.0.0.1:9002"),
            ("BONDED_HEALTH_BIND", "127.0.0.1:9001"),
            ("BONDED_LOG_LEVEL", "debug"),
            ("BONDED_FORWARDING_MODE", "tun"),
            ("BONDED_TUN_NAME", "bondedtest0"),
            ("BONDED_TUN_CIDR", "100.65.0.1/24"),
            ("BONDED_TUN_MTU", "1380"),
            ("BONDED_TUN_EGRESS_INTERFACE", "eth0"),
            ("BONDED_AUTHORIZED_KEYS_FILE", "/tmp/auth.toml"),
            ("BONDED_INVITE_TOKENS_FILE", "/tmp/tokens.toml"),
        ];

        apply_env_overrides(&mut cfg, |key| {
            env.iter()
                .find(|(candidate, _)| *candidate == key)
                .map(|(_, value)| (*value).to_owned())
        });

        assert_eq!(cfg.server.hostname, "vpn.example.com");
        assert_eq!(cfg.server.https_bind, "0.0.0.0:8443");
        assert_eq!(cfg.server.https_public, 443);
        assert_eq!(cfg.server.tls_cert_file, "/etc/bonded/server.crt");
        assert_eq!(cfg.server.tls_key_file, "/etc/bonded/server.key");
        assert_eq!(cfg.server.wireguard_bind, Some("0.0.0.0:51820".to_owned()));
        assert_eq!(cfg.server.wireguard_public, Some(51820));
        assert_eq!(
            cfg.server.wireguard_peers_file,
            Some("/tmp/wg-peers.toml".to_owned())
        );
        assert_eq!(cfg.server.wireguard_peer_lease_secs, 3600);
        assert_eq!(cfg.server.tcp_bind, Some("0.0.0.0:8000".to_owned()));
        assert_eq!(cfg.server.tcp_public, Some(8000));
        assert_eq!(cfg.server.status_bind, "127.0.0.1:9002");
        assert_eq!(cfg.server.health_bind, "127.0.0.1:9001");
        assert_eq!(cfg.server.log_level, "debug");
        assert_eq!(cfg.server.forwarding_mode, "tun");
        assert_eq!(cfg.server.tun_name, "bondedtest0");
        assert_eq!(cfg.server.tun_cidr, "100.65.0.1/24");
        assert_eq!(cfg.server.tun_mtu, 1380);
        assert_eq!(cfg.server.tun_egress_interface, "eth0");
        assert_eq!(cfg.server.authorized_keys_file, "/tmp/auth.toml");
        assert_eq!(cfg.server.invite_tokens_file, "/tmp/tokens.toml");
    }

    #[test]
    fn https_public_addr_combines_hostname_and_port() {
        let mut cfg = ServerConfig::default();
        cfg.server.hostname = "vpn.example.com".to_owned();
        cfg.server.https_public = 443;
        assert_eq!(cfg.server.https_public_addr(), "vpn.example.com:443");

        cfg.server.https_public = 8443;
        assert_eq!(cfg.server.https_public_addr(), "vpn.example.com:8443");
    }

    #[test]
    fn wireguard_public_addr_is_none_when_unconfigured() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.server.wireguard_public_addr(), None);
    }

    #[test]
    fn wireguard_public_addr_combines_hostname_and_port() {
        let mut cfg = ServerConfig::default();
        cfg.server.hostname = "vpn.example.com".to_owned();
        cfg.server.wireguard_public = Some(51820);
        assert_eq!(
            cfg.server.wireguard_public_addr(),
            Some("vpn.example.com:51820".to_owned())
        );
    }

    #[test]
    fn startup_creates_missing_server_state_files() {
        let root = temp_state_path("state-files");
        let authorized = root.join("authorized_keys.toml");
        let invites = root.join("invite_tokens.toml");
        let wg_peers = root.join("wireguard_peers.toml");

        let mut cfg = ServerConfig::default();
        cfg.server.authorized_keys_file = authorized.display().to_string();
        cfg.server.invite_tokens_file = invites.display().to_string();
        cfg.server.wireguard_peers_file = Some(wg_peers.display().to_string());

        ensure_server_state_files(&cfg).expect("state files should be created");

        assert!(authorized.exists());
        assert!(invites.exists());
        assert!(wg_peers.exists());
        assert_eq!(
            fs::read_to_string(&authorized).expect("authorized keys should be readable"),
            "devices = []\n"
        );
        assert_eq!(
            fs::read_to_string(&invites).expect("invite tokens should be readable"),
            "tokens = []\n"
        );
        assert_eq!(
            fs::read_to_string(&wg_peers).expect("wireguard peers should be readable"),
            "peers = []\n"
        );

        let _ = fs::remove_file(authorized);
        let _ = fs::remove_file(invites);
        let _ = fs::remove_file(wg_peers);
        let _ = fs::remove_dir(root);
    }

    #[test]
    fn detects_ipv4_icmp_echo_frames() {
        let packet = vec![
            0x45, 0x00, 0x00, 0x1c, // IPv4 header start + total length
            0x12, 0x34, 0x40, 0x00, // id + flags/fragment
            64, 1, 0, 0, // ttl + proto=icmp + checksum placeholder
            10, 8, 0, 2, // src ip
            1, 1, 1, 1, // dst ip
            8, 0, 0, 0, // ICMP echo request type/code/checksum
            0xab, 0xcd, 0x00, 0x01, // echo id + sequence
        ];

        assert!(is_ipv4_icmp_echo_frame(&packet));
    }

    #[test]
    fn rejects_non_icmp_echo_frames() {
        let tcp_packet = vec![
            0x45, 0x00, 0x00, 0x14, // IPv4 header total length only
            0x12, 0x34, 0x40, 0x00, // id + flags/fragment
            64, 6, 0, 0, // ttl + proto=tcp + checksum placeholder
            10, 8, 0, 2, // src ip
            1, 1, 1, 1, // dst ip
        ];

        assert!(!is_ipv4_icmp_echo_frame(&tcp_packet));
    }
}
