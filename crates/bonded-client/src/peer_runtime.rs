use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bonded_core::auth::{create_auth_challenge, sign_bytes, DeviceKeypair};
use bonded_core::config::{PeerShareMode, SocketProtectFn};
use bonded_core::peer_share::{
    PeerShareAdvertisement, PeerShareIntroductionRequest, SignedPeerShareIntroduction,
};
use pnet_datalink::NetworkInterface;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::cert_proof;
use crate::peer_discovery::{PeerShareAdvertiser, PeerShareBrowser};
use crate::peer_listener::{
    accept_peer_relay, connect_peer_relay, register_peer_relay_upstream,
    relay_peer_frames_rate_limited, AcceptedPeerRelay, PeerListenerIdentity, PeerRelayRateLimiter,
};
use crate::{
    bootstrap_scheme_candidates, enumerate_interfaces, establish_transport_paths,
    load_or_create_device_keypair, request_bootstrap_json, ClientConfig, ClientTransport,
};

pub struct PeerShareRuntime {
    tasks: Vec<JoinHandle<()>>,
    _listener_endpoint: Option<quinn::Endpoint>,
}

pub type PeerShareEventLogger = Arc<dyn Fn(String) + Send + Sync>;

const PEER_RUNTIME_RETRY_DELAY: Duration = Duration::from_secs(2);

impl Drop for PeerShareRuntime {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

pub async fn start_peer_share_runtime(
    config: &ClientConfig,
    peer_transport_tx: tokio::sync::mpsc::UnboundedSender<ClientTransport>,
    event_logger: Option<PeerShareEventLogger>,
) -> anyhow::Result<PeerShareRuntime> {
    let private_key_path = crate::expand_home_path(&config.client.private_key_path);
    let public_key_path = crate::expand_home_path(&config.client.public_key_path);
    let device_keypair = load_or_create_device_keypair(&private_key_path, &public_key_path)?;
    let mode = config.client.peer_share_mode;
    let is_provider = mode == PeerShareMode::Both || mode == PeerShareMode::ProviderOnly;
    let is_consumer = mode == PeerShareMode::Both || mode == PeerShareMode::ConsumerOnly;

    // Provider side: QUIC listener + mDNS advertiser + accept task
    let (listener_endpoint, listener_identity, advertisement, advertiser) = if is_provider {
        let (endpoint, identity, adv) = build_listener_runtime(config, &device_keypair)?;
        let advertiser = PeerShareAdvertiser::start(&adv)?;
        (Some(endpoint), Some(identity), Some(adv), Some(advertiser))
    } else {
        (None, None, None, None)
    };
    // Consumer side: mDNS browser
    let browser = if is_consumer {
        Some(PeerShareBrowser::start()?)
    } else {
        None
    };

    if let (Some(adv), Some(identity)) = (advertisement.as_ref(), listener_identity.as_ref()) {
        info!(
            endpoint = %adv.endpoint,
            nonce = %identity.instance_nonce,
            "peer-share runtime started"
        );
        emit_peer_share_event(
            event_logger.as_ref(),
            format!(
                "runtime started endpoint={} nonce={}",
                adv.endpoint, identity.instance_nonce
            ),
        );
    } else {
        info!("peer-share runtime started (consumer-only mode)");
        emit_peer_share_event(
            event_logger.as_ref(),
            "runtime started (consumer-only mode)".to_owned(),
        );
    }

    let accept_task = if is_provider {
        let accept_endpoint = listener_endpoint.clone().expect("provider mode requires listener");
        let accept_config = config.clone();
        let accept_server_key = config.client.server_public_key.clone();
        let accept_identity = listener_identity.clone().expect("provider mode requires identity");
        let accept_logger = event_logger.clone();
        let accept_max_consumers = config.client.peer_share_max_consumers.max(1) as usize;
        let accept_bandwidth_kbps = config.client.peer_share_relay_bandwidth_kbps;
        let active_relays = Arc::new(AtomicUsize::new(0));
        let advertiser = advertiser;
        Some(tokio::spawn(async move {
        let _advertiser = advertiser;
        while let Some(incoming) = accept_endpoint.accept().await {
            let connection = match incoming.await {
                Ok(connection) => connection,
                Err(err) => {
                    warn!(error = %err, "peer-share QUIC accept failed");
                    emit_peer_share_event(
                        accept_logger.as_ref(),
                        format!("QUIC accept failed: {err}"),
                    );
                    continue;
                }
            };

            let AcceptedPeerRelay {
                transport: mut peer,
                introduction,
            } = match accept_peer_relay(&accept_server_key, &accept_identity, connection).await {
                Ok(peer) => peer,
                Err(err) => {
                    warn!(error = %err, "peer-share introduction verification failed");
                    emit_peer_share_event(
                        accept_logger.as_ref(),
                        format!("introduction verification failed: {err}"),
                    );
                    continue;
                }
            };
            let consumer_key = introduction.introduction.consumer_device_public_key.clone();
            // Enforce the provider's concurrent-consumer cap before spending
            // resources on a dedicated upstream transport.
            let in_flight = active_relays.fetch_add(1, Ordering::SeqCst);
            if in_flight >= accept_max_consumers {
                active_relays.fetch_sub(1, Ordering::SeqCst);
                warn!(
                    consumer = %consumer_key,
                    max = accept_max_consumers,
                    "peer-share consumer cap reached; rejecting relay"
                );
                emit_peer_share_event(
                    accept_logger.as_ref(),
                    format!("consumer cap reached; rejecting relay for consumer={consumer_key}"),
                );
                continue;
            }
            info!(
                consumer = %consumer_key,
                provider_nonce = %introduction.introduction.provider_instance_nonce,
                "peer-share relay accepted"
            );
            emit_peer_share_event(
                accept_logger.as_ref(),
                format!(
                    "accepted relay for consumer={} provider_nonce={}",
                    consumer_key, introduction.introduction.provider_instance_nonce,
                ),
            );

            let relay_config = accept_config.clone();
            let relay_logger = accept_logger.clone();
            let relay_count = active_relays.clone();
            tokio::spawn(async move {
                let mut peer = peer;
                // Resilience: if the upstream (provider->server) connection fails,
                // re-establish it instead of terminating the relay permanently.
                // The peer (consumer->provider QUIC) connection is kept alive
                // across upstream reconnects.
                let result = async {
                    let mut retry_delay = std::time::Duration::from_secs(1);
                    const MAX_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(30);
                    loop {
                        // The introduction is a short-lived credential only
                        // the consumer can mint. Once it expires the server
                        // rejects every re-registration, so retrying is
                        // futile: abandon the relay instead. Dropping the
                        // peer connection lets the consumer notice the loss
                        // and mint a fresh introduction. (Observed
                        // 2026-10-17: ~44 rejected re-registrations over
                        // 15 minutes against one expired introduction.)
                        if introduction_expired(&introduction) {
                            anyhow::bail!(
                                "peer relay introduction expired; abandoning relay so the consumer can re-introduce"
                            );
                        }
                        let mut upstreams = match establish_peer_upstream_paths(&relay_config).await {
                            Ok(u) => u,
                            Err(e) => {
                                tracing::warn!(error = %e, "provider: failed to establish upstream paths, retrying");
                                tokio::time::sleep(retry_delay).await;
                                retry_delay = std::cmp::min(retry_delay * 2, MAX_RETRY_DELAY);
                                continue;
                            }
                        };
                        if upstreams.is_empty() {
                            anyhow::bail!(
                                "peer-share relay accept produced no upstream transport paths"
                            );
                        }
                        let mut upstream = upstreams.remove(0);
                        tracing::warn!("provider: sending relay registration");
                        if let Err(e) = register_peer_relay_upstream(&mut upstream, introduction.clone()).await {
                            tracing::warn!(error = %e, "provider: relay registration failed, retrying");
                            tokio::time::sleep(retry_delay).await;
                            retry_delay = std::cmp::min(retry_delay * 2, MAX_RETRY_DELAY);
                            continue;
                        }
                        tracing::warn!("provider: relay registration sent");
                        let mut limiter = PeerRelayRateLimiter::new(accept_bandwidth_kbps);
                        match relay_peer_frames_rate_limited(&mut peer, &mut upstream, &mut limiter).await {
                            Ok(()) => {
                                // Relay completed normally (peer disconnected)
                                return Ok(());
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "provider: relay upstream failed, re-establishing");
                                // Check if peer is still alive before retrying
                                // If peer.recv() would fail immediately, the peer is gone
                                tokio::time::sleep(retry_delay).await;
                                retry_delay = std::cmp::min(retry_delay * 2, MAX_RETRY_DELAY);
                                // Continue loop to re-establish upstream
                            }
                        }
                    }
                }
                .await;
                relay_count.fetch_sub(1, Ordering::SeqCst);
                match result {
                    Ok(()) => {
                        emit_peer_share_event(
                            relay_logger.as_ref(),
                            format!("relay loop completed for consumer={consumer_key}"),
                        );
                    }
                    Err(err) => {
                        warn!(error = %err, consumer = %consumer_key, "peer relay terminated");
                        emit_peer_share_event(
                            relay_logger.as_ref(),
                            format!("relay terminated for consumer={consumer_key}: {err}"),
                        );
                    }
                }
            });
        }
    }))
    } else {
        None
    };

    let browse_task = if is_consumer {
        let browse_config = config.clone();
        let browse_server_key = config.client.server_public_key.clone();
        let browse_device_keypair = device_keypair.clone();
        let browse_self_key = device_keypair.public_key_b64.clone();
        let browse_bind_ip = peer_relay_bind_ip(config)?;
        let browse_logger = event_logger.clone();
        let (closed_peer_tx, mut closed_peer_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let browser = browser.expect("consumer mode requires browser");
        Some(tokio::spawn(async move {
        let mut connected_peers = HashSet::new();
        loop {
            let advertisement = tokio::select! {
                Some(peer_id) = closed_peer_rx.recv() => {
                    connected_peers.remove(&peer_id);
                    info!(peer = %peer_id, "peer-share path closed; allowing rediscovery");
                    emit_peer_share_event(
                        browse_logger.as_ref(),
                        format!("path closed for peer={peer_id}; allowing rediscovery"),
                    );
                    continue;
                }
                advertisement = browser.recv() => {
                    match advertisement {
                        Ok(advertisement) => advertisement,
                        Err(err) => {
                            warn!(error = %err, "peer-share browser stopped");
                            emit_peer_share_event(
                                browse_logger.as_ref(),
                                format!("browser stopped: {err}"),
                            );
                            break;
                        }
                    }
                }
            };

            if !should_accept_discovered_peer(&advertisement, &browse_server_key, &browse_self_key)
            {
                continue;
            }

            let peer_id = format!(
                "{}:{}",
                advertisement.device_public_key, advertisement.instance_nonce
            );
            if connected_peers.contains(&peer_id) {
                continue;
            }
            info!(
                peer = %peer_id,
                endpoint = %advertisement.endpoint,
                "discovered peer-share advertisement"
            );
            emit_peer_share_event(
                browse_logger.as_ref(),
                format!(
                    "discovered peer={peer_id} endpoint={}",
                    advertisement.endpoint
                ),
            );

            let introduction = match request_peer_share_introduction(
                &browse_config,
                &browse_device_keypair,
                &advertisement,
            )
            .await
            {
                Ok(introduction) => introduction,
                Err(err) => {
                    warn!(error = %err, peer = %peer_id, "peer-share introduction request failed");
                    emit_peer_share_event(
                        browse_logger.as_ref(),
                        format!("introduction request failed for peer={peer_id}: {err}"),
                    );
                    sleep(PEER_RUNTIME_RETRY_DELAY).await;
                    continue;
                }
            };
            info!(peer = %peer_id, "peer-share introduction issued");
            emit_peer_share_event(
                browse_logger.as_ref(),
                format!("introduction issued for peer={peer_id}"),
            );

            let transport = match connect_peer_relay(
                &browse_server_key,
                &advertisement.device_public_key,
                &introduction,
                browse_config.socket_protect.as_ref(),
                browse_bind_ip,
            )
            .await
            {
                Ok(transport) => transport,
                Err(err) => {
                    warn!(error = %err, peer = %peer_id, "peer-share relay dial failed");
                    emit_peer_share_event(
                        browse_logger.as_ref(),
                        format!("relay dial failed for peer={peer_id}: {err}"),
                    );
                    sleep(PEER_RUNTIME_RETRY_DELAY).await;
                    continue;
                }
            };
            emit_peer_share_event(
                browse_logger.as_ref(),
                format!("relay dial succeeded for peer={peer_id}"),
            );

            let relay_expires_at = introduction.introduction.expires_at;
            if peer_transport_tx
                .send(ClientTransport::peer_relay(
                    transport,
                    peer_id.clone(),
                    closed_peer_tx.clone(),
                    relay_expires_at,
                ))
                .is_err()
            {
                break;
            }
            connected_peers.insert(peer_id);
        }
        }))
    } else {
        None
    };

    let mut tasks = Vec::new();
    if let Some(task) = accept_task {
        tasks.push(task);
    }
    if let Some(task) = browse_task {
        tasks.push(task);
    }

    Ok(PeerShareRuntime {
        tasks,
        _listener_endpoint: listener_endpoint,
    })
}

async fn establish_peer_upstream_paths(
    config: &ClientConfig,
) -> anyhow::Result<Vec<ClientTransport>> {
    let mut peer_config = config.clone();
    let filtered: Vec<String> = peer_config
        .client
        .preferred_protocols
        .iter()
        .filter(|protocol| {
            protocol.eq_ignore_ascii_case("wss")
                || protocol.eq_ignore_ascii_case("websocket_tls")
                || protocol.eq_ignore_ascii_case("h3")
                || protocol.eq_ignore_ascii_case("quic")
        })
        .cloned()
        .collect();
    peer_config.client.preferred_protocols = if filtered.is_empty() {
        vec!["wss".to_owned(), "h3".to_owned()]
    } else {
        filtered
    };
    establish_transport_paths(&peer_config, 1).await
}

fn build_listener_runtime(
    config: &ClientConfig,
    device_keypair: &DeviceKeypair,
) -> anyhow::Result<(
    quinn::Endpoint,
    PeerListenerIdentity,
    PeerShareAdvertisement,
)> {
    let cert = generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .context("failed to generate peer-share listener certificate")?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
    let fingerprint = cert_proof::compute_fingerprint(&cert_der);
    let bind_addr: SocketAddr =
        config
            .client
            .peer_share_bind_address
            .parse()
            .with_context(|| {
                format!(
                    "invalid peer_share_bind_address: {}",
                    config.client.peer_share_bind_address
                )
            })?;
    let advertise_ip = resolve_advertise_ip(config, &enumerate_interfaces(), bind_addr)?;
    let listener_bind_addr = match bind_addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => SocketAddr::new(advertise_ip, bind_addr.port()),
        IpAddr::V6(ip) if ip.is_unspecified() => SocketAddr::new(advertise_ip, bind_addr.port()),
        _ => bind_addr,
    };
    let endpoint = quinn::Endpoint::new(
        Default::default(),
        Some(build_peer_server_config(cert_der, key_der)),
        bind_peer_listener_socket(listener_bind_addr, config.socket_protect.as_ref())?,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|err| {
        anyhow::anyhow!("failed to bind peer-share listener on {listener_bind_addr}: {err}")
    })?;
    let listen_addr = endpoint.local_addr()?;
    let endpoint_str = SocketAddr::new(advertise_ip, listen_addr.port()).to_string();
    let instance_nonce = create_auth_challenge();
    let listener_identity = PeerListenerIdentity {
        provider_device_public_key: device_keypair.public_key_b64.clone(),
        instance_nonce: instance_nonce.clone(),
        listener_transport: "quic".to_owned(),
        listener_cert_fingerprint: fingerprint.clone(),
    };
    let advertisement = PeerShareAdvertisement {
        version: 1,
        device_public_key: device_keypair.public_key_b64.clone(),
        server_public_key: config.client.server_public_key.clone(),
        instance_nonce,
        endpoint: endpoint_str,
        listener_cert_fingerprint: fingerprint,
        capabilities: vec!["relay".to_owned(), "quic".to_owned()],
    };
    Ok((endpoint, listener_identity, advertisement))
}

fn bind_peer_listener_socket(
    bind_addr: SocketAddr,
    socket_protect: Option<&SocketProtectFn>,
) -> anyhow::Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(bind_addr)?;
    #[cfg(unix)]
    if let Some(protect) = socket_protect {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        if !protect.0(fd) {
            anyhow::bail!(
                "failed to protect peer-share listener socket from VPN capture (fd={fd})"
            );
        }
    }

    Ok(socket)
}

/// Whether a signed peer-share introduction has passed its expiry
/// (Unix epoch seconds, matching the server's issuance and the
/// verification-side `ensure_not_expired` check).
fn introduction_expired(introduction: &SignedPeerShareIntroduction) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    introduction.introduction.expires_at <= now
}

fn peer_relay_bind_ip(config: &ClientConfig) -> anyhow::Result<Option<IpAddr>> {
    let bind_ip = config.client.peer_share_advertise_ip.trim();
    if bind_ip.is_empty() {
        return Ok(None);
    }

    bind_ip
        .parse()
        .with_context(|| {
            format!(
                "invalid peer_share_advertise_ip for peer relay dial: {}",
                config.client.peer_share_advertise_ip
            )
        })
        .map(Some)
}

fn emit_peer_share_event(logger: Option<&PeerShareEventLogger>, message: String) {
    if let Some(logger) = logger {
        logger(message);
    }
}

async fn request_peer_share_introduction(
    config: &ClientConfig,
    consumer_keypair: &DeviceKeypair,
    advertisement: &PeerShareAdvertisement,
) -> anyhow::Result<SignedPeerShareIntroduction> {
    let bootstrap_address = config.client.server_public_address.trim();
    if bootstrap_address.is_empty() {
        anyhow::bail!("server_public_address is required for peer-share introduction bootstrap");
    }

    let request = build_peer_introduction_request(consumer_keypair, advertisement)?;
    let request_body = serde_json::to_string(&request)?;
    let mut errors = Vec::new();
    for scheme in bootstrap_scheme_candidates(config) {
        let response = match request_bootstrap_json(
            config,
            scheme,
            bootstrap_address,
            "POST",
            "/v1/bootstrap/peer-share/introduction",
            Some(&request_body),
        )
        .await
        {
            Ok(body) => body,
            Err(err) => {
                errors.push(format!("scheme={scheme:?}: {err:#}"));
                continue;
            }
        };
        return serde_json::from_str(&response)
            .map_err(|err| anyhow::anyhow!("invalid peer-share introduction JSON: {err}"));
    }

    anyhow::bail!(
        "failed to request peer-share introduction via {}: {}",
        bootstrap_address,
        errors.join(" | ")
    )
}

fn build_peer_introduction_request(
    consumer_keypair: &DeviceKeypair,
    advertisement: &PeerShareAdvertisement,
) -> anyhow::Result<PeerShareIntroductionRequest> {
    let listener_transport = advertised_listener_transport(advertisement)?;
    let mut request = PeerShareIntroductionRequest {
        consumer_device_public_key: consumer_keypair.public_key_b64.clone(),
        provider_device_public_key: advertisement.device_public_key.clone(),
        provider_instance_nonce: advertisement.instance_nonce.clone(),
        provider_endpoint: advertisement.endpoint.clone(),
        listener_transport,
        listener_cert_fingerprint: advertisement.listener_cert_fingerprint.clone(),
        consumer_signature: String::new(),
    };
    request.consumer_signature = sign_bytes(consumer_keypair, &request.signed_payload()?)?;
    Ok(request)
}

fn advertised_listener_transport(advertisement: &PeerShareAdvertisement) -> anyhow::Result<String> {
    if advertisement
        .capabilities
        .iter()
        .any(|capability| capability.eq_ignore_ascii_case("quic"))
    {
        Ok("quic".to_owned())
    } else {
        anyhow::bail!("peer advertisement did not include a supported listener transport")
    }
}

fn should_accept_discovered_peer(
    advertisement: &PeerShareAdvertisement,
    expected_server_public_key: &str,
    self_public_key: &str,
) -> bool {
    advertisement.server_public_key == expected_server_public_key
        && advertisement.device_public_key != self_public_key
}

fn resolve_advertise_ip(
    config: &ClientConfig,
    interfaces: &[NetworkInterface],
    listen_addr: SocketAddr,
) -> anyhow::Result<IpAddr> {
    if !config.client.peer_share_advertise_ip.trim().is_empty() {
        return config
            .client
            .peer_share_advertise_ip
            .parse()
            .with_context(|| {
                format!(
                    "invalid peer_share_advertise_ip: {}",
                    config.client.peer_share_advertise_ip
                )
            });
    }

    match listen_addr.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => return Ok(IpAddr::V4(ip)),
        IpAddr::V6(ip) if !ip.is_unspecified() => return Ok(IpAddr::V6(ip)),
        _ => {}
    }

    let candidates: Vec<IpAddr> = interfaces
        .iter()
        .flat_map(|interface| interface.ips.iter())
        .map(|network| network.ip())
        .collect();
    // Prefer an address on the same link as one of the client's server
    // paths. Interface enumeration order is arbitrary, and on Android it
    // includes the VPN's own tunnel interface — whose address is not a
    // LAN address a peer can dial (and is identical on every client), so
    // first-bindable-wins can advertise the tunnel address and make the
    // provider unreachable. A candidate sharing a /24 with a configured
    // path bind address is on the link the client actually uses.
    if let Some(ip) = prefer_path_subnet_candidate(&candidates, &config.client.path_bind_addresses)
    {
        return Ok(ip);
    }
    select_advertise_ip(&candidates).ok_or_else(|| {
        anyhow::anyhow!("failed to determine a non-loopback peer-share advertise IP")
    })
}

/// Pick the first bindable IPv4 candidate that shares its /24 with one of
/// the configured path bind addresses (the local addresses of the
/// client's server transports). Returns None when no candidate matches,
/// leaving default selection to apply.
fn prefer_path_subnet_candidate(candidates: &[IpAddr], bind_addresses: &[String]) -> Option<IpAddr> {
    let bind_ips: Vec<Ipv4Addr> = bind_addresses
        .iter()
        .filter_map(|raw| raw.trim().parse::<IpAddr>().ok())
        .filter_map(|ip| match ip {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect();
    if bind_ips.is_empty() {
        return None;
    }
    candidates.iter().copied().find(|candidate| {
        let IpAddr::V4(candidate_v4) = candidate else {
            return false;
        };
        if !is_bindable_advertise_ip(candidate) {
            return false;
        }
        let candidate_octets = candidate_v4.octets();
        bind_ips
            .iter()
            .any(|bind_ip| candidate_octets[..3] == bind_ip.octets()[..3])
    })
}

/// Whether the peer-share listener can actually bind and advertise this
/// address: not loopback/unspecified/multicast, and not link-local. A
/// link-local address (169.254.0.0/16, fe80::/10) cannot be bound without
/// a scope id, so `UdpSocket::bind` rejects it with EINVAL — and interface
/// enumeration on phones commonly lists a link-local IPv6 address ahead of
/// the usable LAN IPv4 address.
fn is_bindable_advertise_ip(ip: &IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => !ip.is_link_local(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) != 0xfe80,
    }
}

/// Pick the address to advertise for the peer-share listener: a bindable
/// IPv4 address first, then any bindable address, then — so unusual setups
/// keep working — the first non-loopback address of any kind.
fn select_advertise_ip(candidates: &[IpAddr]) -> Option<IpAddr> {
    candidates
        .iter()
        .copied()
        .find(|ip| ip.is_ipv4() && is_bindable_advertise_ip(ip))
        .or_else(|| {
            candidates
                .iter()
                .copied()
                .find(|ip| is_bindable_advertise_ip(ip))
        })
        .or_else(|| {
            candidates
                .iter()
                .copied()
                .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
        })
}

fn build_peer_server_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> quinn::ServerConfig {
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::try_from(key_der).expect("valid private key DER");
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server TLS config should build");
    tls_config.alpn_protocols = vec![b"bonded-peer".to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .expect("QUIC crypto config should build"),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4u32.into());
    // Peer relays are standby failover paths: they sit idle until the primary
    // path fails. Quinn's default 30s max idle timeout would silently kill an
    // idle relay, so send periodic PINGs to keep the QUIC connection alive.
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    server_config.transport_config(Arc::new(transport));
    server_config
}

#[cfg(test)]
mod tests {
    use bonded_core::auth::verify_signature;

    use super::{
        build_peer_introduction_request, introduction_expired, prefer_path_subnet_candidate,
        resolve_advertise_ip, select_advertise_ip, should_accept_discovered_peer,
    };
    use bonded_core::auth::DeviceKeypair;
    use bonded_core::config::{ClientConfig, PeerShareMode};
    use bonded_core::peer_share::{PeerShareAdvertisement, SignedPeerShareIntroduction};
    use pnet_datalink::NetworkInterface;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn discovered_peers_ignore_self_and_other_servers() {
        let advertisement = PeerShareAdvertisement {
            version: 1,
            device_public_key: "peer-a".to_owned(),
            server_public_key: "server-a".to_owned(),
            instance_nonce: "nonce-1".to_owned(),
            endpoint: "192.168.1.20:54443".to_owned(),
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            capabilities: vec!["relay".to_owned(), "quic".to_owned()],
        };
        assert!(should_accept_discovered_peer(
            &advertisement,
            "server-a",
            "self"
        ));
        assert!(!should_accept_discovered_peer(
            &advertisement,
            "server-b",
            "self"
        ));
        assert!(!should_accept_discovered_peer(
            &advertisement,
            "server-a",
            "peer-a"
        ));
    }

    #[test]
    fn introduction_expiry_gate() {
        let claims = bonded_core::peer_share::PeerShareIntroductionClaims {
            consumer_device_public_key: "consumer".to_owned(),
            provider_device_public_key: "provider".to_owned(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            expires_at: 0,
        };
        let mut introduction = SignedPeerShareIntroduction {
            introduction: claims,
            server_signature: "signature".to_owned(),
        };
        // expires_at = 0 is long past: the provider must abandon the relay
        // instead of re-registering with this introduction.
        assert!(introduction_expired(&introduction));

        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs()
            + 300;
        introduction.introduction.expires_at = future;
        assert!(!introduction_expired(&introduction));
    }

    #[test]
    fn introduction_request_is_signed_with_consumer_key() {
        let consumer = DeviceKeypair::generate();
        let advertisement = PeerShareAdvertisement {
            version: 1,
            device_public_key: "provider".to_owned(),
            server_public_key: "server-a".to_owned(),
            instance_nonce: "nonce-1".to_owned(),
            endpoint: "192.168.1.20:54443".to_owned(),
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            capabilities: vec!["relay".to_owned(), "quic".to_owned()],
        };

        let request = build_peer_introduction_request(&consumer, &advertisement)
            .expect("request should build");
        verify_signature(
            &consumer.public_key_b64,
            &request
                .signed_payload()
                .expect("request payload should serialize"),
            &request.consumer_signature,
        )
        .expect("request signature should verify");
    }

    #[test]
    fn advertise_ip_uses_explicit_override() {
        let mut config = ClientConfig::default();
        config.client.peer_share_advertise_ip = "127.0.0.1".to_owned();
        let ip = resolve_advertise_ip(
            &config,
            &Vec::<NetworkInterface>::new(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 54443),
        )
        .expect("override should parse");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn advertise_ip_prefers_path_subnet_over_tunnel_address() {
        // The Android failure mode: enumeration lists the VPN tunnel
        // address (10.8.0.2, the same on every client) before the Wi-Fi
        // address. The Wi-Fi address shares a /24 with the Wi-Fi path
        // bind address and must win; otherwise the provider advertises
        // an address no peer can dial.
        let candidates = vec![
            IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140)),
        ];
        let binds = vec!["192.168.1.140".to_owned(), "192.0.0.4".to_owned()];
        assert_eq!(
            prefer_path_subnet_candidate(&candidates, &binds),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140)))
        );
    }

    #[test]
    fn advertise_ip_path_subnet_no_match_without_binds() {
        let candidates = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140))];
        assert_eq!(prefer_path_subnet_candidate(&candidates, &[]), None);
        assert_eq!(
            prefer_path_subnet_candidate(&candidates, &["203.0.113.9".to_owned()]),
            None
        );
    }
    #[test]
    fn advertise_ip_skips_link_local_ipv6_for_lan_ipv4() {
        // The phone failure mode: enumeration lists a link-local IPv6
        // address first; binding it would fail with EINVAL, so the LAN
        // IPv4 address must win.
        let candidates = vec![
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
        ];
        assert_eq!(
            select_advertise_ip(&candidates),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)))
        );
    }

    #[test]
    fn advertise_ip_skips_link_local_ipv4_for_global_ipv6() {
        let candidates = vec![
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2600, 0, 0, 0, 0, 0, 0, 5)),
        ];
        assert_eq!(
            select_advertise_ip(&candidates),
            Some(IpAddr::V6(Ipv6Addr::new(0x2600, 0, 0, 0, 0, 0, 0, 5)))
        );
    }

    #[test]
    fn advertise_ip_falls_back_when_only_link_local_exists() {
        let candidates = vec![IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 9))];
        assert_eq!(
            select_advertise_ip(&candidates),
            Some(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 9)))
        );
    }

    #[test]
    fn advertise_ip_rejects_loopback_only() {
        let candidates = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        assert_eq!(select_advertise_ip(&candidates), None);
    }
}
