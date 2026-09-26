//! Server-side WireGuard peer registry and address allocation.
//!
//! When a client calls `POST /v1/bootstrap/wireguard/peer` it registers its
//! WireGuard public key and receives an assigned `/32` IP from the
//! `100.64.1.0/24` block. Peer assignments are persisted to disk, refreshed on
//! re-provisioning, and reclaimed after lease expiry so restart-safe WireGuard
//! bootstrap does not leak addresses forever.
//!
//! The actual WireGuard handshake is handled by boringtun in a separate
//! server-side endpoint (Phase 6.3+).

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use base64::Engine as _;
use bonded_core::config::DEFAULT_WIREGUARD_PEER_LEASE_SECS;
use bonded_core::session::{SessionFrame, SessionHeader, FLAG_PING, FLAG_PONG};
use bonded_core::transport::WireGuardKeypair;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::PublicKey;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tracing::{debug, info, warn};

use crate::session_registry::SessionRegistry;
use crate::smoltcp_forwarder::{SessionContext, SessionOutboundRouter, SmoltcpForwarder};
use crate::tun_bridge::TunBridge;
use crate::tunnel_pcap::TunnelPcapLogger;

type ForwarderRegistry = Arc<RwLock<HashMap<u64, Arc<SessionContext>>>>;

const WG_MAX_DATAGRAM: usize = 1500;
const WG_HS_BUF: usize = 148;
const WG_ENCAP_OVERHEAD: usize = 60;
const WG_FAKE_SRC_IP: [u8; 4] = [100, 64, 0, 1];
const WG_FAKE_DST_IP: [u8; 4] = [100, 64, 0, 2];
const IPV4_HDR_LEN: usize = 20;
const MAX_RESPONSE_DRAIN_PER_CYCLE: usize = 256;

/// Holds the per-peer allocation: the WireGuard public key and the assigned IP.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct WireGuardPeer {
    /// The client device's ed25519 public key (base64), used as the stable
    /// identifier across reconnections.
    pub device_public_key: String,
    /// The client's WireGuard X25519 public key (base64).
    pub wg_public_key: String,
    /// Allocated /32 IP from the bonded WireGuard subnet.
    pub peer_ip: Ipv4Addr,
    /// UNIX timestamp (seconds) when this peer allocation expires unless it is
    /// refreshed by another bootstrap provisioning call.
    #[serde(default)]
    pub lease_expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredWireGuardPeer {
    pub peer_ip: String,
    pub lease_expires_at: u64,
}

/// Thread-safe registry of WireGuard peers with CIDR allocation.
pub struct WireGuardPeerRegistry {
    peers: Mutex<HashMap<String, WireGuardPeer>>,
    /// Next host octet to allocate from 100.64.1.x/24.
    next_octet: Mutex<u8>,
    peer_lease: Duration,
    path: Option<PathBuf>,
}

#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
struct WireGuardPeersFile {
    #[serde(default)]
    peers: Vec<WireGuardPeer>,
}

impl WireGuardPeerRegistry {
    /// Create a new registry.  IPs will be allocated from `100.64.1.1/32`
    /// upwards (skipping .0 and .255).
    pub fn new() -> Self {
        Self::new_with_lease(Duration::from_secs(DEFAULT_WIREGUARD_PEER_LEASE_SECS))
    }

    pub fn new_with_lease(peer_lease: Duration) -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            next_octet: Mutex::new(1),
            peer_lease,
            path: None,
        }
    }

    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::load_with_lease(path, Duration::from_secs(DEFAULT_WIREGUARD_PEER_LEASE_SECS))
    }

    pub fn load_with_lease(path: impl AsRef<Path>, peer_lease: Duration) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (peers, next_octet, normalized) = load_peers_file(&path, peer_lease)?;
        let registry = Self {
            peers: Mutex::new(peers),
            next_octet: Mutex::new(next_octet),
            peer_lease,
            path: Some(path),
        };
        if normalized {
            let peers = registry.peers.lock().expect("wg peer registry lock");
            registry.persist_locked(&peers)?;
        }
        Ok(registry)
    }

    /// Register a peer and return its allocated `"a.b.c.d/32"` CIDR string.
    ///
    /// If the `device_public_key` was already registered, the existing
    /// allocation is returned unchanged (idempotent).
    pub fn register_peer(&self, device_public_key: &str, wg_public_key: &str) -> String {
        self.register_peer_lease(device_public_key, wg_public_key)
            .peer_ip
    }

    pub fn register_peer_lease(
        &self,
        device_public_key: &str,
        wg_public_key: &str,
    ) -> RegisteredWireGuardPeer {
        let mut peers = self.peers.lock().expect("wg peer registry lock");
        self.prune_expired_locked(&mut peers)
            .expect("pruning expired WireGuard peers should succeed");
        let lease_expires_at = unix_timestamp_after(self.peer_lease)
            .expect("computing WireGuard peer lease expiry should succeed");
        if let Some(existing) = peers.get_mut(device_public_key) {
            let peer_ip = existing.peer_ip;
            let old_wg_public_key = existing.wg_public_key.clone();
            let changed = old_wg_public_key != wg_public_key;
            if changed {
                existing.wg_public_key = wg_public_key.to_owned();
            }
            let lease_changed = existing.lease_expires_at != lease_expires_at;
            existing.lease_expires_at = lease_expires_at;
            if changed || lease_changed {
                info!(
                    device_pk = %device_public_key,
                    old_wg_pk = %old_wg_public_key,
                    new_wg_pk = %wg_public_key,
                    peer_ip = %peer_ip,
                    lease_expires_at,
                    "WireGuard peer key updated"
                );
                self.persist_locked(&peers)
                    .expect("persisting updated WireGuard peer should succeed");
            }
            return RegisteredWireGuardPeer {
                peer_ip: format!("{peer_ip}/32"),
                lease_expires_at,
            };
        }

        let ip = {
            let mut n = self.next_octet.lock().expect("wg octet lock");
            allocate_peer_ip(&peers, &mut n).expect("WireGuard peer allocation should succeed")
        };

        info!(
            device_pk = %device_public_key,
            wg_pk = %wg_public_key,
            peer_ip = %ip,
            lease_expires_at,
            "WireGuard peer registered"
        );
        peers.insert(
            device_public_key.to_owned(),
            WireGuardPeer {
                device_public_key: device_public_key.to_owned(),
                wg_public_key: wg_public_key.to_owned(),
                peer_ip: ip,
                lease_expires_at,
            },
        );
        self.persist_locked(&peers)
            .expect("persisting WireGuard peer registration should succeed");
        RegisteredWireGuardPeer {
            peer_ip: format!("{ip}/32"),
            lease_expires_at,
        }
    }

    /// Look up a peer by its WireGuard public key (for use by the WG
    /// transport when deciding whether to accept an inbound handshake).
    pub fn find_by_wg_key(&self, wg_public_key: &str) -> Option<WireGuardPeer> {
        let mut peers = self.peers.lock().expect("wg peer registry lock");
        self.prune_expired_locked(&mut peers)
            .expect("pruning expired WireGuard peers should succeed");
        peers
            .values()
            .find(|p| p.wg_public_key == wg_public_key)
            .cloned()
    }

    /// Return all registered peers (for kernel WG configuration helpers).
    pub fn all_peers(&self) -> Vec<WireGuardPeer> {
        let mut peers = self.peers.lock().expect("wg peer registry lock");
        self.prune_expired_locked(&mut peers)
            .expect("pruning expired WireGuard peers should succeed");
        peers.values().cloned().collect()
    }

    fn persist_locked(&self, peers: &HashMap<String, WireGuardPeer>) -> anyhow::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        persist_peers_file(path, peers)
    }

    fn prune_expired_locked(
        &self,
        peers: &mut HashMap<String, WireGuardPeer>,
    ) -> anyhow::Result<()> {
        let now = unix_timestamp_now()?;
        let before = peers.len();
        peers.retain(|_, peer| peer.lease_expires_at == 0 || peer.lease_expires_at > now);
        if peers.len() != before {
            self.persist_locked(peers)?;
        }
        Ok(())
    }
}

fn load_peers_file(
    path: &Path,
    peer_lease: Duration,
) -> anyhow::Result<(HashMap<String, WireGuardPeer>, u8, bool)> {
    if !path.exists() {
        return Ok((HashMap::new(), 1, false));
    }

    let raw = fs::read_to_string(path)?;
    let parsed: WireGuardPeersFile = toml::from_str(&raw)?;
    let now = unix_timestamp_now()?;
    let default_lease_expires_at = unix_timestamp_after(peer_lease)?;
    let mut peers = HashMap::new();
    let mut normalized = false;
    let mut max_octet = 0u8;
    for mut peer in parsed.peers {
        if peer.lease_expires_at == 0 {
            peer.lease_expires_at = default_lease_expires_at;
            normalized = true;
        }
        if peer.lease_expires_at <= now {
            normalized = true;
            continue;
        }
        max_octet = max_octet.max(peer.peer_ip.octets()[3]);
        peers.insert(peer.device_public_key.clone(), peer);
    }
    Ok((
        peers,
        normalize_octet(max_octet.saturating_add(1)),
        normalized,
    ))
}

fn persist_peers_file(path: &Path, peers: &HashMap<String, WireGuardPeer>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut peer_list: Vec<_> = peers.values().cloned().collect();
    peer_list.sort_by(|left, right| left.device_public_key.cmp(&right.device_public_key));
    let raw = toml::to_string_pretty(&WireGuardPeersFile { peers: peer_list })?;
    fs::write(path, raw)?;
    Ok(())
}

fn allocate_peer_ip(
    peers: &HashMap<String, WireGuardPeer>,
    next_octet: &mut u8,
) -> anyhow::Result<Ipv4Addr> {
    let start = normalize_octet(*next_octet);
    for offset in 0..254u16 {
        let candidate = (((start as u16 - 1 + offset) % 254) + 1) as u8;
        let in_use = peers
            .values()
            .any(|peer| peer.peer_ip.octets()[3] == candidate);
        if !in_use {
            *next_octet = normalize_octet(candidate.saturating_add(1));
            return Ok(Ipv4Addr::new(100, 64, 1, candidate));
        }
    }

    anyhow::bail!("WireGuard peer allocation exhausted for 100.64.1.0/24")
}

fn normalize_octet(octet: u8) -> u8 {
    match octet {
        0 | 255 => 1,
        value => value.min(254),
    }
}

fn unix_timestamp_now() -> anyhow::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn unix_timestamp_after(duration: Duration) -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .saturating_add(duration)
        .as_secs())
}

/// Build a `WireGuardKeypair` from a persisted 32-byte seed file at `path`, or
/// generate a new one and write the seed if the file does not exist.
///
/// The seed is stored as raw bytes, not PEM.  Protect the file with `0600`.
pub fn load_or_generate_wg_keypair(path: &str) -> anyhow::Result<Arc<WireGuardKeypair>> {
    use std::io::ErrorKind;

    match std::fs::read(path) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                anyhow::bail!(
                    "WireGuard key file {path} has wrong length: {} (expected 32)",
                    bytes.len()
                );
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            Ok(Arc::new(WireGuardKeypair::from_secret_bytes(seed)))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let kp = WireGuardKeypair::generate();
            // Persist the 32-byte secret.
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            let secret_bytes: [u8; 32] = kp.secret.to_bytes();
            std::fs::write(path, &secret_bytes)?;
            info!(path = %path, pubkey = %kp.public_key_b64(), "Generated new WireGuard server keypair");
            Ok(Arc::new(kp))
        }
        Err(e) => Err(e.into()),
    }
}

struct WireGuardPeerTransportState {
    tunn: Tunn,
    peer_addr: Option<SocketAddr>,
    pending_recv: VecDeque<SessionFrame>,
    wg_buf: Vec<u8>,
}

#[derive(Clone)]
struct WireGuardPeerRuntime {
    device_public_key: String,
    session_id: u64,
    socket: Arc<UdpSocket>,
    state: Arc<AsyncMutex<WireGuardPeerTransportState>>,
}

struct WireGuardServerPeer {
    public_key: String,
    session_id: u64,
    runtime: Arc<WireGuardPeerRuntime>,
    forwarder: Option<Arc<SmoltcpForwarder>>,
    session_ctx: Option<Arc<SessionContext>>,
    transport_id: u64,
    tun_bridge: Option<TunBridge>,
}

impl WireGuardPeerRuntime {
    fn new(
        peer: &WireGuardPeer,
        keypair: &WireGuardKeypair,
        session_id: u64,
        socket: Arc<UdpSocket>,
    ) -> anyhow::Result<Self> {
        let peer_public_key = decode_peer_public_key(&peer.wg_public_key)?;
        let tunn = Tunn::new(
            keypair.secret.clone(),
            peer_public_key,
            None,
            Some(25),
            session_id as u32,
            None,
        );

        Ok(Self {
            device_public_key: peer.device_public_key.clone(),
            session_id,
            socket,
            state: Arc::new(AsyncMutex::new(WireGuardPeerTransportState {
                tunn,
                peer_addr: None,
                pending_recv: VecDeque::new(),
                wg_buf: vec![0u8; WG_MAX_DATAGRAM + WG_ENCAP_OVERHEAD],
            })),
        })
    }

    async fn try_accept_datagram(
        &self,
        src: SocketAddr,
        datagram: &[u8],
    ) -> anyhow::Result<Option<Vec<SessionFrame>>> {
        let (peer_addr, outbound_packets, decoded_frames) = {
            let mut guard = self.state.lock().await;
            if let Some(existing_peer_addr) = guard.peer_addr {
                if existing_peer_addr != src {
                    return Ok(None);
                }
            }

            let processed = process_datagram(&mut guard, src.ip(), datagram)?;
            let Some((outbound_packets, decoded_frames)) = processed else {
                return Ok(None);
            };

            if guard.peer_addr.is_none() {
                guard.peer_addr = Some(src);
            }

            (
                guard.peer_addr.expect("peer address set"),
                outbound_packets,
                decoded_frames,
            )
        };

        for packet in outbound_packets {
            self.socket
                .send_to(&packet, peer_addr)
                .await
                .with_context(|| format!("WireGuard: failed to send packet to {peer_addr}"))?;
        }

        Ok(Some(decoded_frames))
    }

    async fn send_frame(&self, frame: SessionFrame) -> anyhow::Result<()> {
        let (peer_addr, outbound_packets) = {
            let mut guard = self.state.lock().await;
            let peer_addr = guard.peer_addr.ok_or_else(|| {
                anyhow::anyhow!(
                    "WireGuard: peer address is not established for device {}",
                    self.device_public_key
                )
            })?;

            let mut outbound_packets: Vec<Vec<u8>> = Vec::new();
            let state = &mut *guard;

            if let TunnResult::WriteToNetwork(packet) = state.tunn.update_timers(&mut state.wg_buf)
            {
                outbound_packets.push(packet.to_vec());
            }

            let encoded = frame.encode();
            let ip_packet = wrap_in_ipv4(&encoded);
            let needed = (ip_packet.len() + WG_ENCAP_OVERHEAD).max(WG_HS_BUF);
            if state.wg_buf.len() < needed {
                state.wg_buf.resize(needed, 0);
            }

            match state.tunn.encapsulate(&ip_packet, &mut state.wg_buf) {
                TunnResult::WriteToNetwork(packet) => outbound_packets.push(packet.to_vec()),
                other => {
                    anyhow::bail!(
                        "WireGuard: failed to encapsulate response frame for session {}: {other:?}",
                        self.session_id
                    );
                }
            }

            (peer_addr, outbound_packets)
        };

        for packet in outbound_packets {
            self.socket
                .send_to(&packet, peer_addr)
                .await
                .with_context(|| format!("WireGuard: failed to send packet to {peer_addr}"))?;
        }

        Ok(())
    }
}

pub async fn run_wireguard_server(
    bind: &str,
    keypair: Arc<WireGuardKeypair>,
    peers: Arc<WireGuardPeerRegistry>,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tun_bridge: Option<TunBridge>,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    info!(bind = %bind, "wireguard udp listener bound");

    let mut datagram_buf = vec![0u8; WG_MAX_DATAGRAM + WG_ENCAP_OVERHEAD];
    let mut peer_by_source: HashMap<SocketAddr, String> = HashMap::new();
    let mut runtimes: HashMap<String, Arc<WireGuardServerPeer>> = HashMap::new();

    loop {
        let (read, source) = socket.recv_from(&mut datagram_buf).await?;
        let datagram = &datagram_buf[..read];

        let matched_peer = if let Some(device_public_key) = peer_by_source.get(&source) {
            runtimes.get(device_public_key).cloned()
        } else {
            None
        };

        let peer = if let Some(existing) = matched_peer {
            existing
        } else {
            let mut found = None;
            for registered_peer in peers.all_peers() {
                let runtime = ensure_peer_runtime(
                    &mut runtimes,
                    &registered_peer,
                    keypair.clone(),
                    socket.clone(),
                    sessions.clone(),
                    forwarders.clone(),
                    tun_bridge.clone(),
                    tunnel_pcap.clone(),
                )
                .await?;
                if runtime
                    .runtime
                    .try_accept_datagram(source, datagram)
                    .await?
                    .is_some()
                {
                    peer_by_source.insert(source, registered_peer.device_public_key.clone());
                    found = Some(runtime);
                    break;
                }
            }

            let Some(runtime) = found else {
                debug!(source = %source, bytes = read, "wireguard datagram did not match any provisioned peer");
                continue;
            };

            runtime
        };

        let Some(frames) = peer.runtime.try_accept_datagram(source, datagram).await? else {
            peer_by_source.remove(&source);
            debug!(source = %source, session_id = peer.session_id, "wireguard datagram rejected by cached peer runtime");
            continue;
        };

        peer_by_source.insert(source, peer.public_key.clone());
        handle_decoded_frames(&peer, frames, &tunnel_pcap).await;
    }
}

async fn ensure_peer_runtime(
    runtimes: &mut HashMap<String, Arc<WireGuardServerPeer>>,
    peer: &WireGuardPeer,
    keypair: Arc<WireGuardKeypair>,
    socket: Arc<UdpSocket>,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tun_bridge: Option<TunBridge>,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
) -> anyhow::Result<Arc<WireGuardServerPeer>> {
    if let Some(existing) = runtimes.get(&peer.device_public_key) {
        if sessions.contains_client(&peer.device_public_key) {
            return Ok(existing.clone());
        }

        warn!(
            public_key = %peer.device_public_key,
            session_id = existing.session_id,
            "discarding stale wireguard peer runtime with missing session registration"
        );
        runtimes.remove(&peer.device_public_key);
    }

    let handle = sessions.register_client(peer.device_public_key.clone());
    let runtime = Arc::new(WireGuardPeerRuntime::new(
        peer,
        keypair.as_ref(),
        handle.session_id,
        socket,
    )?);

    info!(
        public_key = %peer.device_public_key,
        session_id = handle.session_id,
        "wireguard peer runtime created"
    );

    let (forward_tx, mut forward_rx) = mpsc::unbounded_channel::<SessionFrame>();
    let transport_id = crate::smoltcp_forwarder::alloc_transport_id();
    // Exactly one forwarding context per session, shared by every path.
    let session_ctx: Option<Arc<SessionContext>> = if tun_bridge.is_some() {
        None
    } else {
        let ctx = {
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
        ctx.router.add_transport(transport_id, forward_tx);
        Some(ctx)
    };
    let forwarder: Option<Arc<SmoltcpForwarder>> =
        session_ctx.as_ref().map(|ctx| ctx.forwarder.clone());

    let mut tun_rx = if let Some(bridge) = &tun_bridge {
        let (tun_tx, tun_rx) = mpsc::unbounded_channel::<SessionFrame>();
        bridge.register_session(handle.session_id, tun_tx).await;
        Some(tun_rx)
    } else {
        None
    };

    let peer_context = Arc::new(WireGuardServerPeer {
        public_key: peer.device_public_key.clone(),
        session_id: handle.session_id,
        runtime: runtime.clone(),
        forwarder: forwarder.clone(),
        session_ctx: session_ctx.clone(),
        transport_id,
        tun_bridge: tun_bridge.clone(),
    });

    let peer_context_for_task = peer_context.clone();
    let forwarders_for_task = forwarders.clone();
    let sessions_for_task = sessions.clone();
    tokio::spawn(async move {
        loop {
            for _ in 0..MAX_RESPONSE_DRAIN_PER_CYCLE {
                let maybe_tun_frame = match tun_rx.as_mut() {
                    Some(tun_rx) => match tun_rx.try_recv() {
                        Ok(frame) => Some(frame),
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                    },
                    None => None,
                };
                let Some(tun_frame) = maybe_tun_frame else {
                    break;
                };

                maybe_log_tunnel_packet(&tunnel_pcap, &tun_frame.payload);
                if let Err(err) = peer_context_for_task.runtime.send_frame(tun_frame).await {
                    warn!(
                        session_id = peer_context_for_task.session_id,
                        public_key = %peer_context_for_task.public_key,
                        error = %err,
                        "failed to send drained WireGuard TUN return packet"
                    );
                    cleanup_wireguard_peer(
                        &peer_context_for_task,
                        &forwarders_for_task,
                        &sessions_for_task,
                    )
                    .await;
                    return;
                }
            }

            if peer_context_for_task.tun_bridge.is_none() {
                for _ in 0..MAX_RESPONSE_DRAIN_PER_CYCLE {
                    let maybe_forwarded_frame = match forward_rx.try_recv() {
                        Ok(frame) => Some(frame),
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                    };
                    let Some(forwarded_frame) = maybe_forwarded_frame else {
                        break;
                    };

                    maybe_log_tunnel_packet(&tunnel_pcap, &forwarded_frame.payload);
                    if let Err(err) = peer_context_for_task
                        .runtime
                        .send_frame(forwarded_frame)
                        .await
                    {
                        warn!(
                            session_id = peer_context_for_task.session_id,
                            public_key = %peer_context_for_task.public_key,
                            error = %err,
                            "failed to return drained forwarded WireGuard frame"
                        );
                        cleanup_wireguard_peer(
                            &peer_context_for_task,
                            &forwarders_for_task,
                            &sessions_for_task,
                        )
                        .await;
                        return;
                    }
                }
            }

            if let Some(tun_rx) = tun_rx.as_mut() {
                tokio::select! {
                    maybe_tun_frame = tun_rx.recv() => {
                        let Some(tun_frame) = maybe_tun_frame else {
                            warn!(
                                session_id = peer_context_for_task.session_id,
                                public_key = %peer_context_for_task.public_key,
                                "wireguard peer task ending because TUN return channel closed"
                            );
                            cleanup_wireguard_peer(&peer_context_for_task, &forwarders_for_task, &sessions_for_task).await;
                            return;
                        };

                        maybe_log_tunnel_packet(&tunnel_pcap, &tun_frame.payload);
                        if let Err(err) = peer_context_for_task.runtime.send_frame(tun_frame).await {
                            warn!(
                                session_id = peer_context_for_task.session_id,
                                public_key = %peer_context_for_task.public_key,
                                error = %err,
                                "failed to send WireGuard TUN return packet"
                            );
                            cleanup_wireguard_peer(&peer_context_for_task, &forwarders_for_task, &sessions_for_task).await;
                            return;
                        }
                    }
                    maybe_forwarded_frame = forward_rx.recv() => {
                        let Some(forwarded_frame) = maybe_forwarded_frame else {
                            warn!(
                                session_id = peer_context_for_task.session_id,
                                public_key = %peer_context_for_task.public_key,
                                "wireguard peer task ending because forward response queue closed"
                            );
                            cleanup_wireguard_peer(&peer_context_for_task, &forwarders_for_task, &sessions_for_task).await;
                            return;
                        };

                        maybe_log_tunnel_packet(&tunnel_pcap, &forwarded_frame.payload);
                        if let Err(err) = peer_context_for_task.runtime.send_frame(forwarded_frame).await {
                            warn!(
                                session_id = peer_context_for_task.session_id,
                                public_key = %peer_context_for_task.public_key,
                                error = %err,
                                "failed to return forwarded WireGuard frame"
                            );
                            cleanup_wireguard_peer(&peer_context_for_task, &forwarders_for_task, &sessions_for_task).await;
                            return;
                        }
                    }
                }
            } else {
                let Some(forwarded_frame) = forward_rx.recv().await else {
                    warn!(
                        session_id = peer_context_for_task.session_id,
                        public_key = %peer_context_for_task.public_key,
                        "wireguard peer task ending because forward response queue closed"
                    );
                    cleanup_wireguard_peer(
                        &peer_context_for_task,
                        &forwarders_for_task,
                        &sessions_for_task,
                    )
                    .await;
                    return;
                };

                maybe_log_tunnel_packet(&tunnel_pcap, &forwarded_frame.payload);
                if let Err(err) = peer_context_for_task
                    .runtime
                    .send_frame(forwarded_frame)
                    .await
                {
                    warn!(
                        session_id = peer_context_for_task.session_id,
                        public_key = %peer_context_for_task.public_key,
                        error = %err,
                        "failed to return forwarded WireGuard frame"
                    );
                    cleanup_wireguard_peer(
                        &peer_context_for_task,
                        &forwarders_for_task,
                        &sessions_for_task,
                    )
                    .await;
                    return;
                }
            }
        }
    });

    runtimes.insert(peer.device_public_key.clone(), peer_context.clone());
    Ok(peer_context)
}

async fn handle_decoded_frames(
    peer: &WireGuardServerPeer,
    frames: Vec<SessionFrame>,
    tunnel_pcap: &Option<Arc<TunnelPcapLogger>>,
) {
    for frame in frames {
        maybe_log_tunnel_packet(tunnel_pcap, &frame.payload);

        if frame.header.flags & FLAG_PING != 0 && frame.payload.is_empty() {
            info!(
                session_id = peer.session_id,
                public_key = %peer.public_key,
                sequence = frame.header.sequence,
                "wireguard heartbeat ping received, sending pong"
            );
            let pong = SessionFrame {
                header: SessionHeader {
                    connection_id: frame.header.connection_id,
                    sequence: frame.header.sequence,
                    flags: FLAG_PONG,
                },
                payload: frame.payload,
            };
            if let Err(err) = peer.runtime.send_frame(pong).await {
                warn!(
                    session_id = peer.session_id,
                    public_key = %peer.public_key,
                    error = %err,
                    "failed to send wireguard heartbeat pong"
                );
            }
            continue;
        }

        if frame.header.flags & FLAG_PING != 0 {
            warn!(
                session_id = peer.session_id,
                public_key = %peer.public_key,
                sequence = frame.header.sequence,
                flags = frame.header.flags,
                payload_len = frame.payload.len(),
                "wireguard frame has ping flag with payload; forwarding as data"
            );
        }

        if let Some(bridge) = &peer.tun_bridge {
            if let Err(err) = bridge.submit_client_frame(peer.session_id, frame) {
                warn!(
                    session_id = peer.session_id,
                    public_key = %peer.public_key,
                    error = %err,
                    "failed to enqueue WireGuard frame into TUN bridge"
                );
            }
            continue;
        }

        if let Some(forwarder) = &peer.forwarder {
            if let Some(ctx) = &peer.session_ctx {
                ctx.router.mark_active(peer.transport_id);
            }
            forwarder.ingest_packet(frame);
        }
    }
}

async fn cleanup_wireguard_peer(
    peer: &WireGuardServerPeer,
    forwarders: &ForwarderRegistry,
    sessions: &SessionRegistry,
) {
    warn!(
        session_id = peer.session_id,
        public_key = %peer.public_key,
        has_tun_bridge = peer.tun_bridge.is_some(),
        has_forwarder = peer.forwarder.is_some(),
        "cleaning up wireguard peer runtime"
    );
    if let Some(bridge) = &peer.tun_bridge {
        bridge.unregister_session(peer.session_id).await;
        sessions.unregister_client(&peer.public_key);
    }
    if let Some(ctx) = &peer.session_ctx {
        ctx.router.remove_transport(peer.transport_id);
        if ctx.router.transport_count() == 0 {
            if let Some(forwarder) = &peer.forwarder {
                forwarder.clear_session();
            }
            forwarders
                .write()
                .expect("forwarder registry lock should not be poisoned")
                .remove(&peer.session_id);
            sessions.unregister_client(&peer.public_key);
        }
    }
}

fn process_datagram(
    state: &mut WireGuardPeerTransportState,
    peer_ip: IpAddr,
    datagram: &[u8],
) -> anyhow::Result<Option<(Vec<Vec<u8>>, Vec<SessionFrame>)>> {
    let mut outbound_packets: Vec<Vec<u8>> = Vec::new();
    let mut decoded_frames: Vec<SessionFrame> = Vec::new();

    let result = state
        .tunn
        .decapsulate(Some(peer_ip), datagram, &mut state.wg_buf);
    let accepted = handle_tunn_result(result, &mut outbound_packets, &mut decoded_frames)?;
    if !accepted {
        return Ok(None);
    }

    loop {
        let result = state.tunn.decapsulate(None, &[], &mut state.wg_buf);
        let done = matches!(result, TunnResult::Done);
        let _ = handle_tunn_result(result, &mut outbound_packets, &mut decoded_frames)?;
        if done {
            break;
        }
    }

    while let Some(frame) = state.pending_recv.pop_front() {
        decoded_frames.push(frame);
    }

    Ok(Some((outbound_packets, decoded_frames)))
}

fn handle_tunn_result(
    result: TunnResult<'_>,
    outbound_packets: &mut Vec<Vec<u8>>,
    decoded_frames: &mut Vec<SessionFrame>,
) -> anyhow::Result<bool> {
    match result {
        TunnResult::Done => Ok(true),
        TunnResult::WriteToNetwork(packet) => {
            outbound_packets.push(packet.to_vec());
            Ok(true)
        }
        TunnResult::WriteToTunnelV4(ip_packet, ..) | TunnResult::WriteToTunnelV6(ip_packet, ..) => {
            match unwrap_from_ipv4(ip_packet)
                .and_then(|payload| SessionFrame::decode(payload).map_err(Into::into))
            {
                Ok(frame) => decoded_frames.push(frame),
                Err(err) => warn!(error = %err, "WireGuard: failed to decode frame"),
            }
            Ok(true)
        }
        TunnResult::Err(_) => Ok(false),
    }
}

fn decode_peer_public_key(public_key_b64: &str) -> anyhow::Result<PublicKey> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64)
        .context("invalid WireGuard peer public key base64")?;
    if decoded.len() != 32 {
        anyhow::bail!(
            "WireGuard peer public key must be 32 bytes (got {})",
            decoded.len()
        );
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(PublicKey::from(bytes))
}

fn maybe_log_tunnel_packet(tunnel_pcap: &Option<Arc<TunnelPcapLogger>>, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    if let Some(writer) = tunnel_pcap {
        writer.log_packet(payload);
    }
}

fn wrap_in_ipv4(payload: &[u8]) -> Vec<u8> {
    let total_len = IPV4_HDR_LEN + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    let total_len_bytes = (total_len as u16).to_be_bytes();
    packet[2] = total_len_bytes[0];
    packet[3] = total_len_bytes[1];
    packet[8] = 64;
    packet[9] = 253;
    packet[12..16].copy_from_slice(&WG_FAKE_SRC_IP);
    packet[16..20].copy_from_slice(&WG_FAKE_DST_IP);

    let mut checksum: u32 = 0;
    for index in (0..IPV4_HDR_LEN).step_by(2) {
        checksum += u16::from_be_bytes([packet[index], packet[index + 1]]) as u32;
    }
    while checksum >> 16 != 0 {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    let checksum = !(checksum as u16);
    packet[10] = (checksum >> 8) as u8;
    packet[11] = (checksum & 0xff) as u8;
    packet[IPV4_HDR_LEN..].copy_from_slice(payload);
    packet
}

fn unwrap_from_ipv4(ip_packet: &[u8]) -> anyhow::Result<&[u8]> {
    if ip_packet.len() < IPV4_HDR_LEN {
        anyhow::bail!(
            "WireGuard: received IP packet too short ({} bytes)",
            ip_packet.len()
        );
    }
    let ihl = ((ip_packet[0] & 0x0f) as usize) * 4;
    if ip_packet.len() < ihl {
        anyhow::bail!(
            "WireGuard: malformed IP packet (IHL={ihl} > pkt_len={})",
            ip_packet.len()
        );
    }
    Ok(&ip_packet[ihl..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonded_client::{establish_transport_paths, ClientTransport};
    use bonded_core::config::{ClientConfig, ClientSection};
    use bonded_core::transport::{Transport, WireGuardTransport};
    use bytes::Bytes;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn wireguard_peer_runtime_exchanges_frames() {
        let server_socket = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("server socket should bind"),
        );
        let server_addr = server_socket
            .local_addr()
            .expect("server addr should resolve");

        let server_keypair = WireGuardKeypair::generate();
        let client_keypair = WireGuardKeypair::generate();
        let peer = WireGuardPeer {
            device_public_key: "device-under-test".to_owned(),
            wg_public_key: client_keypair.public_key_b64(),
            peer_ip: Ipv4Addr::new(100, 64, 1, 10),
            lease_expires_at: unix_timestamp_after(Duration::from_secs(300))
                .expect("lease expiry should compute"),
        };
        let server_runtime = Arc::new(
            WireGuardPeerRuntime::new(&peer, &server_keypair, 7, server_socket.clone())
                .expect("server runtime should build"),
        );

        let server_task = {
            let server_socket = server_socket.clone();
            let server_runtime = server_runtime.clone();
            tokio::spawn(async move {
                let mut datagram_buf = vec![0u8; WG_MAX_DATAGRAM + WG_ENCAP_OVERHEAD];
                loop {
                    let (read, source) = server_socket
                        .recv_from(&mut datagram_buf)
                        .await
                        .expect("server should receive datagram");
                    let frames = server_runtime
                        .try_accept_datagram(source, &datagram_buf[..read])
                        .await
                        .expect("server should process datagram");
                    let Some(frames) = frames else {
                        continue;
                    };
                    let Some(frame) = frames.into_iter().next() else {
                        continue;
                    };

                    assert_eq!(frame.header.connection_id, 77);
                    assert_eq!(&frame.payload[..], b"wireguard-ping");

                    server_runtime
                        .send_frame(bonded_core::session::SessionFrame {
                            header: bonded_core::session::SessionHeader {
                                connection_id: frame.header.connection_id,
                                sequence: 1,
                                flags: 0,
                            },
                            payload: Bytes::from_static(b"wireguard-pong"),
                        })
                        .await
                        .expect("server should send echo response");
                    break;
                }
            })
        };

        let mut client_transport = WireGuardTransport::new(
            client_keypair,
            server_keypair.public,
            "127.0.0.1:0",
            server_addr,
            11,
            #[cfg(unix)]
            None,
        )
        .await
        .expect("client transport should build");

        client_transport
            .send(bonded_core::session::SessionFrame {
                header: bonded_core::session::SessionHeader {
                    connection_id: 77,
                    sequence: 0,
                    flags: 0,
                },
                payload: Bytes::from_static(b"wireguard-ping"),
            })
            .await
            .expect("client should send frame");

        let echoed = client_transport
            .recv()
            .await
            .expect("client should receive echoed frame");
        assert_eq!(echoed.header.sequence, 1);
        assert_eq!(&echoed.payload[..], b"wireguard-pong");

        server_task.await.expect("server task should join");
    }

    #[tokio::test]
    async fn wireguard_bootstrap_provisions_and_dials_transport() {
        let registry = Arc::new(WireGuardPeerRegistry::new());
        let server_keypair = Arc::new(WireGuardKeypair::generate());

        let udp_socket = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("udp socket should bind"),
        );
        let udp_addr = udp_socket.local_addr().expect("udp addr should resolve");

        let bootstrap_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bootstrap listener should bind");
        let bootstrap_addr = bootstrap_listener
            .local_addr()
            .expect("bootstrap addr should resolve");

        let bootstrap_registry = registry.clone();
        let bootstrap_keypair = server_keypair.clone();
        let bootstrap_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = bootstrap_listener
                    .accept()
                    .await
                    .expect("bootstrap accept should succeed");
                let mut raw = vec![0u8; 4096];
                let read = stream
                    .read(&mut raw)
                    .await
                    .expect("bootstrap request should read");
                let request = String::from_utf8(raw[..read].to_vec())
                    .expect("bootstrap request should be utf8");
                let (headers, body) = request
                    .split_once("\r\n\r\n")
                    .expect("request should contain separator");
                let request_line = headers.lines().next().expect("request line should exist");

                let response_body = if request_line.starts_with("GET /v1/bootstrap/capabilities ") {
                    serde_json::json!({
                        "transports": ["wss", "wireguard"],
                        "wss": { "endpoint": bootstrap_addr.to_string() },
                        "wireguard": {
                            "endpoint": udp_addr.to_string(),
                            "provision_endpoint": format!("http://{}/v1/bootstrap/wireguard/peer", bootstrap_addr),
                            "server_public_key": bootstrap_keypair.public_key_b64(),
                        }
                    })
                    .to_string()
                } else if request_line.starts_with("POST /v1/bootstrap/wireguard/peer ") {
                    let value: serde_json::Value = serde_json::from_str(body.trim())
                        .expect("wireguard peer request should parse");
                    let device_public_key = value["device_public_key"]
                        .as_str()
                        .expect("device_public_key should exist");
                    let wg_public_key = value["wg_public_key"]
                        .as_str()
                        .expect("wg_public_key should exist");
                    let peer_ip =
                        bootstrap_registry.register_peer(device_public_key, wg_public_key);
                    serde_json::json!({
                        "server_wg_public_key": bootstrap_keypair.public_key_b64(),
                        "peer_ip": peer_ip,
                    })
                    .to_string()
                } else {
                    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .expect("404 should write");
                    continue;
                };

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body,
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("bootstrap response should write");
            }
        });

        let server_registry = registry.clone();
        let server_socket = udp_socket.clone();
        let server_keypair_for_task = server_keypair.clone();
        let wireguard_task = tokio::spawn(async move {
            let mut datagram_buf = vec![0u8; WG_MAX_DATAGRAM + WG_ENCAP_OVERHEAD];
            let mut runtime: Option<Arc<WireGuardPeerRuntime>> = None;
            loop {
                let (read, source) = server_socket
                    .recv_from(&mut datagram_buf)
                    .await
                    .expect("wireguard server should receive datagram");

                if runtime.is_none() {
                    for peer in server_registry.all_peers() {
                        let candidate = Arc::new(
                            WireGuardPeerRuntime::new(
                                &peer,
                                &server_keypair_for_task,
                                19,
                                server_socket.clone(),
                            )
                            .expect("wireguard runtime should build"),
                        );
                        if candidate
                            .try_accept_datagram(source, &datagram_buf[..read])
                            .await
                            .expect("initial wireguard datagram should process")
                            .is_some()
                        {
                            runtime = Some(candidate);
                            break;
                        }
                    }
                    continue;
                }

                let frames = runtime
                    .as_ref()
                    .expect("runtime should exist")
                    .try_accept_datagram(source, &datagram_buf[..read])
                    .await
                    .expect("wireguard datagram should process")
                    .expect("datagram should belong to provisioned peer");
                let Some(frame) = frames.into_iter().next() else {
                    continue;
                };

                runtime
                    .as_ref()
                    .expect("runtime should exist")
                    .send_frame(bonded_core::session::SessionFrame {
                        header: bonded_core::session::SessionHeader {
                            connection_id: frame.header.connection_id,
                            sequence: 1,
                            flags: 0,
                        },
                        payload: Bytes::from_static(b"bootstrap-wireguard-pong"),
                    })
                    .await
                    .expect("wireguard echo should send");
                break;
            }
        });

        let cfg = ClientConfig {
            client: ClientSection {
                device_name: "wg-bootstrap-test".to_owned(),
                tun_name: "bondedwg-test".to_owned(),
                server_public_address: bootstrap_addr.to_string(),
                server_websocket_address: format!("ws://{bootstrap_addr}"),
                preferred_protocols: vec!["wireguard".to_owned()],
                private_key_path: temp_test_file("wg-bootstrap-private")
                    .to_string_lossy()
                    .to_string(),
                public_key_path: temp_test_file("wg-bootstrap-public")
                    .to_string_lossy()
                    .to_string(),
                ..ClientSection::default()
            },
            socket_protect: None,
            socket_network_bind: None,
        };

        let mut paths = establish_transport_paths(&cfg, 1)
            .await
            .expect("wireguard path should establish via bootstrap");
        assert_eq!(paths.len(), 1);
        assert!(matches!(paths[0], ClientTransport::WireGuard(_)));

        paths[0]
            .send(bonded_core::session::SessionFrame {
                header: bonded_core::session::SessionHeader {
                    connection_id: 91,
                    sequence: 0,
                    flags: 0,
                },
                payload: Bytes::from_static(b"bootstrap-wireguard-ping"),
            })
            .await
            .expect("wireguard frame should send");
        let echoed = paths[0]
            .recv()
            .await
            .expect("wireguard echoed frame should arrive");
        assert_eq!(&echoed.payload[..], b"bootstrap-wireguard-pong");

        wireguard_task.await.expect("wireguard task should join");
        bootstrap_task.abort();
        let _ = fs::remove_file(&cfg.client.private_key_path);
        let _ = fs::remove_file(&cfg.client.public_key_path);
    }

    #[tokio::test]
    async fn stale_runtime_is_recreated_after_session_cleanup() {
        let mut runtimes = HashMap::new();
        let peer = WireGuardPeer {
            device_public_key: "stale-device".to_owned(),
            wg_public_key: WireGuardKeypair::generate().public_key_b64(),
            peer_ip: Ipv4Addr::new(100, 64, 1, 20),
            lease_expires_at: unix_timestamp_after(Duration::from_secs(300))
                .expect("lease expiry should compute"),
        };
        let keypair = Arc::new(WireGuardKeypair::generate());
        let socket = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("udp socket should bind"),
        );
        let sessions = SessionRegistry::default();
        let forwarders: ForwarderRegistry = Arc::new(RwLock::new(HashMap::new()));

        let first = ensure_peer_runtime(
            &mut runtimes,
            &peer,
            keypair.clone(),
            socket.clone(),
            sessions.clone(),
            forwarders.clone(),
            None,
            None,
        )
        .await
        .expect("first runtime should be created");
        assert!(sessions.contains_client(&peer.device_public_key));

        cleanup_wireguard_peer(&first, &forwarders, &sessions).await;
        assert!(!sessions.contains_client(&peer.device_public_key));

        let recreated = ensure_peer_runtime(
            &mut runtimes,
            &peer,
            keypair,
            socket,
            sessions.clone(),
            forwarders,
            None,
            None,
        )
        .await
        .expect("stale runtime should be recreated");

        assert!(sessions.contains_client(&peer.device_public_key));
        assert_ne!(first.session_id, recreated.session_id);
    }

    #[tokio::test]
    async fn peer_runtime_without_tun_bridge_stays_registered() {
        let mut runtimes = HashMap::new();
        let peer = WireGuardPeer {
            device_public_key: "forwarder-device".to_owned(),
            wg_public_key: WireGuardKeypair::generate().public_key_b64(),
            peer_ip: Ipv4Addr::new(100, 64, 1, 21),
            lease_expires_at: unix_timestamp_after(Duration::from_secs(300))
                .expect("lease expiry should compute"),
        };
        let keypair = Arc::new(WireGuardKeypair::generate());
        let socket = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("udp socket should bind"),
        );
        let sessions = SessionRegistry::default();
        let forwarders: ForwarderRegistry = Arc::new(RwLock::new(HashMap::new()));

        let runtime = ensure_peer_runtime(
            &mut runtimes,
            &peer,
            keypair,
            socket,
            sessions.clone(),
            forwarders,
            None,
            None,
        )
        .await
        .expect("runtime should be created without tun bridge");

        for _ in 0..3 {
            tokio::task::yield_now().await;
        }

        assert!(sessions.contains_client(&peer.device_public_key));
        assert_eq!(runtime.session_id, 0);
    }

    #[test]
    fn persisted_registry_keeps_same_ip_and_updates_wg_key() {
        let path = temp_test_file("wg-peer-registry");
        let registry =
            WireGuardPeerRegistry::load(&path).expect("registry should load from missing path");

        let first_key = WireGuardKeypair::generate().public_key_b64();
        let second_key = WireGuardKeypair::generate().public_key_b64();
        let first_ip = registry.register_peer("persisted-device", &first_key);
        let second_ip = registry.register_peer("persisted-device", &second_key);

        assert_eq!(first_ip, second_ip);

        let reloaded = WireGuardPeerRegistry::load(&path).expect("registry should reload");
        let peer = reloaded
            .find_by_wg_key(&second_key)
            .expect("reloaded registry should contain rotated wg key");
        assert_eq!(peer.device_public_key, "persisted-device");
        assert_eq!(format!("{}/32", peer.peer_ip), first_ip);
        assert!(reloaded.find_by_wg_key(&first_key).is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn expired_peers_are_pruned_and_ips_can_be_reused() {
        let path = temp_test_file("wg-peer-expiry");
        fs::write(
            &path,
            r#"[[peers]]
device_public_key = "expired-device"
wg_public_key = "expired-wg"
peer_ip = "100.64.1.7"
lease_expires_at = 1
"#,
        )
        .expect("expired peer state should write");

        let registry = WireGuardPeerRegistry::load_with_lease(&path, Duration::from_secs(60))
            .expect("registry should load and prune expired peers");
        assert!(registry.all_peers().is_empty());

        let assigned = registry.register_peer(
            "fresh-device",
            &WireGuardKeypair::generate().public_key_b64(),
        );
        assert_eq!(assigned, "100.64.1.1/32");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn persisted_legacy_peers_are_normalized_with_new_lease() {
        let path = temp_test_file("wg-peer-legacy");
        fs::write(
            &path,
            r#"[[peers]]
device_public_key = "legacy-device"
wg_public_key = "legacy-wg"
peer_ip = "100.64.1.9"
"#,
        )
        .expect("legacy peer state should write");

        let registry = WireGuardPeerRegistry::load_with_lease(&path, Duration::from_secs(60))
            .expect("registry should load legacy peer state");
        let peer = registry
            .all_peers()
            .into_iter()
            .next()
            .expect("legacy peer should remain active");
        assert!(peer.lease_expires_at > unix_timestamp_now().expect("current time should compute"));

        let _ = fs::remove_file(path);
    }

    fn temp_test_file(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("bonded-wireguard-{name}-{stamp}.pem"))
    }
}
