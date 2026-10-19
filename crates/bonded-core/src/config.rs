use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

pub const DEFAULT_SERVER_CONFIG_PATH: &str = "/etc/bonded/server.toml";
pub const DEFAULT_AUTHORIZED_KEYS_PATH: &str = "/var/lib/bonded/authorized_keys.toml";
pub const DEFAULT_INVITE_TOKENS_PATH: &str = "/var/lib/bonded/invite_tokens.toml";
pub const DEFAULT_SERVER_IDENTITY_KEY_PATH: &str = "/var/lib/bonded/server-identity.pem";
pub const DEFAULT_WIREGUARD_PEERS_PATH: &str = "/var/lib/bonded/wireguard_peers.toml";
pub const DEFAULT_WIREGUARD_PEER_LEASE_SECS: u64 = 30 * 24 * 60 * 60;

pub const DEFAULT_CLIENT_CONFIG_PATH: &str = "~/.config/bonded/client.toml";
pub const DEFAULT_CLIENT_PRIVATE_KEY_PATH: &str = "~/.local/share/bonded/device-key.pem";
pub const DEFAULT_CLIENT_PUBLIC_KEY_PATH: &str = "~/.local/share/bonded/device-key.pub";

/// Transport kind identifier for diagnostics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    NaiveTcp,
    WebSocketTls,
}

impl TransportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TransportKind::NaiveTcp => "NaiveTCP",
            TransportKind::WebSocketTls => "WebSocketTLS",
        }
    }
}

/// Callback called with a raw socket file-descriptor just before the socket
/// connects.  On Android this is used to call `VpnService.protect(fd)` so
/// that the tunnel session's own TCP connections bypass the VPN routing table
/// and avoid a routing loop.
#[derive(Clone)]
pub struct SocketProtectFn(pub Arc<dyn Fn(i32) -> bool + Send + Sync>);

/// Callback called with a raw socket file-descriptor plus the selected local
/// bind address just before the socket connects. On Android this is used to
/// bind the socket to the specific `Network` that owns that address so a
/// cellular path does not silently follow the default Wi-Fi route.
#[derive(Clone)]
pub struct SocketNetworkBindFn(pub Arc<dyn Fn(i32, &str) -> bool + Send + Sync>);

impl std::fmt::Debug for SocketProtectFn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SocketProtectFn(..)")
    }
}

impl std::fmt::Debug for SocketNetworkBindFn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SocketNetworkBindFn(..)")
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse TOML config: {0}")]
    Toml(#[from] toml::de::Error),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub server: ServerSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerSection {
    /// Public hostname of the server (no port), used to build QR-code pairing
    /// URLs and reported in the capabilities endpoint.
    pub hostname: String,

    // ── HTTPS / WSS / QUIC ───────────────────────────────────────────────────
    /// Local address to bind the HTTPS/WSS/QUIC listener (TCP + UDP).
    /// Default: `0.0.0.0:443`.
    pub https_bind: String,
    /// Public port for HTTPS/WSS connections.  Combined with `hostname` to
    /// form the advertised endpoint.  Default: `443`.
    pub https_public: u16,
    /// Path to the PEM TLS certificate chain.  Empty = TLS disabled (plain
    /// HTTP/WS only, no QUIC).  If `acme_domain` is set, ACME writes the
    /// renewed certificate here.
    pub tls_cert_file: String,
    /// Path to the PEM TLS private key.  Empty = TLS disabled.  ACME writes
    /// the renewed key here.
    pub tls_key_file: String,

    // ── WireGuard ────────────────────────────────────────────────────────────
    /// Local UDP address to bind the WireGuard listener (e.g.
    /// `"0.0.0.0:51820"`).  When set, the WireGuard endpoint is enabled.
    #[serde(default)]
    pub wireguard_bind: Option<String>,
    /// Public UDP port clients should use to reach the WireGuard endpoint.
    /// Combined with `hostname` in the capabilities response.  Required when
    /// `wireguard_bind` is set.
    #[serde(default)]
    pub wireguard_public: Option<u16>,
    /// Path to the 32-byte WireGuard private key seed file.  Generated
    /// automatically on first boot when `wireguard_bind` is set.
    #[serde(default)]
    pub wireguard_key_file: Option<String>,
    /// Path to the persisted WireGuard peer allocation state. When set, peer
    /// IP assignments survive server restart and existing devices keep the
    /// same `/32` allocation across re-provisioning.
    #[serde(default)]
    pub wireguard_peers_file: Option<String>,
    /// Lease duration for a provisioned WireGuard peer assignment. Expired
    /// peers are pruned and their `/32` can be reused by a future bootstrap.
    pub wireguard_peer_lease_secs: u64,

    // ── Debug NaiveTCP ───────────────────────────────────────────────────────
    /// Local address for the unencrypted NaiveTCP listener (debug/testing
    /// only).  Not started when unset.
    #[serde(default)]
    pub tcp_bind: Option<String>,
    /// Public port for the NaiveTCP endpoint.
    #[serde(default)]
    pub tcp_public: Option<u16>,

    // ── Infrastructure ───────────────────────────────────────────────────────
    pub status_bind: String,
    pub health_bind: String,
    pub log_level: String,
    pub forwarding_mode: String,
    pub tun_name: String,
    pub tun_cidr: String,
    pub tun_mtu: u16,
    pub tun_egress_interface: String,
    pub authorized_keys_file: String,
    pub invite_tokens_file: String,
    /// Path where the server's stable ed25519 identity key is persisted.
    /// Created automatically on first boot; must not change after pairing QR
    /// codes are issued.
    pub identity_key_file: String,

    // ── ACME ─────────────────────────────────────────────────────────────────
    /// Domain for ACME TLS-ALPN-01 certificate automation (e.g.
    /// `"vpn.example.com"`).  When set, the server manages TLS certs via
    /// Let's Encrypt.  Requires the server to be directly reachable on
    /// `https_bind` (port 443 by default).
    #[serde(default)]
    pub acme_domain: Option<String>,
    /// Contact e-mail sent to Let's Encrypt.  Required when `acme_domain` is
    /// set.
    #[serde(default)]
    pub acme_email: Option<String>,
    /// Use the Let's Encrypt staging environment (recommended for testing).
    #[serde(default)]
    pub acme_staging: bool,
}

impl ServerSection {
    /// Returns the public HTTPS endpoint string (`hostname:https_public`),
    /// used in pairing QR codes and the capabilities response.
    pub fn https_public_addr(&self) -> String {
        format!("{}:{}", self.hostname, self.https_public)
    }

    /// Returns the public WireGuard endpoint string (`hostname:port`), or
    /// `None` when WireGuard is not configured.
    pub fn wireguard_public_addr(&self) -> Option<String> {
        let port = self.wireguard_public?;
        Some(format!("{}:{}", self.hostname, port))
    }
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            hostname: String::new(),
            https_bind: "0.0.0.0:443".to_owned(),
            https_public: 443,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            wireguard_bind: None,
            wireguard_public: None,
            wireguard_key_file: None,
            wireguard_peers_file: None,
            wireguard_peer_lease_secs: DEFAULT_WIREGUARD_PEER_LEASE_SECS,
            tcp_bind: None,
            tcp_public: None,
            status_bind: "0.0.0.0:8082".to_owned(),
            health_bind: "0.0.0.0:8081".to_owned(),
            log_level: "info".to_owned(),
            forwarding_mode: "proxy".to_owned(),
            tun_name: "bonded0".to_owned(),
            tun_cidr: "100.64.0.1/24".to_owned(),
            tun_mtu: 1420,
            tun_egress_interface: String::new(),
            authorized_keys_file: DEFAULT_AUTHORIZED_KEYS_PATH.to_owned(),
            invite_tokens_file: DEFAULT_INVITE_TOKENS_PATH.to_owned(),
            identity_key_file: DEFAULT_SERVER_IDENTITY_KEY_PATH.to_owned(),
            acme_domain: None,
            acme_email: None,
            acme_staging: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client: ClientSection,
    /// Not serialised – set at runtime on platforms that require socket
    /// protection (e.g. Android VPN services).
    #[serde(skip)]
    pub socket_protect: Option<SocketProtectFn>,
    /// Not serialised – set at runtime on Android so sockets can be bound to
    /// the specific `Network` that owns a chosen bind address.
    #[serde(skip)]
    pub socket_network_bind: Option<SocketNetworkBindFn>,
}

/// Peer-share role mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerShareMode {
    #[default]
    Both,
    ProviderOnly,
    ConsumerOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSection {
    pub device_name: String,
    pub tun_name: String,
    pub server_public_address: String,
    /// Optional pre-resolved host:port dial target used when DNS must happen
    /// before the VPN is active. TLS and HTTP identity still come from
    /// `server_public_address` / `server_websocket_address`.
    #[serde(default)]
    pub server_resolved_address: String,
    /// Deprecated: use `server_public_address` (the bootstrap port serves both
    /// WSS and HTTPS).  Kept for backward compatibility; takes precedence over
    /// `server_public_address` for WebSocket connections when non-empty.
    #[serde(default)]
    pub server_websocket_address: String,
    pub path_bind_addresses: Vec<String>,
    pub server_public_key: String,
    pub invite_token: String,
    pub preferred_protocols: Vec<String>,
    /// Explicit opt-in for insecure debug transports such as NaiveTCP.
    /// Production configs must leave this disabled.
    #[serde(default)]
    pub allow_insecure_debug_transports: bool,
    pub private_key_path: String,
    pub public_key_path: String,
    /// Pinned SHA-256 fingerprint of the server TLS leaf certificate
    /// (`"sha256:<hex>"`).  Empty string means no pin stored yet; the client
    /// will fetch and verify a cert-proof on the next connection and then
    /// persist the fingerprint here.  When non-empty the fingerprint is checked
    /// against the cert presented by the server; a mismatch triggers a
    /// re-proof rather than a hard failure (handles cert rotation).
    #[serde(default)]
    pub tls_cert_fingerprint: String,
    /// Server's WireGuard X25519 public key (base64), provisioned from
    /// `/v1/bootstrap/wireguard/peer` during pairing.
    #[serde(default)]
    pub wireguard_server_public_key: String,
    #[serde(default)]
    pub peer_share_enabled: bool,
    #[serde(default)]
    pub peer_share_mode: PeerShareMode,
    #[serde(default)]
    pub peer_share_bind_address: String,
    #[serde(default)]
    pub peer_share_advertise_ip: String,
    /// Maximum number of concurrent peer-share consumers this device will
    /// relay for. Additional consumers are rejected at accept time.
    #[serde(default = "default_peer_share_max_consumers")]
    pub peer_share_max_consumers: u32,
    /// Bandwidth cap per peer relay in kilobits per second. 0 = unlimited.
    #[serde(default)]
    pub peer_share_relay_bandwidth_kbps: u64,
    /// Periodically upload the on-device diagnostic log to the server
    /// (signed with the device key). Opt-in; off by default.
    #[serde(default)]
    pub diagnostics_upload_enabled: bool,
    /// Diagnostics upload cadence in seconds (clamped to 60–3600 at
    /// use). Defaults to 900.
    #[serde(default = "default_diagnostics_upload_period_secs")]
    pub diagnostics_upload_period_secs: u64,
}

fn default_diagnostics_upload_period_secs() -> u64 {
    crate::diagnostics::DEFAULT_DIAGNOSTICS_PERIOD_SECS
}

fn default_peer_share_max_consumers() -> u32 {
    4
}

impl Default for ClientSection {
    fn default() -> Self {
        Self {
            device_name: "linux-cli".to_owned(),
            tun_name: "bonded0".to_owned(),
            server_public_address: String::new(),
            server_resolved_address: String::new(),
            server_websocket_address: String::new(),
            path_bind_addresses: Vec::new(),
            server_public_key: String::new(),
            invite_token: String::new(),
            preferred_protocols: vec!["wss".to_owned(), "h3".to_owned(), "wireguard".to_owned()],
            allow_insecure_debug_transports: false,
            private_key_path: DEFAULT_CLIENT_PRIVATE_KEY_PATH.to_owned(),
            public_key_path: DEFAULT_CLIENT_PUBLIC_KEY_PATH.to_owned(),
            tls_cert_fingerprint: String::new(),
            wireguard_server_public_key: String::new(),
            peer_share_enabled: false,
            peer_share_mode: PeerShareMode::Both,
            peer_share_bind_address: "0.0.0.0:54443".to_owned(),
            peer_share_advertise_ip: String::new(),
            peer_share_max_consumers: default_peer_share_max_consumers(),
            peer_share_relay_bandwidth_kbps: 0,
            diagnostics_upload_enabled: false,
            diagnostics_upload_period_secs: default_diagnostics_upload_period_secs(),
        }
    }
}

pub fn load_server_config(path: &Path) -> Result<ServerConfig, ConfigError> {
    let data = fs::read_to_string(path)?;
    Ok(toml::from_str(&data)?)
}

pub fn load_client_config(path: &Path) -> Result<ClientConfig, ConfigError> {
    let data = fs::read_to_string(path)?;
    Ok(toml::from_str(&data)?)
}

#[cfg(test)]
mod tests {
    use super::{ClientConfig, ServerConfig};

    #[test]
    fn default_server_config_has_expected_values() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.server.https_bind, "0.0.0.0:443");
        assert_eq!(cfg.server.https_public, 443);
        assert_eq!(cfg.server.status_bind, "0.0.0.0:8082");
        assert_eq!(cfg.server.forwarding_mode, "proxy");
        assert_eq!(cfg.server.tun_name, "bonded0");
        assert_eq!(cfg.server.tun_cidr, "100.64.0.1/24");
        assert_eq!(cfg.server.tun_mtu, 1420);
        assert!(cfg.server.tun_egress_interface.is_empty());
        assert!(cfg.server.tls_cert_file.is_empty());
        assert!(cfg.server.tls_key_file.is_empty());
        assert!(cfg.server.wireguard_bind.is_none());
        assert!(cfg.server.tcp_bind.is_none());
    }

    #[test]
    fn server_config_parses_with_missing_options_using_defaults() {
        let cfg: ServerConfig = toml::from_str(
            r#"
[server]
https_bind = "127.0.0.1:9000"
"#,
        )
        .expect("partial server config should parse");

        assert_eq!(cfg.server.https_bind, "127.0.0.1:9000");
        assert_eq!(cfg.server.https_public, 443);
        assert_eq!(cfg.server.status_bind, "0.0.0.0:8082");
        assert_eq!(cfg.server.forwarding_mode, "proxy");
        assert_eq!(cfg.server.tun_name, "bonded0");
        assert_eq!(cfg.server.tun_cidr, "100.64.0.1/24");
        assert_eq!(cfg.server.tun_mtu, 1420);
        assert!(cfg.server.tun_egress_interface.is_empty());
        assert_eq!(cfg.server.health_bind, "0.0.0.0:8081");
        assert_eq!(cfg.server.log_level, "info");
    }

    #[test]
    fn server_config_parses_without_server_section_using_defaults() {
        let cfg: ServerConfig = toml::from_str("").expect("empty config should parse");
        let defaults = ServerConfig::default();
        assert_eq!(cfg.server.https_bind, defaults.server.https_bind);
        assert_eq!(cfg.server.https_public, defaults.server.https_public);
        assert_eq!(cfg.server.status_bind, defaults.server.status_bind);
        assert_eq!(cfg.server.health_bind, defaults.server.health_bind);
    }

    #[test]
    fn https_public_addr_combines_hostname_and_port() {
        let mut cfg = ServerConfig::default();
        cfg.server.hostname = "vpn.example.com".to_owned();
        cfg.server.https_public = 8443;
        assert_eq!(cfg.server.https_public_addr(), "vpn.example.com:8443");
    }

    #[test]
    fn wireguard_public_addr_returns_none_when_unconfigured() {
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
    fn client_defaults_exclude_insecure_debug_transports() {
        let cfg = ClientConfig::default();
        assert_eq!(
            cfg.client.preferred_protocols,
            vec!["wss", "h3", "wireguard"]
        );
        assert!(!cfg.client.allow_insecure_debug_transports);
        assert!(!cfg.client.peer_share_enabled);
        assert_eq!(cfg.client.peer_share_bind_address, "0.0.0.0:54443");
    }
}
