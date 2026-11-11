use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::session::{
    SessionFrame, SessionHeader, FLAG_PEER_DIAL_BACK, FLAG_PEER_RELAY_REGISTRATION,
};

const TXT_VERSION_KEY: &str = "version";
const TXT_DEVICE_KEY: &str = "device_key";
const TXT_SERVER_KEY: &str = "server_key";
const TXT_INSTANCE_NONCE_KEY: &str = "instance_nonce";
const TXT_ENDPOINT_KEY: &str = "endpoint";
const TXT_ENDPOINTS_KEY: &str = "endpoints";
const TXT_CAPABILITIES_KEY: &str = "capabilities";
const TXT_CERT_FINGERPRINT_KEY: &str = "cert_fingerprint";

/// Whether an address may be advertised as a peer-share endpoint: it
/// must be in a non-routable/private block — 10.0.0.0/8, 172.16.0.0/12,
/// 192.168.0.0/16, or link-local 169.254.0.0/16. A LAN peer can only
/// dial addresses on a local network, so a public address (notably the
/// cellular address, e.g. 192.0.0.4) must never leak into an
/// advertisement — a consumer reading only the mDNS A record would
/// dial an unreachable address. The check is on the address itself,
/// not the interface name: interface naming varies by vendor
/// (Qualcomm `rmnet*`, MediaTek `ccmni*`, `v4-rmnet1`, …) and a
/// prefix list misses new names. A carrier-assigned private address
/// on a cellular interface rides along (accepted: that edge case is
/// out of scope). IPv6 addresses are not advertised. This is the one
/// shared definition: the provider's advertisement builder and the
/// mDNS consumer's record selection both filter through it, so no
/// path can reintroduce a public address into an advertisement. (The
/// dial path deliberately does NOT filter: the allow-list governs
/// what may be advertised, not what may be dialed — loopback
/// listeners are legitimate dial targets.)
pub fn is_advertisable_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 10
                || (octets[0] == 172 && (octets[1] & 0xf0) == 0x10)
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 169 && octets[1] == 254)
        }
        IpAddr::V6(_) => false,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerShareIntroductionRequest {
    pub consumer_device_public_key: String,
    pub provider_device_public_key: String,
    pub provider_instance_nonce: String,
    pub provider_endpoint: String,
    pub listener_transport: String,
    pub listener_cert_fingerprint: String,
    pub consumer_signature: String,
    /// Reverse dial (4.56): when true, the consumer asks the server to
    /// mint a reversed introduction and push a dial-back notification
    /// to the provider's live session. Defaults off, so old requests
    /// (and old servers, which ignore unknown JSON fields) behave
    /// exactly as before.
    #[serde(default)]
    pub dial_back: bool,
    /// Endpoints the provider should dial the consumer on, in order:
    /// the consumer's own advertised addresses (4.55 list, same port
    /// as its peer listener). Only meaningful with `dial_back`.
    #[serde(default)]
    pub consumer_endpoints: Vec<String>,
    /// Cert fingerprint of the consumer's own peer listener, which the
    /// reversed introduction carries as `listener_cert_fingerprint`
    /// (the consumer is the listener on a reversed leg). Only
    /// meaningful with `dial_back`; the server rejects a dial-back
    /// request without it.
    #[serde(default)]
    pub consumer_listener_cert_fingerprint: String,
}

fn default_claims_direction() -> String {
    "forward".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerShareIntroductionClaims {
    pub consumer_device_public_key: String,
    pub provider_device_public_key: String,
    pub provider_instance_nonce: String,
    pub provider_endpoint: String,
    pub listener_transport: String,
    pub listener_cert_fingerprint: String,
    pub expires_at: u64,
    /// Which leg this introduction authorizes (4.56): `"forward"` —
    /// the consumer dials the provider's listener (all introductions
    /// minted before 4.56, which carry no such field, parse as
    /// forward); `"reverse"` — the provider dials the consumer's
    /// listener. The direction is part of the server-signed claims,
    /// so a reversed introduction cannot be replayed as a forward
    /// one: both verifiers check it. On a reversed introduction
    /// `listener_cert_fingerprint` is the CONSUMER's listener cert
    /// (the consumer is the listener) and `consumer_endpoints` holds
    /// the addresses the provider should dial, in order;
    /// `provider_endpoint` still names the provider's listener
    /// endpoint and identifies the pair.
    #[serde(default = "default_claims_direction")]
    pub direction: String,
    /// Dialable addresses for the listener on a reversed leg; empty
    /// on a forward introduction (the consumer dials the provider's
    /// `provider_endpoint` there).
    #[serde(default)]
    pub consumer_endpoints: Vec<String>,
}

impl PeerShareIntroductionClaims {
    /// Whether this introduction authorizes a provider-initiated
    /// (reversed) leg rather than a consumer-initiated one.
    pub fn is_reverse(&self) -> bool {
        self.direction == "reverse"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPeerShareIntroduction {
    pub introduction: PeerShareIntroductionClaims,
    pub server_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRelayRegistration {
    pub introduction: SignedPeerShareIntroduction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerShareAdvertisement {
    pub version: u16,
    pub device_public_key: String,
    pub server_public_key: String,
    pub instance_nonce: String,
    /// Primary endpoint (the first of `endpoints`): the single address
    /// old single-endpoint readers use, and the address the mDNS
    /// service record itself carries.
    pub endpoint: String,
    /// Every dialable address this provider listens on (same port),
    /// primary first. A consumer tries them in order until one
    /// connects. Old advertisements have no such record and parse as
    /// a one-element list holding `endpoint`.
    #[serde(default)]
    pub endpoints: Vec<String>,
    pub listener_cert_fingerprint: String,
    pub capabilities: Vec<String>,
}

impl PeerShareIntroductionRequest {
    /// The bytes the consumer signs. Covers ONLY the original six
    /// fields, deliberately NOT the dial-back fields (4.56): an old
    /// server verifies with its own six-field payload, so a new
    /// client signing an extended payload would fail verification
    /// against it. The dial-back fields ride inside the TLS-protected
    /// bootstrap request and the server only acts on them after the
    /// signature over the core fields verifies; a flipped flag or
    /// endpoint list cannot yield a usable leg, because the
    /// provider's dial (4.57) verifies the server-signed reversed
    /// introduction's listener cert fingerprint before sending
    /// anything sensitive.
    pub fn signed_payload(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(&serde_json::json!({
            "consumer_device_public_key": self.consumer_device_public_key,
            "provider_device_public_key": self.provider_device_public_key,
            "provider_instance_nonce": self.provider_instance_nonce,
            "provider_endpoint": self.provider_endpoint,
            "listener_transport": self.listener_transport,
            "listener_cert_fingerprint": self.listener_cert_fingerprint,
        }))?)
    }
}

impl PeerShareIntroductionClaims {
    pub fn signing_payload(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }
}

impl PeerShareAdvertisement {
    /// (Re)build the endpoint fields from an IP list and port: `endpoint`
    /// is the primary (first) address for old single-endpoint readers,
    /// `endpoints` is the full list in dial order. Non-advertisable
    /// addresses (see `is_advertisable_ip`) are dropped here — this is
    /// the last line of defence, so no caller, pinned config value
    /// included, can put a public address into an advertisement. A list
    /// that filters to empty leaves `endpoint` empty, which fails
    /// loudly at mDNS registration instead of advertising an
    /// unreachable address.
    pub fn set_endpoints(&mut self, ips: &[IpAddr], port: u16) {
        let endpoints: Vec<String> = ips
            .iter()
            .filter(|ip| is_advertisable_ip(ip))
            .map(|ip| SocketAddr::new(*ip, port).to_string())
            .collect();
        self.endpoint = endpoints.first().cloned().unwrap_or_default();
        self.endpoints = endpoints;
    }

    /// Drop every non-advertisable address from an advertisement
    /// received over the wire (mDNS TXT records are untrusted input:
    /// an old or misconfigured provider can advertise a public
    /// cellular address). `endpoint` is reset to the first surviving
    /// entry so the primary and the list never disagree. Returns
    /// whether any usable address remains; false means the
    /// advertisement names nothing this consumer can dial.
    pub fn sanitize_advertised_endpoints(&mut self) -> bool {
        self.endpoints.retain(|endpoint| {
            endpoint
                .parse::<SocketAddr>()
                .map(|addr| is_advertisable_ip(&addr.ip()))
                .unwrap_or(false)
        });
        self.endpoint = self.endpoints.first().cloned().unwrap_or_default();
        !self.endpoints.is_empty()
    }

    /// Dialable addresses in order: the full advertised list, or the
    /// single primary endpoint for old advertisements without a list.
    /// Unparseable entries are skipped; an empty result means the
    /// advertisement carries no usable address at all. Public
    /// addresses are dropped even when the advertisement lists them:
    /// a consumer must never burn a dial timeout on an address it
    /// cannot reach.
    pub fn endpoint_addrs(&self) -> Vec<SocketAddr> {
        let addrs: Vec<SocketAddr> = self
            .endpoints
            .iter()
            .filter_map(|endpoint| endpoint.parse().ok())
            .filter(|addr: &SocketAddr| is_advertisable_ip(&addr.ip()))
            .collect();
        if addrs.is_empty() {
            self.endpoint
                .parse()
                .ok()
                .filter(|addr: &SocketAddr| is_advertisable_ip(&addr.ip()))
                .into_iter()
                .collect()
        } else {
            addrs
        }
    }

    pub fn txt_records(&self) -> Vec<(String, String)> {
        vec![
            (TXT_VERSION_KEY.to_owned(), self.version.to_string()),
            (TXT_DEVICE_KEY.to_owned(), self.device_public_key.clone()),
            (TXT_SERVER_KEY.to_owned(), self.server_public_key.clone()),
            (
                TXT_INSTANCE_NONCE_KEY.to_owned(),
                self.instance_nonce.clone(),
            ),
            (TXT_ENDPOINT_KEY.to_owned(), self.endpoint.clone()),
            (
                TXT_ENDPOINTS_KEY.to_owned(),
                self.endpoints.join(","),
            ),
            (
                TXT_CERT_FINGERPRINT_KEY.to_owned(),
                self.listener_cert_fingerprint.clone(),
            ),
            (TXT_CAPABILITIES_KEY.to_owned(), self.capabilities.join(",")),
        ]
    }

    pub fn from_txt_record_map(records: &BTreeMap<String, String>) -> anyhow::Result<Self> {
        let endpoint = required_txt_record(records, TXT_ENDPOINT_KEY)?;
        // New advertisements carry the full list; old ones have no
        // `endpoints` record and parse as a one-element list holding
        // the single endpoint.
        let endpoints: Vec<String> = match records.get(TXT_ENDPOINTS_KEY) {
            Some(list) => list
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
            None => Vec::new(),
        };
        let endpoints = if endpoints.is_empty() {
            vec![endpoint.clone()]
        } else {
            endpoints
        };
        Ok(Self {
            version: required_txt_record(records, TXT_VERSION_KEY)?.parse()?,
            device_public_key: required_txt_record(records, TXT_DEVICE_KEY)?,
            server_public_key: required_txt_record(records, TXT_SERVER_KEY)?,
            instance_nonce: required_txt_record(records, TXT_INSTANCE_NONCE_KEY)?,
            endpoint,
            endpoints,
            listener_cert_fingerprint: required_txt_record(records, TXT_CERT_FINGERPRINT_KEY)?,
            capabilities: required_txt_record(records, TXT_CAPABILITIES_KEY)?
                .split(',')
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
        })
    }
}

impl PeerRelayRegistration {
    pub fn into_control_frame(self) -> anyhow::Result<SessionFrame> {
        Ok(SessionFrame {
            header: SessionHeader {
                connection_id: 0,
                sequence: 0,
                flags: FLAG_PEER_RELAY_REGISTRATION,
            },
            payload: Bytes::from(serde_json::to_vec(&self)?),
        })
    }

    pub fn from_control_frame(frame: &SessionFrame) -> anyhow::Result<Self> {
        if frame.header.flags & FLAG_PEER_RELAY_REGISTRATION == 0 {
            anyhow::bail!("session frame did not contain a peer relay registration");
        }
        Ok(serde_json::from_slice(&frame.payload)?)
    }
}

/// Server-to-provider dial-back notification (4.56): pushed on the
/// provider's live session when the server mints a reversed
/// introduction for a consumer that asked to be dialed back. The
/// notification is self-contained — the provider needs nothing else
/// to dial the consumer (4.57): the consumer's key and endpoints,
/// plus the server-signed reversed introduction it presents to the
/// consumer on dial and to the server as its relay registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerShareDialBackNotification {
    pub consumer_device_public_key: String,
    pub consumer_endpoints: Vec<String>,
    pub introduction: SignedPeerShareIntroduction,
}

impl PeerShareDialBackNotification {
    pub fn into_control_frame(self) -> anyhow::Result<SessionFrame> {
        Ok(SessionFrame {
            header: SessionHeader {
                connection_id: 0,
                sequence: 0,
                flags: FLAG_PEER_DIAL_BACK,
            },
            payload: Bytes::from(serde_json::to_vec(&self)?),
        })
    }

    pub fn from_control_frame(frame: &SessionFrame) -> anyhow::Result<Self> {
        if frame.header.flags & FLAG_PEER_DIAL_BACK == 0 {
            anyhow::bail!("session frame did not contain a peer dial-back notification");
        }
        Ok(serde_json::from_slice(&frame.payload)?)
    }
}

fn required_txt_record(records: &BTreeMap<String, String>, key: &str) -> anyhow::Result<String> {
    records
        .get(key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing peer advertisement TXT record: {key}"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        is_advertisable_ip, PeerRelayRegistration, PeerShareAdvertisement,
        PeerShareDialBackNotification, PeerShareIntroductionClaims,
        PeerShareIntroductionRequest, SignedPeerShareIntroduction,
    };

    #[test]
    fn introduction_request_signature_payload_excludes_signature_field() {
        let request = PeerShareIntroductionRequest {
            consumer_device_public_key: "consumer".to_owned(),
            provider_device_public_key: "provider".to_owned(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            consumer_signature: "sig".to_owned(),
            dial_back: false,
            consumer_endpoints: Vec::new(),
            consumer_listener_cert_fingerprint: String::new(),
        };

        let payload =
            String::from_utf8(request.signed_payload().expect("payload should serialize"))
                .expect("payload should be utf8");
        assert!(payload.contains("consumer_device_public_key"));
        assert!(!payload.contains("consumer_signature"));
    }

    #[test]
    fn introduction_request_signature_payload_excludes_dial_back_fields() {
        // The dial-back fields must stay out of the signed payload so
        // a new client still verifies against an old server (4.56):
        // the old server signs/ verifies the six-field payload.
        let request = PeerShareIntroductionRequest {
            consumer_device_public_key: "consumer".to_owned(),
            provider_device_public_key: "provider".to_owned(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            consumer_signature: "sig".to_owned(),
            dial_back: true,
            consumer_endpoints: vec!["192.168.43.10:54443".to_owned()],
            consumer_listener_cert_fingerprint: "sha256:consumer-listener".to_owned(),
        };

        let payload =
            String::from_utf8(request.signed_payload().expect("payload should serialize"))
                .expect("payload should be utf8");
        assert!(!payload.contains("dial_back"));
        assert!(!payload.contains("consumer_endpoints"));
        assert!(!payload.contains("consumer_listener_cert_fingerprint"));

        // ...but the fields themselves round-trip through JSON, so the
        // server sees the flag and the endpoints.
        let parsed: PeerShareIntroductionRequest = serde_json::from_str(
            &serde_json::to_string(&request).expect("request should serialize"),
        )
        .expect("request should parse");
        assert_eq!(parsed, request);
        assert!(parsed.dial_back);
    }

    #[test]
    fn introduction_request_without_dial_back_fields_parses_as_forward_only() {
        // Old clients / old servers send no dial-back fields: they
        // parse as dial-back off with no endpoints, i.e. exactly the
        // pre-4.56 behaviour.
        let parsed: PeerShareIntroductionRequest = serde_json::from_str(
            r#"{"consumer_device_public_key":"consumer","provider_device_public_key":"provider","provider_instance_nonce":"nonce-1","provider_endpoint":"192.168.1.20:54443","listener_transport":"quic","listener_cert_fingerprint":"sha256:abcd","consumer_signature":"sig"}"#,
        )
        .expect("old request should parse");
        assert!(!parsed.dial_back);
        assert!(parsed.consumer_endpoints.is_empty());
        assert!(parsed.consumer_listener_cert_fingerprint.is_empty());
    }

    #[test]
    fn introduction_claims_payload_includes_expiry() {
        let claims = PeerShareIntroductionClaims {
            consumer_device_public_key: "consumer".to_owned(),
            provider_device_public_key: "provider".to_owned(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            expires_at: 12345,
            direction: "forward".to_owned(),
            consumer_endpoints: Vec::new(),
        };

        let payload =
            String::from_utf8(claims.signing_payload().expect("payload should serialize"))
                .expect("payload should be utf8");
        assert!(payload.contains("expires_at"));
    }

    #[test]
    fn introduction_claims_without_direction_parse_as_forward() {
        // Claims minted by an old server carry no direction: they
        // parse as forward, so old introductions keep verifying.
        let parsed: PeerShareIntroductionClaims = serde_json::from_str(
            r#"{"consumer_device_public_key":"consumer","provider_device_public_key":"provider","provider_instance_nonce":"nonce-1","provider_endpoint":"192.168.1.20:54443","listener_transport":"quic","listener_cert_fingerprint":"sha256:abcd","expires_at":12345}"#,
        )
        .expect("old claims should parse");
        assert_eq!(parsed.direction, "forward");
        assert!(!parsed.is_reverse());
        assert!(parsed.consumer_endpoints.is_empty());
    }

    #[test]
    fn reversed_introduction_claims_name_roles_and_endpoints() {
        let claims = PeerShareIntroductionClaims {
            consumer_device_public_key: "consumer".to_owned(),
            provider_device_public_key: "provider".to_owned(),
            provider_instance_nonce: "nonce-1".to_owned(),
            provider_endpoint: "192.168.1.20:54443".to_owned(),
            listener_transport: "quic".to_owned(),
            listener_cert_fingerprint: "sha256:consumer-listener".to_owned(),
            expires_at: 12345,
            direction: "reverse".to_owned(),
            consumer_endpoints: vec!["192.168.43.10:54443".to_owned()],
        };
        assert!(claims.is_reverse());
        let parsed: PeerShareIntroductionClaims = serde_json::from_str(
            &serde_json::to_string(&claims).expect("claims should serialize"),
        )
        .expect("claims should parse");
        assert_eq!(parsed, claims);
        assert!(parsed.is_reverse());
        // The reversed listener cert is the consumer's, not the
        // provider's: the roles are named by the claims, not by
        // position alone.
        assert_eq!(
            parsed.listener_cert_fingerprint,
            "sha256:consumer-listener"
        );
    }

    #[test]
    fn peer_share_advertisement_txt_round_trip() {
        let advertisement = PeerShareAdvertisement {
            version: 1,
            device_public_key: "consumer".to_owned(),
            server_public_key: "server".to_owned(),
            instance_nonce: "nonce-1".to_owned(),
            endpoint: "192.168.1.20:54443".to_owned(),
            endpoints: vec![
                "192.168.1.20:54443".to_owned(),
                "10.0.0.5:54443".to_owned(),
            ],
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            capabilities: vec!["relay".to_owned(), "quic".to_owned()],
        };

        let records = advertisement
            .txt_records()
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let parsed = PeerShareAdvertisement::from_txt_record_map(&records)
            .expect("advertisement should parse from txt records");

        assert_eq!(parsed, advertisement);
        assert_eq!(
            parsed.endpoint_addrs(),
            vec![
                "192.168.1.20:54443".parse().unwrap(),
                "10.0.0.5:54443".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn peer_share_advertisement_without_endpoints_record_parses_as_single() {
        // Old single-endpoint advertisements carry no `endpoints`
        // record: they parse as a one-element list holding `endpoint`,
        // so an old provider is still dialable by a new consumer.
        let mut records = BTreeMap::new();
        records.insert("version".to_owned(), "1".to_owned());
        records.insert("device_key".to_owned(), "consumer".to_owned());
        records.insert("server_key".to_owned(), "server".to_owned());
        records.insert("instance_nonce".to_owned(), "nonce-1".to_owned());
        records.insert("endpoint".to_owned(), "192.168.1.20:54443".to_owned());
        records.insert("cert_fingerprint".to_owned(), "sha256:abcd".to_owned());
        records.insert("capabilities".to_owned(), "relay,quic".to_owned());

        let parsed = PeerShareAdvertisement::from_txt_record_map(&records)
            .expect("old advertisement should parse");
        assert_eq!(parsed.endpoint, "192.168.1.20:54443");
        assert_eq!(parsed.endpoints, vec!["192.168.1.20:54443".to_owned()]);
        assert_eq!(
            parsed.endpoint_addrs(),
            vec!["192.168.1.20:54443".parse().unwrap()]
        );
    }

    #[test]
    fn peer_share_advertisement_set_endpoints_keeps_primary_first() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut advertisement = PeerShareAdvertisement {
            version: 1,
            device_public_key: "consumer".to_owned(),
            server_public_key: "server".to_owned(),
            instance_nonce: "nonce-1".to_owned(),
            endpoint: String::new(),
            endpoints: Vec::new(),
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            capabilities: vec!["relay".to_owned(), "quic".to_owned()],
        };
        advertisement.set_endpoints(
            &[
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            ],
            54443,
        );
        assert_eq!(advertisement.endpoint, "192.168.1.20:54443");
        assert_eq!(
            advertisement.endpoints,
            vec!["192.168.1.20:54443".to_owned(), "10.0.0.5:54443".to_owned()]
        );
    }

    #[test]
    fn peer_relay_registration_round_trips_through_control_frame() {
        let registration = PeerRelayRegistration {
            introduction: SignedPeerShareIntroduction {
                introduction: PeerShareIntroductionClaims {
                    consumer_device_public_key: "consumer".to_owned(),
                    provider_device_public_key: "provider".to_owned(),
                    provider_instance_nonce: "nonce-1".to_owned(),
                    provider_endpoint: "192.168.1.20:54443".to_owned(),
                    listener_transport: "quic".to_owned(),
                    listener_cert_fingerprint: "sha256:abcd".to_owned(),
                    expires_at: 12345,
                    direction: "forward".to_owned(),
                    consumer_endpoints: Vec::new(),
                },
                server_signature: "sig".to_owned(),
            },
        };

        let frame = registration
            .clone()
            .into_control_frame()
            .expect("control frame should serialize");
        let parsed =
            PeerRelayRegistration::from_control_frame(&frame).expect("control frame should parse");
        assert_eq!(parsed, registration);
    }

    #[test]
    fn dial_back_notification_round_trips_through_control_frame() {
        use crate::session::FLAG_PEER_DIAL_BACK;

        let notification = PeerShareDialBackNotification {
            consumer_device_public_key: "consumer".to_owned(),
            consumer_endpoints: vec!["192.168.43.10:54443".to_owned()],
            introduction: SignedPeerShareIntroduction {
                introduction: PeerShareIntroductionClaims {
                    consumer_device_public_key: "consumer".to_owned(),
                    provider_device_public_key: "provider".to_owned(),
                    provider_instance_nonce: "nonce-1".to_owned(),
                    provider_endpoint: "192.168.1.20:54443".to_owned(),
                    listener_transport: "quic".to_owned(),
                    listener_cert_fingerprint: "sha256:consumer-listener".to_owned(),
                    expires_at: 12345,
                    direction: "reverse".to_owned(),
                    consumer_endpoints: vec!["192.168.43.10:54443".to_owned()],
                },
                server_signature: "sig".to_owned(),
            },
        };

        let frame = notification
            .clone()
            .into_control_frame()
            .expect("control frame should serialize");
        assert_ne!(frame.header.flags & FLAG_PEER_DIAL_BACK, 0);
        let parsed = PeerShareDialBackNotification::from_control_frame(&frame)
            .expect("control frame should parse");
        assert_eq!(parsed, notification);
        assert!(parsed.introduction.introduction.is_reverse());

        // A relay-registration frame is not a dial-back frame.
        let registration = PeerRelayRegistration {
            introduction: notification.introduction.clone(),
        };
        let relay_frame = registration
            .into_control_frame()
            .expect("registration frame should serialize");
        assert!(PeerShareDialBackNotification::from_control_frame(&relay_frame).is_err());
    }

    #[test]
    fn advertisable_ip_allow_list_is_private_and_link_local_only() {
        // The allow-list is the address, not the interface name:
        // every private block and link-local is kept, every public
        // address is dropped, whatever the interface is called.
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        assert!(is_advertisable_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(is_advertisable_ip(&IpAddr::V4(Ipv4Addr::new(
            172, 20, 72, 22
        ))));
        assert!(is_advertisable_ip(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 140
        ))));
        assert!(is_advertisable_ip(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 2
        ))));
        assert!(!is_advertisable_ip(&IpAddr::V4(Ipv4Addr::new(
            192, 0, 0, 4
        ))));
        assert!(!is_advertisable_ip(&IpAddr::V4(Ipv4Addr::new(
            100, 64, 1, 2
        ))));
        assert!(!is_advertisable_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_advertisable_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_advertisable_ip(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!is_advertisable_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn set_endpoints_drops_public_cellular_address() {
        // The 6a regression, second half: even if a public address
        // reaches set_endpoints (pinned config, future caller), it
        // must not land in the advertisement — the primary becomes
        // the first surviving private address.
        use std::net::{IpAddr, Ipv4Addr};

        let mut advertisement = sample_advertisement();
        advertisement.set_endpoints(
            &[
                IpAddr::V4(Ipv4Addr::new(192, 0, 0, 4)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 140)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            ],
            54443,
        );
        assert_eq!(advertisement.endpoint, "192.168.1.140:54443");
        assert_eq!(
            advertisement.endpoints,
            vec!["192.168.1.140:54443".to_owned()]
        );
    }

    #[test]
    fn endpoint_addrs_and_sanitize_drop_public_addresses() {
        // A wire advertisement listing a public cellular address
        // (old provider, pinned config, or a stale record) must not
        // make the consumer dial it: endpoint_addrs drops it, and
        // sanitize resets the primary to the first surviving entry.
        let mut advertisement = sample_advertisement();
        advertisement.endpoint = "192.0.0.4:54443".to_owned();
        advertisement.endpoints = vec![
            "192.0.0.4:54443".to_owned(),
            "192.168.1.20:54443".to_owned(),
            "100.64.1.2:54443".to_owned(),
            "10.0.0.5:54443".to_owned(),
        ];
        assert_eq!(
            advertisement.endpoint_addrs(),
            vec![
                "192.168.1.20:54443".parse().unwrap(),
                "10.0.0.5:54443".parse().unwrap(),
            ]
        );
        assert!(advertisement.sanitize_advertised_endpoints());
        assert_eq!(advertisement.endpoint, "192.168.1.20:54443");
        assert_eq!(
            advertisement.endpoints,
            vec![
                "192.168.1.20:54443".to_owned(),
                "10.0.0.5:54443".to_owned(),
            ]
        );

        // Nothing reachable left: sanitize reports it and the
        // advertisement carries no primary at all.
        advertisement.endpoint = "192.0.0.4:54443".to_owned();
        advertisement.endpoints = vec!["192.0.0.4:54443".to_owned()];
        assert!(!advertisement.sanitize_advertised_endpoints());
        assert_eq!(advertisement.endpoint, "");
        assert!(advertisement.endpoints.is_empty());
        assert!(advertisement.endpoint_addrs().is_empty());
    }

    fn sample_advertisement() -> PeerShareAdvertisement {
        PeerShareAdvertisement {
            version: 1,
            device_public_key: "consumer".to_owned(),
            server_public_key: "server".to_owned(),
            instance_nonce: "nonce-1".to_owned(),
            endpoint: String::new(),
            endpoints: Vec::new(),
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            capabilities: vec!["relay".to_owned(), "quic".to_owned()],
        }
    }
}
