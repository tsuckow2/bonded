use std::collections::BTreeMap;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::session::{SessionFrame, SessionHeader, FLAG_PEER_RELAY_REGISTRATION};

const TXT_VERSION_KEY: &str = "version";
const TXT_DEVICE_KEY: &str = "device_key";
const TXT_SERVER_KEY: &str = "server_key";
const TXT_INSTANCE_NONCE_KEY: &str = "instance_nonce";
const TXT_ENDPOINT_KEY: &str = "endpoint";
const TXT_CAPABILITIES_KEY: &str = "capabilities";
const TXT_CERT_FINGERPRINT_KEY: &str = "cert_fingerprint";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerShareIntroductionRequest {
    pub consumer_device_public_key: String,
    pub provider_device_public_key: String,
    pub provider_instance_nonce: String,
    pub provider_endpoint: String,
    pub listener_transport: String,
    pub listener_cert_fingerprint: String,
    pub consumer_signature: String,
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
    pub endpoint: String,
    pub listener_cert_fingerprint: String,
    pub capabilities: Vec<String>,
}

impl PeerShareIntroductionRequest {
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
                TXT_CERT_FINGERPRINT_KEY.to_owned(),
                self.listener_cert_fingerprint.clone(),
            ),
            (TXT_CAPABILITIES_KEY.to_owned(), self.capabilities.join(",")),
        ]
    }

    pub fn from_txt_record_map(records: &BTreeMap<String, String>) -> anyhow::Result<Self> {
        Ok(Self {
            version: required_txt_record(records, TXT_VERSION_KEY)?.parse()?,
            device_public_key: required_txt_record(records, TXT_DEVICE_KEY)?,
            server_public_key: required_txt_record(records, TXT_SERVER_KEY)?,
            instance_nonce: required_txt_record(records, TXT_INSTANCE_NONCE_KEY)?,
            endpoint: required_txt_record(records, TXT_ENDPOINT_KEY)?,
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
        PeerRelayRegistration, PeerShareAdvertisement, PeerShareIntroductionClaims,
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
        };

        let payload =
            String::from_utf8(request.signed_payload().expect("payload should serialize"))
                .expect("payload should be utf8");
        assert!(payload.contains("consumer_device_public_key"));
        assert!(!payload.contains("consumer_signature"));
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
        };

        let payload =
            String::from_utf8(claims.signing_payload().expect("payload should serialize"))
                .expect("payload should be utf8");
        assert!(payload.contains("expires_at"));
    }

    #[test]
    fn peer_share_advertisement_txt_round_trip() {
        let advertisement = PeerShareAdvertisement {
            version: 1,
            device_public_key: "consumer".to_owned(),
            server_public_key: "server".to_owned(),
            instance_nonce: "nonce-1".to_owned(),
            endpoint: "192.168.1.20:54443".to_owned(),
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
}
