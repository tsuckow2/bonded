use anyhow::Context;
use bonded_core::peer_share::PeerShareAdvertisement;
use mdns_sd::{Receiver, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;

pub const PEER_SHARE_SERVICE_TYPE: &str = "_bonded-peer._udp.local.";

pub struct PeerShareAdvertiser {
    daemon: ServiceDaemon,
}

impl PeerShareAdvertiser {
    pub fn start(advertisement: &PeerShareAdvertisement) -> anyhow::Result<Self> {
        let daemon = ServiceDaemon::new().context("failed to create mDNS daemon")?;
        let service_info = service_info_from_advertisement(advertisement)?;
        daemon
            .register(service_info)
            .context("failed to register peer-share mDNS service")?;
        Ok(Self { daemon })
    }

    pub fn shutdown(self) -> anyhow::Result<()> {
        let _ = self
            .daemon
            .shutdown()
            .map_err(|error| anyhow::anyhow!(error))?;
        Ok(())
    }
}

pub struct PeerShareBrowser {
    daemon: ServiceDaemon,
    receiver: Receiver<ServiceEvent>,
}

impl PeerShareBrowser {
    pub fn start() -> anyhow::Result<Self> {
        let daemon = ServiceDaemon::new().context("failed to create mDNS daemon")?;
        let receiver = daemon
            .browse(PEER_SHARE_SERVICE_TYPE)
            .context("failed to browse peer-share mDNS service")?;
        Ok(Self { daemon, receiver })
    }

    pub async fn recv(&self) -> anyhow::Result<PeerShareAdvertisement> {
        loop {
            match self
                .receiver
                .recv_async()
                .await
                .context("peer-share mDNS browse stream ended")?
            {
                ServiceEvent::ServiceResolved(resolved) if resolved.is_valid() => {
                    return advertisement_from_resolved_service(&resolved);
                }
                _ => {}
            }
        }
    }

    pub fn shutdown(self) -> anyhow::Result<()> {
        let _ = self
            .daemon
            .shutdown()
            .map_err(|error| anyhow::anyhow!(error))?;
        Ok(())
    }
}

fn service_info_from_advertisement(
    advertisement: &PeerShareAdvertisement,
) -> anyhow::Result<ServiceInfo> {
    let endpoint = advertisement
        .endpoint
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid peer-share endpoint: {}", advertisement.endpoint))?;
    let instance_name = service_instance_name(advertisement);
    let hostname = format!("{instance_name}.local.");
    let txt_records = advertisement
        .txt_records()
        .into_iter()
        .collect::<HashMap<_, _>>();
    let mut service_info = ServiceInfo::new(
        PEER_SHARE_SERVICE_TYPE,
        &instance_name,
        &hostname,
        endpoint.ip(),
        endpoint.port(),
        txt_records,
    )
    .context("failed to build peer-share mDNS service info")?;
    service_info.set_requires_probe(true);
    Ok(service_info)
}

fn service_instance_name(advertisement: &PeerShareAdvertisement) -> String {
    let mut digest = Sha256::new();
    digest.update(advertisement.device_public_key.as_bytes());
    digest.update(b":");
    digest.update(advertisement.instance_nonce.as_bytes());
    let hash = digest.finalize();
    format!(
        "bonded-{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3]
    )
}

fn advertisement_from_resolved_service(
    resolved: &ResolvedService,
) -> anyhow::Result<PeerShareAdvertisement> {
    let mut records = BTreeMap::new();
    for key in [
        "version",
        "device_key",
        "server_key",
        "instance_nonce",
        "endpoint",
        "cert_fingerprint",
        "capabilities",
    ] {
        if let Some(value) = resolved.get_property_val_str(key) {
            records.insert(key.to_owned(), value.to_owned());
        }
    }

    if !records.contains_key("endpoint") {
        let address = resolved
            .get_addresses()
            .iter()
            .next()
            .map(|address| address.to_string())
            .context("resolved peer-share service did not include an address")?;
        records.insert(
            "endpoint".to_owned(),
            format!("{address}:{}", resolved.get_port()),
        );
    }

    PeerShareAdvertisement::from_txt_record_map(&records)
}

#[cfg(test)]
mod tests {
    use super::{advertisement_from_resolved_service, service_info_from_advertisement};
    use bonded_core::peer_share::PeerShareAdvertisement;

    #[test]
    fn resolved_service_round_trips_peer_share_advertisement() {
        let advertisement = PeerShareAdvertisement {
            version: 1,
            device_public_key: "consumer".to_owned(),
            server_public_key: "server".to_owned(),
            instance_nonce: "nonce-1".to_owned(),
            endpoint: "192.168.1.20:54443".to_owned(),
            listener_cert_fingerprint: "sha256:abcd".to_owned(),
            capabilities: vec!["relay".to_owned(), "quic".to_owned()],
        };

        let resolved = service_info_from_advertisement(&advertisement)
            .expect("service info should build")
            .as_resolved_service();
        let parsed = advertisement_from_resolved_service(&resolved)
            .expect("advertisement should parse from resolved service");

        assert_eq!(parsed, advertisement);
    }
}
