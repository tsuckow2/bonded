use anyhow::Context;
use bonded_core::peer_share::PeerShareAdvertisement;
use mdns_sd::{Receiver, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;

pub const PEER_SHARE_SERVICE_TYPE: &str = "_bonded-peer._udp.local.";

/// UTC minute index for windowed discovery. Windows are the first 10
/// seconds of each UTC minute, derived from the same device clock the
/// Kotlin lock scheduler uses, so both sides agree on window
/// boundaries without any cross-language signalling.
pub fn utc_minute(unix_secs: u64) -> u64 {
    unix_secs / 60
}

pub struct PeerShareAdvertiser {
    daemon: ServiceDaemon,
    service_info: ServiceInfo,
}

impl PeerShareAdvertiser {
    pub fn start(advertisement: &PeerShareAdvertisement) -> anyhow::Result<Self> {
        let daemon = ServiceDaemon::new().context("failed to create mDNS daemon")?;
        let service_info = service_info_from_advertisement(advertisement)?;
        daemon
            .register(service_info.clone())
            .context("failed to register peer-share mDNS service")?;
        Ok(Self {
            daemon,
            service_info,
        })
    }

    /// Re-announces the service for a discovery window. The daemon
    /// processes commands in order, so the goodbye from unregister is
    /// sent before the new announcement; the goodbye's single resend
    /// fires 120ms later, while a probed re-register announces only
    /// after ~750ms of probing, so no trailing goodbye can land after
    /// the announcement. The daemon itself is never restarted.
    pub fn reannounce(&self) -> anyhow::Result<()> {
        let _ = self
            .daemon
            .unregister(self.service_info.get_fullname())
            .map_err(|error| anyhow::anyhow!(error))
            .context("failed to unregister peer-share mDNS service for re-announce")?;
        self.daemon
            .register(self.service_info.clone())
            .map_err(|error| anyhow::anyhow!(error))
            .context("failed to re-register peer-share mDNS service")?;
        Ok(())
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

    /// Re-queries for the discovery window: stops the current browse
    /// and starts a fresh one, resetting mdns-sd's retransmission
    /// backoff (which doubles to an hour) so a query is actually sent
    /// during the 10s lock window. The daemon itself is never
    /// restarted. Callers must not hold a `recv()` future across this
    /// call: the old receiver is replaced, so an in-flight recv on it
    /// would never resolve.
    pub fn requery(&mut self) -> anyhow::Result<()> {
        self.daemon
            .stop_browse(PEER_SHARE_SERVICE_TYPE)
            .map_err(|error| anyhow::anyhow!(error))
            .context("failed to stop peer-share browse for window re-query")?;
        self.receiver = self
            .daemon
            .browse(PEER_SHARE_SERVICE_TYPE)
            .map_err(|error| anyhow::anyhow!(error))
            .context("failed to restart peer-share browse for window re-query")?;
        Ok(())
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
        "endpoints",
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
    use super::{
        advertisement_from_resolved_service, service_info_from_advertisement, utc_minute,
    };
    use bonded_core::peer_share::PeerShareAdvertisement;

    #[test]
    fn resolved_service_round_trips_peer_share_advertisement() {
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

        let resolved = service_info_from_advertisement(&advertisement)
            .expect("service info should build")
            .as_resolved_service();
        let parsed = advertisement_from_resolved_service(&resolved)
            .expect("advertisement should parse from resolved service");

        assert_eq!(parsed, advertisement);
    }

    #[test]
    fn utc_minute_changes_only_at_minute_boundaries() {
        assert_eq!(utc_minute(0), 0);
        assert_eq!(utc_minute(59), 0);
        assert_eq!(utc_minute(60), 1);
        assert_eq!(utc_minute(119), 1);
        assert_eq!(utc_minute(120), 2);
    }
}
