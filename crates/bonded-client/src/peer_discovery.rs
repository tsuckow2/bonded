use anyhow::Context;
use bonded_core::peer_share::PeerShareAdvertisement;
use mdns_sd::{Receiver, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time::sleep;
use tracing::{debug, warn};


pub const PEER_SHARE_SERVICE_TYPE: &str = "_bonded-peer._udp.local.";

/// How often each mDNS daemon re-checks interface IPs (4.58 idle
/// pacing): the 5 s default wakes the daemon even when the session
/// is idle and nothing is changing. 60 s is enough — the advertise
/// watcher re-reads the interfaces itself on its own poll, and the
/// browse loop re-queries every UTC minute regardless. Tradeoff:
/// the daemon can take up to 60 s to notice a new interface (e.g.
/// joining a new network) on its own; the watcher and the window
/// re-query cover the cases that matter.
const MDNS_IP_CHECK_INTERVAL_SECS: u32 = 60;

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
        daemon
            .set_ip_check_interval(MDNS_IP_CHECK_INTERVAL_SECS)
            .context("failed to set mDNS IP check interval")?;
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

impl Drop for PeerShareAdvertiser {
    fn drop(&mut self) {
        // Best-effort daemon shutdown. Dropping a ServiceDaemon
        // without shutdown() leaks its thread and its SO_REUSEPORT
        // *:5353 socket: mdns-sd's run loop only exits on an Exit
        // command, and dropping the command sender does not stop it
        // — so an aborted watcher task used to leave a live daemon
        // behind, stealing a share of incoming multicast and still
        // answering queries for a stale service instance.
        // shutdown() only queues the Exit command (the daemon wakes
        // on its signal socket), so it is safe to call here; the
        // status receiver is dropped, the daemon still exits.
        let _ = self.daemon.shutdown();
    }
}

/// Commands the browse loop sends to the drain task that owns the
/// mDNS browser daemon (see `PeerShareBrowser`).
enum BrowserCmd {
    Requery,
    Shutdown,
}

/// What the drain task reports when its inner loop ends: the daemon
/// died and should be recreated, or the browser is shutting down.
enum DrainOutcome {
    Recreate,
    Shutdown,
}

/// Create a browser daemon and start browsing for the peer-share
/// service type.
fn start_browse_daemon() -> anyhow::Result<(ServiceDaemon, Receiver<ServiceEvent>)> {
    let daemon = ServiceDaemon::new().context("failed to create mDNS daemon")?;
    daemon
        .set_ip_check_interval(MDNS_IP_CHECK_INTERVAL_SECS)
        .context("failed to set mDNS IP check interval")?;
    let receiver = daemon
        .browse(PEER_SHARE_SERVICE_TYPE)
        .context("failed to browse peer-share mDNS service")?;
    Ok((daemon, receiver))
}

/// Re-query for the discovery window on a live daemon: stop the
/// current browse and start a fresh one, resetting mdns-sd's
/// retransmission backoff (which doubles to an hour) so a query is
/// actually sent during the 10s lock window.
fn requery_browse(
    daemon: &ServiceDaemon,
    receiver: &mut Receiver<ServiceEvent>,
) -> anyhow::Result<()> {
    daemon
        .stop_browse(PEER_SHARE_SERVICE_TYPE)
        .map_err(|error| anyhow::anyhow!(error))
        .context("failed to stop peer-share browse for window re-query")?;
    *receiver = daemon
        .browse(PEER_SHARE_SERVICE_TYPE)
        .map_err(|error| anyhow::anyhow!(error))
        .context("failed to restart peer-share browse for window re-query")?;
    Ok(())
}

/// Drain one browser daemon's event stream into the advertisement
/// channel, handling re-query commands from the browse loop. Returns
/// when the daemon dies (its event channel closed — recreate it) or
/// the browser is shut down.
async fn drain_browser_events(
    daemon: &ServiceDaemon,
    receiver: &mut Receiver<ServiceEvent>,
    cmd_rx: &mut UnboundedReceiver<BrowserCmd>,
    adv_tx: &UnboundedSender<PeerShareAdvertisement>,
) -> DrainOutcome {
    loop {
        tokio::select! {
            event = receiver.recv_async() => {
                match event {
                    Ok(ServiceEvent::ServiceResolved(resolved)) if resolved.is_valid() => {
                        match advertisement_from_resolved_service(&resolved) {
                            Ok(advertisement) => {
                                if adv_tx.send(advertisement).is_err() {
                                    return DrainOutcome::Shutdown;
                                }
                            }
                            Err(err) => {
                                debug!(error = %err, "ignoring unresolvable peer-share service");
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {
                        // The daemon's event channel closed: the
                        // daemon thread is gone. Recreate it.
                        return DrainOutcome::Recreate;
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(BrowserCmd::Requery) => {
                        if let Err(err) = requery_browse(daemon, receiver) {
                            debug!(error = %err, "peer-share browser re-query failed; recreating daemon");
                            return DrainOutcome::Recreate;
                        }
                    }
                    Some(BrowserCmd::Shutdown) | None => return DrainOutcome::Shutdown,
                }
            }
        }
    }
}

/// Wait out the daemon-restart backoff, returning false when the
/// browser was shut down while waiting (so the drain task exits
/// promptly instead of sleeping through the backoff).
async fn browser_restart_backoff(cmd_rx: &mut UnboundedReceiver<BrowserCmd>) -> bool {
    tokio::select! {
        _ = sleep(Duration::from_secs(1)) => true,
        cmd = cmd_rx.recv() => !matches!(cmd, Some(BrowserCmd::Shutdown) | None),
    }
}

/// The browser drain task: owns the mDNS daemon for the whole
/// browser lifetime and recreates it when it dies, so a dead daemon
/// never ends discovery silently. It only exits when the browser is
/// shut down (explicit command, or the command channel closing when
/// the `PeerShareBrowser` is dropped) — either way the daemon is
/// shut down before returning, so no daemon thread or *:5353 socket
/// is left behind.
async fn run_browser_drain(
    mut cmd_rx: UnboundedReceiver<BrowserCmd>,
    adv_tx: UnboundedSender<PeerShareAdvertisement>,
) {
    loop {
        match start_browse_daemon() {
            Ok((daemon, mut receiver)) => {
                match drain_browser_events(&daemon, &mut receiver, &mut cmd_rx, &adv_tx).await
                {
                    DrainOutcome::Shutdown => {
                        let _ = daemon.shutdown();
                        return;
                    }
                    DrainOutcome::Recreate => {
                        let _ = daemon.shutdown();
                        if !browser_restart_backoff(&mut cmd_rx).await {
                            return;
                        }
                    }
                }
            }
            Err(err) => {
                warn!(error = %err, "peer-share browser daemon failed to start; retrying");
                if !browser_restart_backoff(&mut cmd_rx).await {
                    return;
                }
            }
        }
    }
}

pub struct PeerShareBrowser {
    cmd_tx: UnboundedSender<BrowserCmd>,
    adv_rx: UnboundedReceiver<PeerShareAdvertisement>,
}

impl PeerShareBrowser {
    /// Start the browser. A dedicated drain task owns the mDNS daemon
    /// and forwards resolved advertisements over an unbounded channel
    /// to the browse loop.
    ///
    /// The drain task exists because mdns-sd delivers browse events
    /// over a bounded(10) channel with a BLOCKING send: when the
    /// browse loop is busy dialing a peer or requesting an
    /// introduction it stops draining, the channel fills, and the
    /// daemon thread blocks inside its socket-read loop — it stops
    /// reading *:5353 (the kernel backlog grows; 164 KB was observed
    /// on the OnePlus) and stops sending queries, so discovery
    /// stalls for as long as the loop is busy. The drain task always
    /// drains, whatever the loop is doing, so the daemon can never
    /// block on its event channel. The same task recreates the daemon
    /// if it dies, and shuts it down when the browser is dropped.
    pub fn start() -> anyhow::Result<Self> {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let (adv_tx, adv_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(run_browser_drain(cmd_rx, adv_tx));
        Ok(Self { cmd_tx, adv_rx })
    }

    /// Re-queries for the discovery window: asks the drain task to
    /// stop the current browse and start a fresh one, resetting
    /// mdns-sd's retransmission backoff (which doubles to an hour)
    /// so a query is actually sent during the 10s lock window. The
    /// daemon itself is never restarted for a re-query, and the
    /// request is queued, so it is safe to call while a `recv()` is
    /// in flight.
    pub fn requery(&self) -> anyhow::Result<()> {
        self.cmd_tx
            .send(BrowserCmd::Requery)
            .map_err(|_| anyhow::anyhow!("peer-share browser drain task stopped"))
    }

    /// Receive the next discovered advertisement, forwarded by the
    /// drain task. Returns an error when the browser has stopped.
    pub async fn recv(&mut self) -> anyhow::Result<PeerShareAdvertisement> {
        self.adv_rx
            .recv()
            .await
            .context("peer-share browser stopped")
    }

    /// Shut the browser down: the drain task shuts down its daemon
    /// and exits, so a later `recv()` reports the stop. Dropping the
    /// browser without calling this has the same effect (the command
    /// channel closes).
    pub fn shutdown(&self) -> anyhow::Result<()> {
        let _ = self.cmd_tx.send(BrowserCmd::Shutdown);
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
        PeerShareBrowser,
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

    #[tokio::test]
    async fn browser_drain_task_survives_requery_and_shutdown() {
        // The drain task owns the daemon, so the browse loop can never
        // block it: re-querying goes through the command channel and
        // shutdown closes the advertisement channel, so recv() reports
        // the stop instead of hanging. Runs without UDP (the drain
        // task retries its daemon startup in the background), so it
        // passes in the sandbox as well as on a host with mDNS. A
        // discovery that beats the shutdown is legitimate and ignored
        // — the property under test is that the stop is reported
        // promptly.
        use std::time::Duration;

        let mut browser = PeerShareBrowser::start().expect("browser should start");
        browser
            .requery()
            .expect("re-query should reach the drain task");
        browser.shutdown().expect("shutdown should send");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::time::timeout_at(deadline, browser.recv()).await {
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => break,
                Err(_) => panic!("recv did not report the browser stop within 5 s of shutdown"),
            }
        }
    }
}
