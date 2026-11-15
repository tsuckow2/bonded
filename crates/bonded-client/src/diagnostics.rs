//! Periodic diagnostics upload.
//!
//! When `diagnostics_upload_enabled` is set, a background task uploads
//! the client's diagnostic log to the server's
//! `/v1/bootstrap/diagnostics` endpoint on a fixed cadence, signed with
//! the device key. The log contents come from a caller-provided source
//! (the Android FFI layer passes a reader over its on-device log ring
//! file).
//!
//! Contract from the feature's design: routine uploads are SILENT —
//! success produces no log line anywhere. Failures are reported once
//! per attempt through the caller's error sink (which typically logs
//! them, so the failure itself rides the next successful upload).

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bonded_core::auth::sign_bytes;
use bonded_core::config::ClientConfig;
use bonded_core::diagnostics::{
    clamp_diagnostics_period_secs, DiagnosticsUploadRequest, MAX_DIAGNOSTICS_LOG_BYTES,
};

use crate::{bootstrap_scheme_candidates, load_or_create_device_keypair, request_bootstrap_json};

/// Supplies the current diagnostic log contents, if any.
pub type DiagnosticsLogSource = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// Receives one message per failed upload attempt.
pub type DiagnosticsErrorSink = Arc<dyn Fn(String) + Send + Sync>;

/// Delay before the first upload attempt after the task starts, so a
/// freshly started session produces evidence promptly instead of one
/// full period later.
const FIRST_UPLOAD_DELAY_SECS: u64 = 15;

/// Spawn the periodic uploader. Returns immediately; the task runs
/// until the runtime drops it (session end).
///
/// `dozing` (4.77) is the session worker's Doze flag, shared with
/// the caller: while it is set, uploads are deferred — they are not
/// time-critical, and a dozing device should not spend radio and
/// battery on them (~31 MB/h at the 60 s cadence before the 4.76
/// filter). The log ring is untouched, so the deferred content rides
/// the next upload after wake, subject to the hash dedup and the
/// Tier 1 filter. `None` (a caller with no Doze signal, e.g. the
/// Linux CLI) never defers.
pub fn spawn_diagnostics_uploader(
    config: ClientConfig,
    client_build: String,
    log_source: DiagnosticsLogSource,
    on_error: DiagnosticsErrorSink,
    dozing: Option<Arc<AtomicBool>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let keypair = match load_or_create_device_keypair(
            Path::new(&config.client.private_key_path),
            Path::new(&config.client.public_key_path),
        ) {
            Ok(keypair) => keypair,
            Err(err) => {
                on_error(format!(
                    "Diagnostics upload disabled: failed to load device keypair: {err:#}"
                ));
                return;
            }
        };
        let period_secs = clamp_diagnostics_period_secs(
            config.client.diagnostics_upload_period_secs,
        );
        let mut uploader = DiagnosticsUploader {
            config,
            keypair,
            client_build,
            last_uploaded_hash: None,
        };
        let dozing = dozing.unwrap_or_default();
        tokio::time::sleep(Duration::from_secs(FIRST_UPLOAD_DELAY_SECS)).await;
        loop {
            // 4.77: while dozing, skip the upload attempt entirely
            // (no network, no hash update) and sleep out the period
            // — the next iteration after wake uploads the deferred
            // content. Silent by design, like a successful upload.
            if !dozing.load(Ordering::Relaxed) {
                if let Some(contents) = log_source() {
                    if let Err(err) = uploader.upload_if_changed(&contents).await {
                        on_error(format!("Diagnostics upload failed: {err:#}"));
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(period_secs)).await;
        }
    })
}

struct DiagnosticsUploader {
    config: ClientConfig,
    keypair: bonded_core::auth::DeviceKeypair,
    client_build: String,
    last_uploaded_hash: Option<u64>,
}

impl DiagnosticsUploader {
    /// Upload `contents` (tail-capped) unless they are byte-identical
    /// to the last successful upload. Returns Ok when there is nothing
    /// to do or the server accepted the upload; a server rejection is
    /// an Err (the bootstrap helper errors on any non-200).
    async fn upload_if_changed(&mut self, contents: &str) -> anyhow::Result<()> {
        if contents.is_empty() {
            return Ok(());
        }
        // Drop Tier 1 noise before the tail cap, so the 512 KiB cap
        // retains relevant history instead of discarding older relevant
        // lines to make room for noise. The local log ring is unchanged;
        // only the upload payload is filtered.
        let filtered = filter_diagnostics_noise(contents);
        if filtered.trim().is_empty() {
            // Nothing but routine noise: nothing worth uploading.
            return Ok(());
        }
        let log_text = tail_cap_log(&filtered);
        let hash = content_hash(log_text.as_bytes());
        if self.last_uploaded_hash == Some(hash) {
            return Ok(());
        }
        let bootstrap_address = self.config.client.server_public_address.trim();
        if bootstrap_address.is_empty() {
            anyhow::bail!("server_public_address is required for diagnostics upload");
        }
        let mut request = DiagnosticsUploadRequest {
            device_public_key: self.keypair.public_key_b64.clone(),
            client_build: self.client_build.clone(),
            captured_at_unix: now_unix_secs(),
            log_text: log_text.to_owned(),
            signature: String::new(),
        };
        request.signature = sign_bytes(&self.keypair, &request.signed_payload()?)?;
        let request_body = serde_json::to_string(&request)?;
        let mut errors = Vec::new();
        for scheme in bootstrap_scheme_candidates(&self.config) {
            match request_bootstrap_json(
                &self.config,
                scheme,
                bootstrap_address,
                "POST",
                "/v1/bootstrap/diagnostics",
                Some(&request_body),
            )
            .await
            {
                Ok(_) => {
                    self.last_uploaded_hash = Some(hash);
                    return Ok(());
                }
                Err(err) => errors.push(format!("scheme={scheme:?}: {err:#}")),
            }
        }
        anyhow::bail!(
            "failed to upload diagnostics via {bootstrap_address}: {}",
            errors.join(" | ")
        )
    }
}

/// Drop Tier 1 noise lines from a diagnostic log before upload.
///
/// Tier 1 lines are high-frequency routine successes with no diagnostic
/// value per line: one line per heartbeat ping and pong, and one
/// success line per socket-protect / socket-bind call. A diagnostician
/// needs the ping rate and RTT distribution, not one line per ping;
/// and a success line per fd is pure debug chatter. Only the success
/// variants are dropped — a failed protect/bind (`-> false`) is a real
/// event and is kept. The local log ring is unchanged; only the upload
/// payload is filtered.
fn filter_diagnostics_noise(contents: &str) -> String {
    let mut out = String::with_capacity(contents.len() / 2);
    for line in contents.lines() {
        if is_diagnostics_noise_line(line) {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Whether one log-ring line is Tier 1 noise (see
/// [`filter_diagnostics_noise`]).
///
/// Log-ring lines are `<epoch_ms> <level> <message>`; the match is on
/// the message portion so a timestamp/level prefix can never cause a
/// false positive. A line that does not parse as `<epoch_ms> <level>
/// <message>` is kept (never dropped).
fn is_diagnostics_noise_line(line: &str) -> bool {
    let message = log_ring_message(line);
    message.starts_with("Sending heartbeat ping seq=")
        || message.starts_with("Heartbeat pong received: seq=")
        || (message.starts_with("protect_fd(fd=")
            && message.trim_end().ends_with("-> true"))
        || (message.starts_with("bind_socket_to_network(fd=")
            && message.trim_end().ends_with("-> true"))
}

/// The message portion of a log-ring line (`<epoch_ms> <level>
/// <message>`). Returns the whole line when it has no such prefix.
fn log_ring_message(line: &str) -> &str {
    let mut parts = line.splitn(3, ' ');
    let _epoch_ms = parts.next();
    let _level = parts.next();
    parts.next().unwrap_or(line)
}

/// Keep the newest bytes of the log within the server's size limit,
/// starting at a line boundary where possible.
fn tail_cap_log(contents: &str) -> &str {
    if contents.len() <= MAX_DIAGNOSTICS_LOG_BYTES {
        return contents;
    }
    let mut start = contents.len() - MAX_DIAGNOSTICS_LOG_BYTES;
    while start < contents.len() && !contents.is_char_boundary(start) {
        start += 1;
    }
    match contents[start..].find('\n') {
        Some(newline) => &contents[start + newline + 1..],
        None => &contents[start..],
    }
}

fn content_hash(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(bytes);
    hasher.finish()
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_cap_keeps_short_logs_untouched() {
        assert_eq!(tail_cap_log("a\nb\n"), "a\nb\n");
    }

    #[test]
    fn tail_cap_drops_oldest_lines_and_stays_in_limit() {
        let line = "x".repeat(1024);
        let contents = (0..(MAX_DIAGNOSTICS_LOG_BYTES / 1024 + 10))
            .map(|_| line.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let capped = tail_cap_log(&contents);
        assert!(capped.len() <= MAX_DIAGNOSTICS_LOG_BYTES);
        assert!(
            contents.ends_with(capped),
            "the cap must keep the newest content"
        );
        let dropped = contents.len() - capped.len();
        assert!(dropped > 0, "an oversized log must actually be capped");
        assert_eq!(
            contents.as_bytes()[dropped - 1],
            b'\n',
            "the cap must start at a line boundary when one exists"
        );
    }

    #[test]
    fn content_hash_distinguishes_inputs() {
        assert_ne!(content_hash(b"one"), content_hash(b"two"));
        assert_eq!(content_hash(b"same"), content_hash(b"same"));
    }

    #[test]
    fn diagnostics_noise_filter_drops_tier1_and_keeps_the_rest() {
        let log = [
            "1794483579223 4 Sending heartbeat ping seq=1544",
            "1794483579329 4 Heartbeat pong received: seq=1544 rtt=107ms",
            "1794483579329 4 Heartbeat pong received: seq=1545",
            "1794483594934 4 protect_fd(fd=881) -> true",
            "1794483595316 4 bind_socket_to_network(fd=980, bind_address=172.20.72.101) -> true",
            // Failure variants are real events: kept.
            "1794483594934 4 protect_fd(fd=881) -> false",
            "1794483595316 4 bind_socket_to_network(fd=980, bind_address=172.20.72.101) -> false",
            // Tier 2 / Tier 3 lines: kept.
            "1794483594926 4 PeerShare: dialing back consumer=7ETk path=0",
            "1794483594934 4 Relay dial failed: timeout",
            "1794483594934 4 QUIC accept failed: cert mismatch",
            // Unparseable lines are kept, never dropped.
            "garbage line without a timestamp",
            "1794483594934",
        ]
        .join("\n");
        let filtered = filter_diagnostics_noise(&log);
        // All five Tier 1 lines are gone.
        assert!(!filtered.contains("Sending heartbeat ping"));
        assert!(!filtered.contains("Heartbeat pong received"));
        assert!(!filtered.contains("protect_fd(fd=881) -> true"));
        assert!(
            !filtered.contains(
                "bind_socket_to_network(fd=980, bind_address=172.20.72.101) -> true"
            )
        );
        // Failure variants and Tier 2/3 lines survive.
        assert!(filtered.contains("protect_fd(fd=881) -> false"));
        assert!(filtered.contains(
            "bind_socket_to_network(fd=980, bind_address=172.20.72.101) -> false"
        ));
        assert!(filtered.contains("PeerShare: dialing back"));
        assert!(filtered.contains("Relay dial failed"));
        assert!(filtered.contains("QUIC accept failed"));
        assert!(filtered.contains("garbage line without a timestamp"));
        assert_eq!(filtered.lines().count(), 7);
    }

    #[test]
    fn diagnostics_noise_filter_empty_when_all_noise() {
        let log = "1794483579223 4 Sending heartbeat ping seq=1\n\
                   1794483579329 4 Heartbeat pong received: seq=1 rtt=10ms\n";
        assert!(filter_diagnostics_noise(log).trim().is_empty());
    }

    #[test]
    fn diagnostics_noise_filter_matches_real_upload_lines() {
        // Lines copied verbatim from a real OnePlus diagnostics upload
        // (~/workspace/diag-content/f1.log): the filter must drop the
        // Tier 1 lines and keep a Tier 2 line from the same file.
        let log = "1794483579223 4 Sending heartbeat ping seq=1544\n\
                   1794483579329 4 Heartbeat pong received: seq=1544 rtt=107ms\n\
                   1794483594934 4 protect_fd(fd=881) -> true\n\
                   1794483595316 4 bind_socket_to_network(fd=980, bind_address=172.20.72.101) -> true\n\
                   1794483594926 4 PeerShare: dialing back consumer=7ETkjYV/PfsDew780IuI6ZV57nRaJIHmpdtWuOGMK2o= path=0\n";
        let filtered = filter_diagnostics_noise(log);
        assert_eq!(filtered.lines().count(), 1);
        assert!(filtered.contains("PeerShare: dialing back"));
    }
}
