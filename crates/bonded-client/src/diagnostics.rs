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
pub fn spawn_diagnostics_uploader(
    config: ClientConfig,
    client_build: String,
    log_source: DiagnosticsLogSource,
    on_error: DiagnosticsErrorSink,
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
        tokio::time::sleep(Duration::from_secs(FIRST_UPLOAD_DELAY_SECS)).await;
        loop {
            if let Some(contents) = log_source() {
                if let Err(err) = uploader.upload_if_changed(&contents).await {
                    on_error(format!("Diagnostics upload failed: {err:#}"));
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
        let log_text = tail_cap_log(contents);
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
}
