//! Device-signed diagnostic log uploads.
//!
//! A client with diagnostics upload enabled periodically POSTs its
//! on-device diagnostic log ring to the server's
//! `/v1/bootstrap/diagnostics` endpoint using this envelope. The
//! signature pattern mirrors the peer-share introduction request: the
//! device key signs a canonical JSON payload that excludes the
//! signature itself, and the server only accepts uploads from device
//! keys in its authorized set.

use serde::{Deserialize, Serialize};

/// Maximum accepted `log_text` size, in bytes. The client tail-caps
/// its ring at the same bound before sending.
pub const MAX_DIAGNOSTICS_LOG_BYTES: usize = 512 * 1024;

/// How many uploaded files the server keeps per device (newest first).
pub const DIAGNOSTICS_FILES_PER_DEVICE: usize = 192;

/// Default upload cadence for clients, in seconds.
pub const DEFAULT_DIAGNOSTICS_PERIOD_SECS: u64 = 900;

/// Clamp a configured upload period into the supported range.
pub fn clamp_diagnostics_period_secs(period_secs: u64) -> u64 {
    period_secs.clamp(60, 3600)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticsUploadRequest {
    pub device_public_key: String,
    /// Client build identifier (Android versionCode as a string, or a
    /// version string on other platforms). Used in the stored file
    /// name; free-form.
    pub client_build: String,
    /// When the client captured this upload (Unix epoch seconds).
    pub captured_at_unix: u64,
    /// The diagnostic log contents (UTF-8 text, tail-capped by the
    /// client at [`MAX_DIAGNOSTICS_LOG_BYTES`]).
    pub log_text: String,
    pub signature: String,
}

impl DiagnosticsUploadRequest {
    /// Canonical bytes the device key signs: every field except the
    /// signature itself, as a JSON object.
    pub fn signed_payload(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(&serde_json::json!({
            "device_public_key": self.device_public_key,
            "client_build": self.client_build,
            "captured_at_unix": self.captured_at_unix,
            "log_text": self.log_text,
        }))?)
    }
}

/// Filesystem-safe directory name for a device public key: base64url
/// without padding (device keys are standard base64 and may contain
/// `+`, `/`, and `=`).
pub fn diagnostics_device_dir_name(device_public_key: &str) -> String {
    device_public_key
        .chars()
        .filter(|ch| *ch != '=')
        .map(|ch| match ch {
            '+' => '-',
            '/' => '_',
            ch => ch,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> DiagnosticsUploadRequest {
        DiagnosticsUploadRequest {
            device_public_key: "abc+/def=".to_owned(),
            client_build: "146".to_owned(),
            captured_at_unix: 1_760_000_000,
            log_text: "line one\nline two\n".to_owned(),
            signature: "sig".to_owned(),
        }
    }

    #[test]
    fn signed_payload_excludes_signature_and_covers_log() {
        let payload = String::from_utf8(
            sample_request()
                .signed_payload()
                .expect("payload serializes"),
        )
        .expect("payload is utf8");
        assert!(payload.contains("device_public_key"));
        assert!(payload.contains("line one"));
        assert!(!payload.contains("\"signature\""));
        assert!(!payload.contains("\"sig\""));
    }

    #[test]
    fn device_dir_name_is_filesystem_safe() {
        assert_eq!(
            diagnostics_device_dir_name("abc+/def="),
            "abc-_def".to_owned()
        );
        assert_eq!(diagnostics_device_dir_name("plain"), "plain".to_owned());
    }

    #[test]
    fn period_clamps_into_range() {
        assert_eq!(clamp_diagnostics_period_secs(0), 60);
        assert_eq!(clamp_diagnostics_period_secs(900), 900);
        assert_eq!(clamp_diagnostics_period_secs(99_999), 3600);
    }
}
