//! Mint a bound invite for another device (QR-pairing flow).
//!
//! A paired phone asks its server for a single-use invite bound to the TV's
//! device key. The request mirrors the diagnostics upload envelope: it is
//! signed with the phone's device key and POSTed to the server's bootstrap
//! endpoint over the scheme candidates, first success wins. The server only
//! mints for already-authorized device keys, and the bound token is useless
//! to anyone but the target device — which is what makes the phone's
//! plaintext-LAN delivery to the TV safe to intercept.

use bonded_core::auth::{sign_bytes, DeviceKeypair, MintInviteRequest};
use bonded_core::config::ClientConfig;

use crate::{bootstrap_scheme_candidates, request_bootstrap_json};

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Mint a single-use invite bound to `target_device_public_key` from the
/// server in `config`, authenticated by `keypair`. Returns the token string.
pub async fn mint_invite_for_device(
    config: &ClientConfig,
    keypair: &DeviceKeypair,
    target_device_public_key: &str,
) -> anyhow::Result<String> {
    let bootstrap_address = config.client.server_public_address.trim();
    if bootstrap_address.is_empty() {
        anyhow::bail!("server_public_address is required to mint an invite");
    }
    if target_device_public_key.trim().is_empty() {
        anyhow::bail!("target_device_public_key is required to mint an invite");
    }
    let mut request = MintInviteRequest {
        device_public_key: keypair.public_key_b64.clone(),
        target_device_public_key: target_device_public_key.trim().to_owned(),
        requested_at_unix: now_unix_secs(),
        signature: String::new(),
    };
    request.signature = sign_bytes(keypair, &request.signed_payload()?)?;
    let request_body = serde_json::to_string(&request)?;
    let mut errors = Vec::new();
    for scheme in bootstrap_scheme_candidates(config) {
        match request_bootstrap_json(
            config,
            scheme,
            bootstrap_address,
            "POST",
            "/v1/bootstrap/mint-invite",
            Some(&request_body),
        )
        .await
        {
            Ok(body) => {
                let token = serde_json::from_str::<serde_json::Value>(&body)?
                    .get("invite_token")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        anyhow::anyhow!("mint-invite response missing invite_token: {body}")
                    })?
                    .to_owned();
                if token.is_empty() {
                    anyhow::bail!("mint-invite response contained an empty invite_token");
                }
                return Ok(token);
            }
            Err(err) => errors.push(format!("scheme={scheme:?}: {err:#}")),
        }
    }
    anyhow::bail!(
        "failed to mint invite via {bootstrap_address}: {}",
        errors.join(" | ")
    )
}

#[cfg(test)]
mod tests {
    use super::mint_invite_for_device;
    use bonded_core::auth::{verify_signature, DeviceKeypair, MintInviteRequest};
    use bonded_core::config::ClientConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn mint_request_signed_payload_excludes_signature() {
        let device = DeviceKeypair::generate();
        let request = MintInviteRequest {
            device_public_key: device.public_key_b64.clone(),
            target_device_public_key: "tv-key".to_owned(),
            requested_at_unix: 1_760_000_000,
            signature: "not-part-of-payload".to_owned(),
        };
        let payload = request
            .signed_payload()
            .expect("payload should serialize");
        let parsed: serde_json::Value =
            serde_json::from_slice(&payload).expect("payload should be JSON");
        assert_eq!(parsed["device_public_key"], device.public_key_b64);
        assert_eq!(parsed["target_device_public_key"], "tv-key");
        assert_eq!(parsed["requested_at_unix"], 1_760_000_000);
        assert!(parsed.get("signature").is_none());
    }

    #[tokio::test]
    async fn mint_posts_signed_request_and_returns_token() {
        let phone = DeviceKeypair::generate();
        let tv = DeviceKeypair::generate();

        // Minimal plaintext-HTTP bootstrap endpoint: capture the request,
        // answer with a minted token, then close (the client reads to end).
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should resolve");
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept should succeed");
            let mut raw = Vec::new();
            let mut buf = [0_u8; 4096];
            // Read headers, then the Content-Length body.
            let mut header_end = None;
            while header_end.is_none() {
                let n = stream.read(&mut buf).await.expect("request should be readable");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if let Some(pos) = find_subslice(&raw, b"\r\n\r\n") {
                    header_end = Some(pos + 4);
                }
            }
            let header_end = header_end.expect("request should have headers");
            let headers = String::from_utf8_lossy(&raw[..header_end]).into_owned();
            let content_length: usize = headers
                .lines()
                .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|line| line.split(':').nth(1)?.trim().parse().ok())
                .unwrap_or(0);
            while raw.len() < header_end + content_length {
                let n = stream.read(&mut buf).await.expect("body should be readable");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
            }
            let body = String::from_utf8_lossy(&raw[header_end..]).into_owned();
            let response_body = r#"{"invite_token":"minted-for-tv"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("response should be writable");
            stream.shutdown().await.expect("shutdown should succeed");
            body
        });

        let mut config = ClientConfig::default();
        config.client.server_public_address = addr.to_string();
        config.client.server_websocket_address = format!("ws://{addr}");

        let token = mint_invite_for_device(&config, &phone, &tv.public_key_b64)
            .await
            .expect("mint should succeed");
        assert_eq!(token, "minted-for-tv");

        let captured = server_task.await.expect("server task should join");
        let request: MintInviteRequest =
            serde_json::from_str(&captured).expect("captured body should parse");
        assert_eq!(request.device_public_key, phone.public_key_b64);
        assert_eq!(request.target_device_public_key, tv.public_key_b64);
        verify_signature(
            &request.device_public_key,
            &request.signed_payload().expect("payload should serialize"),
            &request.signature,
        )
        .expect("captured request signature should verify");
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }
}
