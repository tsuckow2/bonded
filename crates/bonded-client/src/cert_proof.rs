//! Client-side certificate-proof bootstrapping.
//!
//! Flow:
//! 1. Open a TLS connection with validation *disabled* (the cert may be
//!    self-signed — that is the whole point of this bootstrap).
//! 2. Capture the leaf certificate's DER bytes from the TLS handshake.
//! 3. Send `GET /v1/bootstrap/cert-proof HTTP/1.1` over the open TLS stream.
//! 4. Parse the JSON response `{cert_fingerprint, ed25519_signature}`.
//! 5. Verify the ed25519 signature over `cert_fingerprint` using the
//!    server's public key (already trusted from the QR pairing scan).
//! 6. Confirm the received cert's SHA-256 fingerprint matches the value in
//!    the response (detects transparent MITM relays).
//! 7. Return the `"sha256:<hex>"` fingerprint string.  The caller should
//!    persist this as `client.tls_cert_fingerprint` and use it to pin
//!    subsequent TLS connections.
//!
//! ## Pinning future connections
//!
//! Use [`make_pinned_tls_config`] to build a `rustls::ClientConfig` that
//! accepts a server cert if and only if its SHA-256 fingerprint matches the
//! pinned value.  Pass it to `tokio_tungstenite::client_async_tls_with_config`
//! as `Some(Connector::Rustls(...))`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bonded_core::config::SocketProtectFn;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio_rustls::TlsConnector;

/// Marker embedded in the message of cert-proof errors that represent a
/// *verification* failure: the endpoint produced a well-formed proof, but it
/// does not check out against the paired server key (signature invalid, or
/// the signed fingerprint does not match the certificate actually presented).
///
/// This class of failure means "the server's identity key changed, or this
/// connection is being steered to a different server" and callers must treat
/// it as fatal — never as a cue to fall back to CA validation. Proof
/// *reachability* failures (connect errors, non-200 status, malformed JSON,
/// missing fields) are deliberately NOT marked: they say nothing about the
/// server's identity.
pub const IDENTITY_MISMATCH_MARKER: &str = "server-identity-mismatch";

/// True when `err` (or any cause in its chain) is a cert-proof verification
/// failure — see [`IDENTITY_MISMATCH_MARKER`].
pub fn is_identity_mismatch_error(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.to_string().contains(IDENTITY_MISMATCH_MARKER))
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Fetch the server's TLS cert fingerprint via the bootstrap cert-proof
/// endpoint, verify the ed25519 signature, and return the fingerprint.
///
/// `server_public_key_b64` must be the standard-base64 ed25519 public key
/// from the pairing QR — it is used to verify the signature in the response.
///
/// `socket_protect` is an optional Android VPN socket-protect callback.  When
/// the VPN tunnel is already active the cert-proof TCP socket must be protected
/// before `connect()` is called, otherwise the packet would be routed through
/// the tunnel that is still being established (deadlock).  Pass
/// `config.socket_protect.as_ref()` from the calling context; on non-Android
/// this will always be `None` and the argument is a no-op.
///
/// # Security
///
/// The initial TLS connection is made with certificate validation **disabled**.
/// An active MITM who presents its own cert will be detected in step 6 because
/// the fingerprint of the received cert will not match the signed fingerprint
/// in the response (which was signed by the real server's ed25519 key).
pub async fn fetch_and_verify_cert_proof(
    host: &str,
    port: u16,
    server_public_key_b64: &str,
    socket_protect: Option<&SocketProtectFn>,
    dial_address: Option<&str>,
) -> anyhow::Result<String> {
    let captured_cert: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));

    // Build a TLS config that skips normal cert validation but captures the
    // leaf cert bytes.
    let connector = TlsConnector::from(make_insecure_capture_tls_config(captured_cert.clone()));

    // TCP connect — use a raw TcpSocket so we can protect the fd before
    // connecting on Android (avoids routing the cert-proof traffic through
    // the VPN tunnel that we are in the process of establishing).
    let connect_target = dial_address
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{host}:{port}"));
    let addr: SocketAddr = tokio::net::lookup_host(&connect_target)
        .await
        .map_err(|e| anyhow::anyhow!("failed to resolve {connect_target}: {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses for {connect_target}"))?;
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    #[cfg(unix)]
    if let Some(protect) = socket_protect {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        if !protect.0(fd) {
            anyhow::bail!("failed to protect cert-proof socket from VPN capture (fd={fd})");
        }
    }
    let tcp = socket.connect(addr).await?;

    // TLS handshake (skips validation, captures cert)
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| anyhow::anyhow!("invalid TLS server name: {host}"))?;
    let mut tls = connector.connect(server_name, tcp).await?;

    // Plain HTTP GET over the insecure TLS channel
    let request = format!(
        "GET /v1/bootstrap/cert-proof HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;

    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await?;
    let response = std::str::from_utf8(&raw)
        .map_err(|_| anyhow::anyhow!("non-UTF8 in cert-proof response"))?;

    // Extract JSON body (everything after the blank line that ends the headers)
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("no HTTP body in cert-proof response"))?;

    // Parse status line
    let status_line = response.lines().next().unwrap_or("");
    if !status_line.contains("200") {
        anyhow::bail!("cert-proof endpoint returned non-200 status: {status_line} (body: {body})");
    }

    let captured = captured_cert.lock().unwrap().clone().ok_or_else(|| {
        anyhow::anyhow!("no server certificate was captured during TLS handshake")
    })?;

    verify_cert_proof_response(&captured, server_public_key_b64, body.trim())
}

pub fn make_insecure_capture_tls_config(
    captured_cert: Arc<Mutex<Option<Vec<u8>>>>,
) -> Arc<ClientConfig> {
    let verifier = Arc::new(CapturingVerifier {
        captured: captured_cert,
    });
    Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    )
}

pub fn verify_cert_proof_response(
    presented_cert_der: &[u8],
    server_public_key_b64: &str,
    response_body: &str,
) -> anyhow::Result<String> {
    let parsed: serde_json::Value = serde_json::from_str(response_body)
        .map_err(|e| anyhow::anyhow!("invalid JSON in cert-proof response: {e}"))?;

    let fingerprint = parsed["cert_fingerprint"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("cert-proof response missing 'cert_fingerprint'"))?;
    let signature = parsed["ed25519_signature"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("cert-proof response missing 'ed25519_signature'"))?;

    bonded_core::auth::verify_signature(server_public_key_b64, fingerprint.as_bytes(), signature)
        .map_err(|e| {
            anyhow::anyhow!(
                "{IDENTITY_MISMATCH_MARKER}: cert-proof signature verification failed: {e}"
            )
        })?;

    let computed = compute_fingerprint(presented_cert_der);
    if computed != fingerprint {
        anyhow::bail!(
            "{IDENTITY_MISMATCH_MARKER}: cert-proof fingerprint mismatch: server presented cert with fingerprint {computed} but cert-proof response claimed {fingerprint}. This may indicate an active MITM."
        );
    }

    Ok(fingerprint.to_owned())
}

/// Build a `rustls::ClientConfig` that accepts server certs if and only if the
/// leaf cert's SHA-256 fingerprint matches `expected_fingerprint`
/// (`"sha256:<hex>"`).
///
/// Use with `Connector::Rustls(make_pinned_tls_config(...))` in
/// `tokio_tungstenite::client_async_tls_with_config`.
pub fn make_pinned_tls_config(expected_fingerprint: impl Into<String>) -> Arc<ClientConfig> {
    let verifier = Arc::new(PinnedCertVerifier {
        expected: expected_fingerprint.into(),
    });
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Arc::new(config)
}

/// Compute `"sha256:<lowercase hex>"` of the raw DER bytes of a certificate.
pub fn compute_fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

// ── Dangerous cert verifiers ──────────────────────────────────────────────────

/// A `ServerCertVerifier` that skips all validation but captures the leaf cert.
#[derive(Debug)]
struct CapturingVerifier {
    captured: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        *self.captured.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// A `ServerCertVerifier` that accepts a server cert only if its SHA-256
/// fingerprint matches the pinned value.
#[derive(Debug)]
struct PinnedCertVerifier {
    expected: String,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual = compute_fingerprint(end_entity.as_ref());
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "{IDENTITY_MISMATCH_MARKER}: TLS certificate fingerprint mismatch: got {actual}, expected {}",
                self.expected
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonded_core::auth::{sign_bytes, DeviceKeypair};

    fn proof_body(keypair: &DeviceKeypair, fingerprint: &str) -> String {
        let signature = sign_bytes(keypair, fingerprint.as_bytes())
            .expect("test keypair should sign");
        serde_json::json!({
            "cert_fingerprint": fingerprint,
            "ed25519_signature": signature,
        })
        .to_string()
    }

    #[test]
    fn valid_proof_verifies_and_returns_fingerprint() {
        let server = DeviceKeypair::generate();
        let cert_der = b"fake server cert der bytes";
        let fingerprint = compute_fingerprint(cert_der);
        let body = proof_body(&server, &fingerprint);

        let verified = verify_cert_proof_response(cert_der, &server.public_key_b64, &body)
            .expect("valid proof should verify");
        assert_eq!(verified, fingerprint);
    }

    #[test]
    fn proof_signed_by_another_key_is_an_identity_mismatch() {
        let real_server = DeviceKeypair::generate();
        let other_server = DeviceKeypair::generate();
        let cert_der = b"fake server cert der bytes";
        let fingerprint = compute_fingerprint(cert_der);
        // The endpoint presents a proof signed by a DIFFERENT key than the
        // one this client paired with (server re-keyed, or steering).
        let body = proof_body(&other_server, &fingerprint);

        let err = verify_cert_proof_response(cert_der, &real_server.public_key_b64, &body)
            .expect_err("proof signed by another key must not verify");
        let wrapped = err.context("session establishment wrapper");
        assert!(
            is_identity_mismatch_error(&wrapped),
            "signature failure must classify as identity mismatch through context layers: {wrapped:#}"
        );
    }

    #[test]
    fn pinned_verifier_rejection_is_an_identity_mismatch() {
        // The pinned-fingerprint flavor of verification (WSS/QUIC when a
        // fingerprint is stored from the pairing): a presented cert that
        // does not match the pin is the same identity evidence as a bad
        // cert-proof, and must classify the same way so session
        // establishment fails closed and the app can surface it as a
        // possible interception on that path.
        let verifier = PinnedCertVerifier {
            expected: compute_fingerprint(b"the paired server's cert"),
        };
        let presented = CertificateDer::from(&b"some other cert"[..]);
        let server_name = ServerName::try_from("server.example").expect("valid dns name");
        let err = verifier
            .verify_server_cert(
                &presented,
                &[],
                &server_name,
                &[],
                UnixTime::now(),
            )
            .expect_err("a cert that does not match the pin must be rejected");
        let wrapped = anyhow::Error::new(err).context("wss connect wrapper");
        assert!(
            is_identity_mismatch_error(&wrapped),
            "pinned fingerprint rejection must classify as identity mismatch: {wrapped:#}"
        );
    }

    #[test]
    fn signed_fingerprint_that_differs_from_presented_cert_is_an_identity_mismatch() {
        let server = DeviceKeypair::generate();
        let presented = b"presented cert bytes";
        let claimed = compute_fingerprint(b"some other cert bytes");
        // Signature is valid over the claimed fingerprint, but the cert on
        // this connection computes to a different one (MITM relay shape).
        let body = proof_body(&server, &claimed);

        let err = verify_cert_proof_response(presented, &server.public_key_b64, &body)
            .expect_err("fingerprint mismatch must not verify");
        assert!(
            is_identity_mismatch_error(&err),
            "fingerprint mismatch must classify as identity mismatch: {err:#}"
        );
    }

    #[test]
    fn malformed_proof_is_not_an_identity_mismatch() {
        let server = DeviceKeypair::generate();
        let err = verify_cert_proof_response(b"cert", &server.public_key_b64, "not json at all")
            .expect_err("malformed body must error");
        assert!(
            !is_identity_mismatch_error(&err),
            "reachability/parse failures must not classify as identity mismatch: {err:#}"
        );
    }
}
