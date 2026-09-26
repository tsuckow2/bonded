use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub public_key_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteToken {
    pub token: String,
    pub expires_at: String,
    pub uses_remaining: u32,
}

#[derive(Debug, Error)]
pub enum InviteTokenError {
    #[error("invite token not found")]
    NotFound,
    #[error("invite token has no remaining uses")]
    Exhausted,
}

#[derive(Debug, Default)]
pub struct InviteTokenManager {
    tokens: HashMap<String, InviteToken>,
}

impl InviteTokenManager {
    pub fn from_tokens(tokens: Vec<InviteToken>) -> Self {
        let tokens = tokens
            .into_iter()
            .map(|token| (token.token.clone(), token))
            .collect();
        Self { tokens }
    }

    pub fn issue_token(&mut self, expires_at: String, uses_remaining: u32) -> InviteToken {
        let token = InviteToken {
            token: generate_invite_token_value(),
            expires_at,
            uses_remaining,
        };
        self.tokens.insert(token.token.clone(), token.clone());
        token
    }

    pub fn redeem(&mut self, token_value: &str) -> Result<InviteToken, InviteTokenError> {
        let token = self
            .tokens
            .get_mut(token_value)
            .ok_or(InviteTokenError::NotFound)?;

        if token.uses_remaining == 0 {
            return Err(InviteTokenError::Exhausted);
        }

        token.uses_remaining -= 1;
        Ok(token.clone())
    }

    pub fn get(&self, token_value: &str) -> Option<&InviteToken> {
        self.tokens.get(token_value)
    }

    pub fn all_tokens(&self) -> Vec<InviteToken> {
        self.tokens.values().cloned().collect()
    }
}

fn generate_invite_token_value() -> String {
    let mut raw = [0_u8; 24];
    OsRng.fill_bytes(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeypair {
    pub private_key_b64: String,
    pub public_key_b64: String,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid base64 key material")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("invalid ed25519 private key length: expected 32 bytes, got {0}")]
    InvalidPrivateKeyLength(usize),
    #[error("invalid ed25519 public key length: expected 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),
    #[error("invalid ed25519 signature length: expected 64 bytes, got {0}")]
    InvalidSignatureLength(usize),
    #[error("challenge signature verification failed")]
    SignatureVerificationFailed,
}

impl DeviceKeypair {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        Self::from_signing_key(&signing_key)
    }

    pub fn from_private_key_b64(private_key_b64: &str) -> Result<Self, AuthError> {
        let private_key = base64::engine::general_purpose::STANDARD.decode(private_key_b64)?;
        let private_bytes: [u8; 32] = private_key
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidPrivateKeyLength(private_key.len()))?;

        let signing_key = SigningKey::from_bytes(&private_bytes);
        Ok(Self::from_signing_key(&signing_key))
    }

    pub fn signing_key(&self) -> Result<SigningKey, AuthError> {
        let private_key =
            base64::engine::general_purpose::STANDARD.decode(&self.private_key_b64)?;
        let private_bytes: [u8; 32] = private_key
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidPrivateKeyLength(private_key.len()))?;
        Ok(SigningKey::from_bytes(&private_bytes))
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, AuthError> {
        Ok(self.signing_key()?.verifying_key())
    }

    fn from_signing_key(signing_key: &SigningKey) -> Self {
        let private_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes());
        let public_key_b64 = base64::engine::general_purpose::STANDARD
            .encode(signing_key.verifying_key().to_bytes());

        Self {
            private_key_b64,
            public_key_b64,
        }
    }
}

pub fn create_auth_challenge() -> String {
    let mut raw = [0_u8; 32];
    OsRng.fill_bytes(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

pub fn sign_auth_challenge(
    keypair: &DeviceKeypair,
    challenge_b64: &str,
) -> Result<String, AuthError> {
    let signing_key = keypair.signing_key()?;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(challenge_b64)?;
    let signature = signing_key.sign(&challenge);
    Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
}

/// Sign arbitrary bytes with the keypair's private key.
/// The signature is returned as standard base64.
pub fn sign_bytes(keypair: &DeviceKeypair, message: &[u8]) -> Result<String, AuthError> {
    let signing_key = keypair.signing_key()?;
    let signature = signing_key.sign(message);
    Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
}

/// Verify an ed25519 signature over arbitrary bytes.
///
/// `public_key_b64` — standard base64 encoded 32-byte ed25519 public key  
/// `message`        — the signed message bytes  
/// `signature_b64`  — standard base64 encoded 64-byte signature (as produced by `sign_bytes`)
pub fn verify_signature(
    public_key_b64: &str,
    message: &[u8],
    signature_b64: &str,
) -> Result<(), AuthError> {
    let public_key = base64::engine::general_purpose::STANDARD.decode(public_key_b64)?;
    let public_key_bytes: [u8; 32] = public_key
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidPublicKeyLength(public_key.len()))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| AuthError::InvalidPublicKeyLength(public_key.len()))?;

    let sig_bytes = base64::engine::general_purpose::STANDARD.decode(signature_b64)?;
    let sig_bytes: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidSignatureLength(sig_bytes.len()))?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(message, &signature)
        .map_err(|_| AuthError::SignatureVerificationFailed)
}

/// Load a `DeviceKeypair` from `path`, or create and persist a new one if the
/// file does not exist.  The private key is stored as raw base64 (one line).
/// Fails if the file exists but cannot be read or parsed.
pub fn load_or_create_keypair(path: &Path) -> anyhow::Result<DeviceKeypair> {
    if path.exists() {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read keypair file {}: {e}", path.display()))?;
        let private_key_b64 = raw.trim();
        DeviceKeypair::from_private_key_b64(private_key_b64)
            .map_err(|e| anyhow::anyhow!("failed to parse keypair at {}: {e}", path.display()))
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!("failed to create key directory {}: {e}", parent.display())
            })?;
        }
        let keypair = DeviceKeypair::generate();
        std::fs::write(path, format!("{}\n", keypair.private_key_b64))
            .map_err(|e| anyhow::anyhow!("failed to write keypair to {}: {e}", path.display()))?;
        Ok(keypair)
    }
}

pub fn verify_auth_challenge(
    public_key_b64: &str,
    challenge_b64: &str,
    signature_b64: &str,
) -> Result<(), AuthError> {
    let public_key = base64::engine::general_purpose::STANDARD.decode(public_key_b64)?;
    let public_key_bytes: [u8; 32] = public_key
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidPublicKeyLength(public_key.len()))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| AuthError::InvalidPublicKeyLength(public_key.len()))?;

    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(challenge_b64)?;
    let signature = base64::engine::general_purpose::STANDARD.decode(signature_b64)?;
    let signature_bytes: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidSignatureLength(signature.len()))?;
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify(&challenge, &signature)
        .map_err(|_| AuthError::SignatureVerificationFailed)
}

impl InviteToken {
    pub fn is_usable(&self) -> bool {
        self.uses_remaining > 0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        create_auth_challenge, sign_auth_challenge, verify_auth_challenge, AuthError,
        DeviceKeypair, InviteToken, InviteTokenError, InviteTokenManager,
    };
    use base64::Engine;

    #[test]
    fn token_is_usable_when_remaining_uses_exist() {
        let token = InviteToken {
            token: "abc".to_owned(),
            expires_at: "2026-03-31T00:00:00Z".to_owned(),
            uses_remaining: 1,
        };
        assert!(token.is_usable());
    }

    #[test]
    fn token_not_usable_when_uses_are_zero() {
        let token = InviteToken {
            token: "abc".to_owned(),
            expires_at: "2026-03-31T00:00:00Z".to_owned(),
            uses_remaining: 0,
        };
        assert!(!token.is_usable());
    }

    #[test]
    fn generated_keypair_can_restore_verifying_key() {
        let keypair = DeviceKeypair::generate();
        let parsed = DeviceKeypair::from_private_key_b64(&keypair.private_key_b64)
            .expect("private key should parse");

        assert_eq!(parsed.public_key_b64, keypair.public_key_b64);
    }

    #[test]
    fn invalid_private_key_length_returns_error() {
        let short_key_b64 = base64::engine::general_purpose::STANDARD.encode([7_u8; 16]);
        let err = DeviceKeypair::from_private_key_b64(&short_key_b64)
            .expect_err("short private key should fail");
        assert!(matches!(err, AuthError::InvalidPrivateKeyLength(16)));
    }

    #[test]
    fn issued_token_can_be_redeemed_until_exhausted() {
        let mut manager = InviteTokenManager::default();
        let token = manager.issue_token("2026-04-01T00:00:00Z".to_owned(), 2);

        let first = manager
            .redeem(&token.token)
            .expect("first redeem should succeed");
        assert_eq!(first.uses_remaining, 1);

        let second = manager
            .redeem(&token.token)
            .expect("second redeem should succeed");
        assert_eq!(second.uses_remaining, 0);

        let err = manager
            .redeem(&token.token)
            .expect_err("third redeem should fail");
        assert!(matches!(err, InviteTokenError::Exhausted));
    }

    #[test]
    fn redeeming_unknown_token_fails() {
        let mut manager = InviteTokenManager::default();
        let err = manager
            .redeem("missing-token")
            .expect_err("unknown token should fail");
        assert!(matches!(err, InviteTokenError::NotFound));
    }

    #[test]
    fn signed_challenge_verifies_with_public_key() {
        let keypair = DeviceKeypair::generate();
        let challenge = create_auth_challenge();
        let signature =
            sign_auth_challenge(&keypair, &challenge).expect("challenge should be signable");

        verify_auth_challenge(&keypair.public_key_b64, &challenge, &signature)
            .expect("signature should verify");
    }

    #[test]
    fn tampered_challenge_fails_verification() {
        let keypair = DeviceKeypair::generate();
        let challenge = create_auth_challenge();
        let signature =
            sign_auth_challenge(&keypair, &challenge).expect("challenge should be signable");
        let bad_challenge = create_auth_challenge();

        let err = verify_auth_challenge(&keypair.public_key_b64, &bad_challenge, &signature)
            .expect_err("signature should fail against a different challenge");
        assert!(matches!(err, AuthError::SignatureVerificationFailed));
    }

    #[test]
    fn verify_signature_roundtrip() {
        let keypair = DeviceKeypair::generate();
        let message = b"sha256:abcdef1234567890";
        let sig = super::sign_bytes(&keypair, message).expect("sign_bytes should succeed");
        super::verify_signature(&keypair.public_key_b64, message, &sig)
            .expect("verify_signature should accept valid signature");
    }

    #[test]
    fn verify_signature_tampered_message_fails() {
        let keypair = DeviceKeypair::generate();
        let sig =
            super::sign_bytes(&keypair, b"correct message").expect("sign_bytes should succeed");
        let err = super::verify_signature(&keypair.public_key_b64, b"tampered message", &sig)
            .expect_err("verify_signature should reject signature over different message");
        assert!(matches!(err, AuthError::SignatureVerificationFailed));
    }

    #[test]
    fn verify_signature_wrong_key_fails() {
        let signer = DeviceKeypair::generate();
        let other = DeviceKeypair::generate();
        let sig = super::sign_bytes(&signer, b"hello").expect("sign_bytes should succeed");
        let err = super::verify_signature(&other.public_key_b64, b"hello", &sig)
            .expect_err("verify_signature should reject signature from a different key");
        assert!(matches!(err, AuthError::SignatureVerificationFailed));
    }
}
