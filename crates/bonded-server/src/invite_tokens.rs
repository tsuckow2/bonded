use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bonded_core::auth::{InviteToken, InviteTokenManager};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct InviteTokensFile {
    #[serde(default)]
    tokens: Vec<InviteToken>,
}

pub fn ensure_startup_invite(path: impl AsRef<Path>) -> anyhow::Result<InviteToken> {
    let path = path.as_ref();
    let mut manager = load_manager(path)?;

    if let Some(existing) = manager
        .all_tokens()
        .into_iter()
        .find(|token| token.is_usable())
    {
        return Ok(existing);
    }

    let expires_at = format!(
        "unix:{}",
        unix_timestamp_after(Duration::from_secs(24 * 60 * 60))?
    );
    let created = manager.issue_token(expires_at, 1);
    persist_manager(path, &manager)?;
    Ok(created)
}

pub fn redeem_invite_token(
    path: impl AsRef<Path>,
    token: &str,
    presented_key_b64: &str,
) -> anyhow::Result<bool> {
    let path = path.as_ref();
    let mut manager = load_manager(path)?;
    let redeemed = manager.redeem(token, presented_key_b64).is_ok();
    if redeemed {
        persist_manager(path, &manager)?;
    }

    Ok(redeemed)
}

/// Mint a single-use invite bound to one device key (the QR-pairing flow:
/// a paired phone asks the server for an invite its TV can redeem). The
/// token is persisted to the same file the auth handshake redeem path
/// reads, so it is usable immediately with no restart.
pub fn mint_invite_token(
    path: impl AsRef<Path>,
    bound_key_b64: &str,
    validity_secs: u64,
) -> anyhow::Result<InviteToken> {
    let path = path.as_ref();
    let mut manager = load_manager(path)?;
    let expires_at = format!(
        "unix:{}",
        unix_timestamp_after(Duration::from_secs(validity_secs))?
    );
    let created = manager.issue_bound_token(expires_at, 1, Some(bound_key_b64.to_owned()));
    persist_manager(path, &manager)?;
    Ok(created)
}

fn load_manager(path: &Path) -> anyhow::Result<InviteTokenManager> {
    if !path.exists() {
        return Ok(InviteTokenManager::default());
    }

    let raw = fs::read_to_string(path)?;
    let parsed: InviteTokensFile = toml::from_str(&raw)?;
    Ok(InviteTokenManager::from_tokens(parsed.tokens))
}

fn persist_manager(path: &Path, manager: &InviteTokenManager) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let doc = InviteTokensFile {
        tokens: manager.all_tokens(),
    };
    let toml_data = toml::to_string_pretty(&doc)?;
    fs::write(path, toml_data)?;
    Ok(())
}

fn unix_timestamp_after(offset: Duration) -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .saturating_add(offset)
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::{ensure_startup_invite, redeem_invite_token};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("bonded-{name}-{stamp}.toml"))
    }

    #[test]
    fn ensure_startup_invite_creates_file_and_token() {
        let path = temp_file_path("invite-bootstrap");
        let token = ensure_startup_invite(&path).expect("startup token should be created");

        assert!(!token.token.is_empty());
        assert_eq!(token.uses_remaining, 1);
        assert!(path.exists());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn ensure_startup_invite_reuses_existing_usable_token() {
        let path = temp_file_path("invite-reuse");
        fs::write(
            &path,
            r#"[[tokens]]
token = "existing"
expires_at = "unix:9999999999"
uses_remaining = 1
"#,
        )
        .expect("seed token file should be written");

        let token = ensure_startup_invite(&path).expect("existing token should be reused");
        assert_eq!(token.token, "existing");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn redeem_invite_token_decrements_and_persists() {
        let path = temp_file_path("invite-redeem");
        fs::write(
            &path,
            r#"[[tokens]]
token = "one-shot"
expires_at = "unix:9999999999"
uses_remaining = 1
"#,
        )
        .expect("seed token file should be written");

        assert!(redeem_invite_token(&path, "one-shot", "any-key").expect("redeem should succeed"));
        assert!(!redeem_invite_token(&path, "one-shot", "any-key").expect("second redeem should fail"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn mint_invite_token_is_bound_and_redeemable_only_by_its_target() {
        use super::mint_invite_token;
        let path = temp_file_path("invite-mint");
        let created = mint_invite_token(&path, "tv-key", 600).expect("mint should succeed");
        assert!(!created.token.is_empty());
        assert_eq!(created.uses_remaining, 1);

        assert!(!redeem_invite_token(&path, &created.token, "other-key")
            .expect("wrong-key redeem should report false"));
        assert!(redeem_invite_token(&path, &created.token, "tv-key")
            .expect("right-key redeem should succeed"));

        let _ = fs::remove_file(path);
    }
}
