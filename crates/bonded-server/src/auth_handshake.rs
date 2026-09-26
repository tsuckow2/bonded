use anyhow::Context;
use bonded_core::auth::{create_auth_challenge, verify_auth_challenge};
use bonded_core::transport::WebSocketTlsTransport;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::authorized_keys::{authorize_device_key, AuthorizedKeysStore};
use crate::invite_tokens::redeem_invite_token;

#[derive(Debug, Serialize, Deserialize)]
struct ClientHello {
    public_key_b64: String,
    #[serde(default)]
    invite_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ServerChallenge {
    challenge_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientProof {
    signature_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ServerAuthResult {
    status: String,
}

pub async fn perform_auth_handshake(
    stream: TcpStream,
    authorized_keys: AuthorizedKeysStore,
    invite_tokens_file: &Path,
) -> anyhow::Result<(String, TcpStream)> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let hello: ClientHello = read_json_line(&mut reader)
        .await
        .context("failed to read client hello")?;

    if !authorized_keys.is_authorized(&hello.public_key_b64) {
        let redeemed = if hello.invite_token.trim().is_empty() {
            false
        } else {
            redeem_invite_token(invite_tokens_file, &hello.invite_token)
                .context("failed to redeem invite token")?
        };

        if redeemed {
            let _added = authorize_device_key(authorized_keys.path(), &hello.public_key_b64)
                .context("failed to persist authorized key from invite redemption")?;
            authorized_keys
                .reload()
                .context("failed to reload authorized keys after invite redemption")?;
        } else {
            send_json_line(
                &mut write_half,
                &ServerAuthResult {
                    status: "unauthorized".to_owned(),
                },
            )
            .await?;
            anyhow::bail!("client key is not authorized");
        }
    }

    let challenge = create_auth_challenge();
    send_json_line(
        &mut write_half,
        &ServerChallenge {
            challenge_b64: challenge.clone(),
        },
    )
    .await?;

    let proof: ClientProof = read_json_line(&mut reader)
        .await
        .context("failed to read client proof")?;

    verify_auth_challenge(&hello.public_key_b64, &challenge, &proof.signature_b64)
        .context("challenge signature verification failed")?;

    send_json_line(
        &mut write_half,
        &ServerAuthResult {
            status: "ok".to_owned(),
        },
    )
    .await?;

    let read_half = reader.into_inner();
    let stream = read_half
        .reunite(write_half)
        .map_err(|_| anyhow::anyhow!("failed to reunite tcp stream after handshake"))?;

    Ok((hello.public_key_b64, stream))
}

pub async fn perform_websocket_auth_handshake(
    transport: &mut WebSocketTlsTransport,
    authorized_keys: AuthorizedKeysStore,
    invite_tokens_file: &Path,
) -> anyhow::Result<String> {
    let hello_line = transport
        .recv_text()
        .await
        .context("failed to read websocket client hello")?;
    let hello: ClientHello = serde_json::from_str(hello_line.trim_end())?;

    if !authorized_keys.is_authorized(&hello.public_key_b64) {
        let redeemed = if hello.invite_token.trim().is_empty() {
            false
        } else {
            redeem_invite_token(invite_tokens_file, &hello.invite_token)
                .context("failed to redeem invite token")?
        };

        if redeemed {
            let _added = authorize_device_key(authorized_keys.path(), &hello.public_key_b64)
                .context("failed to persist authorized key from invite redemption")?;
            authorized_keys
                .reload()
                .context("failed to reload authorized keys after invite redemption")?;
        } else {
            transport
                .send_text(&serde_json::to_string(&ServerAuthResult {
                    status: "unauthorized".to_owned(),
                })?)
                .await?;
            anyhow::bail!("client key is not authorized");
        }
    }

    let challenge = create_auth_challenge();
    transport
        .send_text(&serde_json::to_string(&ServerChallenge {
            challenge_b64: challenge.clone(),
        })?)
        .await?;

    let proof_line = transport
        .recv_text()
        .await
        .context("failed to read websocket client proof")?;
    let proof: ClientProof = serde_json::from_str(proof_line.trim_end())?;

    verify_auth_challenge(&hello.public_key_b64, &challenge, &proof.signature_b64)
        .context("challenge signature verification failed")?;

    transport
        .send_text(&serde_json::to_string(&ServerAuthResult {
            status: "ok".to_owned(),
        })?)
        .await?;

    Ok(hello.public_key_b64)
}

/// Run the authentication handshake over a QUIC transport.
///
/// This is the server side of the challenge-response auth handshake.  It uses
/// `QuicTransport::send_text` / `recv_text` (line-delimited JSON) which are
/// backed by the raw QUIC stream bytes — identical to the WebSocket text-frame
/// handshake in terms of wire encoding.
///
/// Returns the authenticated client's public key (base64).
pub async fn perform_quic_auth_handshake(
    transport: &mut bonded_core::transport::QuicTransport,
    invite_tokens_file: &str,
    authorized_keys: &AuthorizedKeysStore,
) -> anyhow::Result<String> {
    let hello_line = transport
        .recv_text()
        .await
        .context("QUIC: failed to read client hello")?;
    let hello: ClientHello =
        serde_json::from_str(hello_line.trim_end()).context("QUIC: invalid client hello JSON")?;

    if !authorized_keys.is_authorized(&hello.public_key_b64) {
        let redeemed = if hello.invite_token.trim().is_empty() {
            false
        } else {
            redeem_invite_token(
                std::path::Path::new(invite_tokens_file),
                &hello.invite_token,
            )
            .context("QUIC: failed to redeem invite token")?
        };

        if redeemed {
            let _added = authorize_device_key(authorized_keys.path(), &hello.public_key_b64)
                .context("QUIC: failed to persist authorized key")?;
            authorized_keys
                .reload()
                .context("QUIC: failed to reload authorized keys")?;
        } else {
            transport
                .send_text(&serde_json::to_string(&ServerAuthResult {
                    status: "unauthorized".to_owned(),
                })?)
                .await?;
            anyhow::bail!("QUIC: client key is not authorized");
        }
    }

    let challenge = create_auth_challenge();
    transport
        .send_text(&serde_json::to_string(&ServerChallenge {
            challenge_b64: challenge.clone(),
        })?)
        .await?;

    let proof_line = transport
        .recv_text()
        .await
        .context("QUIC: failed to read client proof")?;
    let proof: ClientProof =
        serde_json::from_str(proof_line.trim_end()).context("QUIC: invalid client proof JSON")?;

    verify_auth_challenge(&hello.public_key_b64, &challenge, &proof.signature_b64)
        .context("QUIC: challenge signature verification failed")?;

    transport
        .send_text(&serde_json::to_string(&ServerAuthResult {
            status: "ok".to_owned(),
        })?)
        .await?;

    Ok(hello.public_key_b64)
}

async fn read_json_line<T>(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> anyhow::Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let mut line = String::new();
    let read = reader.read_line(&mut line).await?;
    if read == 0 {
        anyhow::bail!("connection closed while reading auth message");
    }

    Ok(serde_json::from_str(line.trim_end())?)
}

async fn send_json_line<T>(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    message: &T,
) -> anyhow::Result<()>
where
    T: Serialize,
{
    let json = serde_json::to_string(message)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        perform_auth_handshake, ClientHello, ClientProof, ServerAuthResult, ServerChallenge,
    };
    use crate::authorized_keys::AuthorizedKeysStore;
    use bonded_core::auth::{sign_auth_challenge, DeviceKeypair};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    fn temp_file_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("bonded-{name}-{stamp}.toml"))
    }

    fn seed_invites(path: &PathBuf) {
        fs::write(
            path,
            r#"[[tokens]]
token = "pair-me"
expires_at = "unix:9999999999"
uses_remaining = 1
"#,
        )
        .expect("invite tokens file should be written");
    }

    #[tokio::test]
    async fn handshake_succeeds_for_authorized_key() {
        let keypair = DeviceKeypair::generate();
        let path = temp_file_path("auth-handshake");
        let invites = temp_file_path("auth-handshake-invites");
        fs::write(
            &path,
            format!(
                "[[devices]]\ndevice_id = \"cli\"\npublic_key = \"{}\"\n",
                keypair.public_key_b64
            ),
        )
        .expect("authorized keys file should be written");
        seed_invites(&invites);

        let store = AuthorizedKeysStore::load(&path).expect("store should load");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should resolve");

        let invites_for_server = invites.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept should succeed");
            let (public_key, _stream) = perform_auth_handshake(stream, store, &invites_for_server)
                .await
                .expect("auth handshake should succeed");
            public_key
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let hello = ClientHello {
            public_key_b64: keypair.public_key_b64.clone(),
            invite_token: String::new(),
        };
        let hello_json = serde_json::to_string(&hello).expect("hello should serialize");
        write_half
            .write_all(format!("{hello_json}\n").as_bytes())
            .await
            .expect("hello should be written");

        let mut challenge_line = String::new();
        reader
            .read_line(&mut challenge_line)
            .await
            .expect("challenge should be readable");
        let challenge: ServerChallenge =
            serde_json::from_str(challenge_line.trim_end()).expect("challenge should parse");

        let signature_b64 = sign_auth_challenge(&keypair, &challenge.challenge_b64)
            .expect("challenge should be signable");
        let proof = ClientProof { signature_b64 };
        let proof_json = serde_json::to_string(&proof).expect("proof should serialize");
        write_half
            .write_all(format!("{proof_json}\n").as_bytes())
            .await
            .expect("proof should be written");

        let mut result_line = String::new();
        reader
            .read_line(&mut result_line)
            .await
            .expect("result should be readable");
        let result: ServerAuthResult =
            serde_json::from_str(result_line.trim_end()).expect("result should parse");
        assert_eq!(result.status, "ok");

        let authenticated_public_key = server_task.await.expect("server task should join");
        assert_eq!(authenticated_public_key, keypair.public_key_b64);

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(invites);
    }

    #[tokio::test]
    async fn handshake_rejects_unauthorized_key() {
        let keypair = DeviceKeypair::generate();
        let path = temp_file_path("auth-handshake-unauthorized");
        let invites = temp_file_path("auth-handshake-unauthorized-invites");
        fs::write(
            &path,
            "[[devices]]\ndevice_id = \"cli\"\npublic_key = \"different\"\n",
        )
        .expect("authorized keys file should be written");
        seed_invites(&invites);

        let store = AuthorizedKeysStore::load(&path).expect("store should load");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should resolve");

        let invites_for_server = invites.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept should succeed");
            perform_auth_handshake(stream, store, &invites_for_server).await
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let hello = ClientHello {
            public_key_b64: keypair.public_key_b64,
            invite_token: String::new(),
        };
        let hello_json = serde_json::to_string(&hello).expect("hello should serialize");
        write_half
            .write_all(format!("{hello_json}\n").as_bytes())
            .await
            .expect("hello should be written");

        let mut result_line = String::new();
        reader
            .read_line(&mut result_line)
            .await
            .expect("result should be readable");
        let result: ServerAuthResult =
            serde_json::from_str(result_line.trim_end()).expect("result should parse");
        assert_eq!(result.status, "unauthorized");

        let server_result = server_task.await.expect("server task should join");
        assert!(server_result.is_err());

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(invites);
    }

    #[tokio::test]
    async fn handshake_redeems_invite_for_new_key() {
        let keypair = DeviceKeypair::generate();
        let path = temp_file_path("auth-handshake-redeem");
        let invites = temp_file_path("auth-handshake-redeem-invites");
        fs::write(&path, "devices = []\n").expect("authorized keys file should be written");
        seed_invites(&invites);

        let store = AuthorizedKeysStore::load(&path).expect("store should load");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should resolve");

        let invites_for_server = invites.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept should succeed");
            perform_auth_handshake(stream, store, &invites_for_server).await
        });

        let stream = TcpStream::connect(addr)
            .await
            .expect("client should connect");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let hello = ClientHello {
            public_key_b64: keypair.public_key_b64.clone(),
            invite_token: "pair-me".to_owned(),
        };
        let hello_json = serde_json::to_string(&hello).expect("hello should serialize");
        write_half
            .write_all(format!("{hello_json}\n").as_bytes())
            .await
            .expect("hello should be written");

        let mut challenge_line = String::new();
        reader
            .read_line(&mut challenge_line)
            .await
            .expect("challenge should be readable");
        let challenge: ServerChallenge =
            serde_json::from_str(challenge_line.trim_end()).expect("challenge should parse");

        let signature_b64 = sign_auth_challenge(&keypair, &challenge.challenge_b64)
            .expect("challenge should be signable");
        let proof = ClientProof { signature_b64 };
        let proof_json = serde_json::to_string(&proof).expect("proof should serialize");
        write_half
            .write_all(format!("{proof_json}\n").as_bytes())
            .await
            .expect("proof should be written");

        let mut result_line = String::new();
        reader
            .read_line(&mut result_line)
            .await
            .expect("result should be readable");
        let result: ServerAuthResult =
            serde_json::from_str(result_line.trim_end()).expect("result should parse");
        assert_eq!(result.status, "ok");

        let server_result = server_task.await.expect("server task should join");
        assert!(server_result.is_ok());

        let reloaded = AuthorizedKeysStore::load(&path).expect("store should reload");
        assert!(reloaded.is_authorized(&keypair.public_key_b64));

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(invites);
    }
}
