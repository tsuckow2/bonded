use crate::{
    cert_proof, establish_naive_tcp_session, establish_naive_tcp_session_with_bind,
    establish_naive_tcp_sessions, establish_transport_paths, ClientTransport,
};
use bonded_core::auth::{create_auth_challenge, sign_bytes, verify_auth_challenge, DeviceKeypair};
use bonded_core::config::{ClientConfig, ClientSection};
use bonded_core::session::{SessionFrame, SessionHeader};
use bonded_core::transport::{NaiveTcpTransport, QuicTransport, Transport, WebSocketTlsTransport};
use bytes::Bytes;
use quinn::ServerConfig as QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

fn temp_file_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be valid")
        .as_nanos();
    std::env::temp_dir().join(format!("bonded-client-integration-{name}-{stamp}.txt"))
}

fn test_client_config(addr: String, keypair: &DeviceKeypair) -> ClientConfig {
    let private_key_path = temp_file_path("private");
    let public_key_path = temp_file_path("public");
    fs::write(&private_key_path, format!("{}\n", keypair.private_key_b64))
        .expect("private key should write");
    fs::write(&public_key_path, format!("{}\n", keypair.public_key_b64))
        .expect("public key should write");

    ClientConfig {
        client: ClientSection {
            server_public_address: addr,
            private_key_path: private_key_path.to_string_lossy().to_string(),
            public_key_path: public_key_path.to_string_lossy().to_string(),
            ..ClientConfig::default().client
        },
        socket_protect: None,
        socket_network_bind: None,
    }
}

async fn server_handshake(stream: TcpStream, expected_public_key: &str) -> TcpStream {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let mut hello_line = String::new();
    reader
        .read_line(&mut hello_line)
        .await
        .expect("hello should be readable");
    let hello: serde_json::Value =
        serde_json::from_str(hello_line.trim_end()).expect("hello should parse");
    assert_eq!(
        hello["public_key_b64"].as_str().unwrap_or_default(),
        expected_public_key
    );

    let challenge_b64 = create_auth_challenge();
    let challenge = json!({ "challenge_b64": challenge_b64 });
    write_half
        .write_all(format!("{}\n", challenge).as_bytes())
        .await
        .expect("challenge should be written");

    let mut proof_line = String::new();
    reader
        .read_line(&mut proof_line)
        .await
        .expect("proof should be readable");
    let proof: serde_json::Value =
        serde_json::from_str(proof_line.trim_end()).expect("proof should parse");
    let signature_b64 = proof["signature_b64"]
        .as_str()
        .expect("signature should exist");
    verify_auth_challenge(expected_public_key, &challenge_b64, signature_b64)
        .expect("signature should verify");

    write_half
        .write_all(b"{\"status\":\"ok\"}\n")
        .await
        .expect("status should be written");

    reader
        .into_inner()
        .reunite(write_half)
        .expect("stream should reunite")
}

async fn websocket_server_handshake(
    stream: TcpStream,
    expected_public_key: &str,
) -> WebSocketTlsTransport {
    let mut transport = WebSocketTlsTransport::accept(stream)
        .await
        .expect("websocket upgrade should succeed");

    let hello_line = transport
        .recv_text()
        .await
        .expect("websocket hello should be readable");
    let hello: serde_json::Value =
        serde_json::from_str(hello_line.trim_end()).expect("websocket hello should parse");
    assert_eq!(
        hello["public_key_b64"].as_str().unwrap_or_default(),
        expected_public_key
    );

    let challenge_b64 = create_auth_challenge();
    let challenge = json!({ "challenge_b64": challenge_b64 });
    transport
        .send_text(&challenge.to_string())
        .await
        .expect("websocket challenge should be written");

    let proof_line = transport
        .recv_text()
        .await
        .expect("websocket proof should be readable");
    let proof: serde_json::Value =
        serde_json::from_str(proof_line.trim_end()).expect("websocket proof should parse");
    let signature_b64 = proof["signature_b64"]
        .as_str()
        .expect("websocket signature should exist");
    verify_auth_challenge(expected_public_key, &challenge_b64, signature_b64)
        .expect("websocket signature should verify");

    transport
        .send_text("{\"status\":\"ok\"}")
        .await
        .expect("websocket status should be written");

    transport
}

fn build_test_quic_server_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> QuicServerConfig {
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::try_from(key_der).expect("valid private key DER");
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server TLS config should build");
    tls_config.alpn_protocols = vec![b"bonded-quic".to_vec()];

    let mut server_config = QuicServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .expect("QUIC crypto config should build"),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4u32.into());
    server_config.transport_config(Arc::new(transport));
    server_config
}

fn build_test_h3_server_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> QuicServerConfig {
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::try_from(key_der).expect("valid private key DER");
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server TLS config should build");
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let mut server_config = QuicServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .expect("HTTP/3 crypto config should build"),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4u32.into());
    server_config.transport_config(Arc::new(transport));
    server_config
}

fn build_test_tls_acceptor(cert_der: Vec<u8>, key_der: Vec<u8>) -> TlsAcceptor {
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::try_from(key_der).expect("valid private key DER");
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server TLS config should build");
    TlsAcceptor::from(Arc::new(tls_config))
}

async fn quic_server_handshake(
    connection: quinn::Connection,
    expected_public_key: &str,
) -> QuicTransport {
    let mut transport = QuicTransport::from_server_connection(connection)
        .await
        .expect("QUIC transport should accept");

    let hello_line = transport
        .recv_text()
        .await
        .expect("QUIC hello should be readable");
    let hello: serde_json::Value =
        serde_json::from_str(hello_line.trim_end()).expect("QUIC hello should parse");
    assert_eq!(
        hello["public_key"].as_str().unwrap_or_default(),
        expected_public_key
    );

    let challenge_b64 = create_auth_challenge();
    let challenge = json!({ "challenge_b64": challenge_b64 });
    transport
        .send_text(&challenge.to_string())
        .await
        .expect("QUIC challenge should be written");

    let proof_line = transport
        .recv_text()
        .await
        .expect("QUIC proof should be readable");
    let proof: serde_json::Value =
        serde_json::from_str(proof_line.trim_end()).expect("QUIC proof should parse");
    let signature_b64 = proof["signature_b64"]
        .as_str()
        .expect("QUIC signature should exist");
    verify_auth_challenge(expected_public_key, &challenge_b64, signature_b64)
        .expect("QUIC signature should verify");

    transport
        .send_text("{\"status\":\"ok\"}")
        .await
        .expect("QUIC status should be written");

    transport
}

#[tokio::test]
async fn single_path_authenticated_frame_exchange() {
    let keypair = DeviceKeypair::generate();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("addr should resolve");

    let expected_public_key = keypair.public_key_b64.clone();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept should succeed");
        let stream = server_handshake(stream, &expected_public_key).await;
        let mut transport = NaiveTcpTransport::from_stream(stream);
        let frame = transport.recv().await.expect("frame should arrive");
        transport.send(frame).await.expect("echo should send");
    });

    let cfg = test_client_config(addr.to_string(), &keypair);
    let stream = establish_naive_tcp_session(&cfg)
        .await
        .expect("session should authenticate");
    let mut transport = NaiveTcpTransport::from_stream(stream);
    transport
        .send(SessionFrame {
            header: SessionHeader {
                connection_id: 5,
                sequence: 1,
                flags: 0,
            },
            payload: Bytes::from_static(b"hello"),
        })
        .await
        .expect("send should succeed");

    let echoed = transport.recv().await.expect("echo should arrive");
    assert_eq!(&echoed.payload[..], b"hello");

    server_task.await.expect("server task should join");

    let _ = fs::remove_file(&cfg.client.private_key_path);
    let _ = fs::remove_file(&cfg.client.public_key_path);
}

#[tokio::test]
async fn h3_bootstrap_request_fetches_capabilities_after_cert_proof() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert = generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .expect("self-signed cert should generate");
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
    let fingerprint = cert_proof::compute_fingerprint(&cert_der);
    let server_identity = DeviceKeypair::generate();
    let signature =
        sign_bytes(&server_identity, fingerprint.as_bytes()).expect("fingerprint should sign");

    let endpoint = quinn::Endpoint::server(
        build_test_h3_server_config(cert_der, key_der),
        "127.0.0.1:0".parse().expect("socket addr should parse"),
    )
    .expect("HTTP/3 endpoint should bind");
    let addr = endpoint.local_addr().expect("HTTP/3 addr should resolve");

    let server_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("incoming should exist");
        let connection = incoming.await.expect("HTTP/3 handshake should succeed");
        let mut h3_conn = h3::server::builder()
            .build(h3_quinn::Connection::new(connection))
            .await
            .expect("HTTP/3 server connection should build");

        let mut request_count = 0usize;
        loop {
            let resolver = match h3_conn.accept().await {
                Ok(Some(resolver)) => resolver,
                Ok(None) => break,
                Err(err) if request_count >= 2 => {
                    let message = err.to_string();
                    if message.contains("H3_NO_ERROR") || message.contains("ApplicationClose") {
                        break;
                    }
                    panic!("HTTP/3 accept after requests should close cleanly: {err}");
                }
                Err(err) => panic!("HTTP/3 accept should succeed: {err}"),
            };
            let (request, mut stream) = resolver
                .resolve_request()
                .await
                .expect("HTTP/3 request should resolve");
            let body = if request.uri().path() == "/v1/bootstrap/cert-proof" {
                json!({
                    "cert_fingerprint": fingerprint,
                    "ed25519_signature": signature,
                })
                .to_string()
            } else if request.uri().path() == "/v1/bootstrap/capabilities" {
                json!({
                    "transports": ["h3"],
                    "wss": { "endpoint": addr.to_string() },
                })
                .to_string()
            } else {
                panic!("unexpected path: {}", request.uri().path());
            };

            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(())
                .expect("HTTP/3 response should build");
            stream
                .send_response(response)
                .await
                .expect("HTTP/3 response headers should send");
            stream
                .send_data(Bytes::from(body))
                .await
                .expect("HTTP/3 response body should send");
            stream.finish().await.expect("HTTP/3 stream should finish");

            request_count += 1;
        }

        assert_eq!(
            request_count, 2,
            "server should handle cert-proof and capabilities requests"
        );
    });

    let mut cfg = test_client_config(addr.to_string(), &DeviceKeypair::generate());
    cfg.client.server_public_key = server_identity.public_key_b64.clone();
    cfg.client.tls_cert_fingerprint.clear();

    let body = super::request_bootstrap_json(
        &cfg,
        super::BootstrapScheme::H3,
        &addr.to_string(),
        "GET",
        "/v1/bootstrap/capabilities",
        None,
    )
    .await
    .expect("HTTP/3 bootstrap request should succeed");

    let parsed: serde_json::Value =
        serde_json::from_str(&body).expect("HTTP/3 bootstrap JSON should parse");
    assert_eq!(parsed["transports"], json!(["h3"]));

    server_task.await.expect("HTTP/3 server task should join");
    let _ = fs::remove_file(&cfg.client.private_key_path);
    let _ = fs::remove_file(&cfg.client.public_key_path);
}

#[tokio::test]
async fn h3_bootstrap_rejects_wrong_server_identity_key() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert = generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .expect("self-signed cert should generate");
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
    let fingerprint = cert_proof::compute_fingerprint(&cert_der);
    let server_identity = DeviceKeypair::generate();
    let signature =
        sign_bytes(&server_identity, fingerprint.as_bytes()).expect("fingerprint should sign");

    let endpoint = quinn::Endpoint::server(
        build_test_h3_server_config(cert_der, key_der),
        "127.0.0.1:0".parse().expect("socket addr should parse"),
    )
    .expect("HTTP/3 endpoint should bind");
    let addr = endpoint.local_addr().expect("HTTP/3 addr should resolve");

    let server_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("incoming should exist");
        let connection = incoming.await.expect("HTTP/3 handshake should succeed");
        let mut h3_conn = h3::server::builder()
            .build(h3_quinn::Connection::new(connection))
            .await
            .expect("HTTP/3 server connection should build");

        let mut request_count = 0usize;
        loop {
            let resolver = match h3_conn.accept().await {
                Ok(Some(resolver)) => resolver,
                Ok(None) => break,
                Err(err) if request_count >= 1 => {
                    let message = err.to_string();
                    if message.contains("H3_NO_ERROR") || message.contains("ApplicationClose") {
                        break;
                    }
                    panic!("HTTP/3 accept after request should close cleanly: {err}");
                }
                Err(err) => panic!("HTTP/3 accept should succeed: {err}"),
            };
            let (request, mut stream) = resolver
                .resolve_request()
                .await
                .expect("HTTP/3 request should resolve");
            assert_eq!(request.uri().path(), "/v1/bootstrap/cert-proof");

            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(())
                .expect("HTTP/3 response should build");
            stream
                .send_response(response)
                .await
                .expect("HTTP/3 response headers should send");
            stream
                .send_data(Bytes::from(
                    json!({
                        "cert_fingerprint": fingerprint,
                        "ed25519_signature": signature,
                    })
                    .to_string(),
                ))
                .await
                .expect("HTTP/3 response body should send");
            stream.finish().await.expect("HTTP/3 stream should finish");
            request_count += 1;
        }

        assert_eq!(
            request_count, 1,
            "wrong identity trust should stop after cert-proof",
        );
    });

    let mut cfg = test_client_config(addr.to_string(), &DeviceKeypair::generate());
    cfg.client.server_public_key = DeviceKeypair::generate().public_key_b64;
    cfg.client.tls_cert_fingerprint.clear();

    let err = super::request_bootstrap_json(
        &cfg,
        super::BootstrapScheme::H3,
        &addr.to_string(),
        "GET",
        "/v1/bootstrap/capabilities",
        None,
    )
    .await
    .expect_err("HTTP/3 bootstrap should fail with the wrong identity key");

    assert!(
        err.to_string()
            .contains("cert-proof signature verification failed"),
        "unexpected error: {err}",
    );

    server_task.await.expect("HTTP/3 server task should join");
    let _ = fs::remove_file(&cfg.client.private_key_path);
    let _ = fs::remove_file(&cfg.client.public_key_path);
}

#[tokio::test]
async fn h3_bootstrap_retries_after_stale_cert_pin() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert = generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .expect("self-signed cert should generate");
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
    let fingerprint = cert_proof::compute_fingerprint(&cert_der);
    let server_identity = DeviceKeypair::generate();
    let signature =
        sign_bytes(&server_identity, fingerprint.as_bytes()).expect("fingerprint should sign");

    let tcp_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("TLS bootstrap listener should bind");
    let addr = tcp_listener
        .local_addr()
        .expect("TLS bootstrap addr should resolve");
    let tls_acceptor = build_test_tls_acceptor(cert_der.clone(), key_der.clone());

    let tls_task = tokio::spawn(async move {
        let (stream, _) = tcp_listener
            .accept()
            .await
            .expect("TLS accept should succeed");
        let mut tls = tls_acceptor
            .accept(stream)
            .await
            .expect("TLS handshake should succeed");
        let mut raw = vec![0u8; 4096];
        let read = tls.read(&mut raw).await.expect("TLS request should read");
        let request = String::from_utf8(raw[..read].to_vec()).expect("TLS request should be utf8");
        assert!(request.starts_with("GET /v1/bootstrap/cert-proof "));

        let body = json!({
            "cert_fingerprint": fingerprint,
            "ed25519_signature": signature,
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        );
        tls.write_all(response.as_bytes())
            .await
            .expect("TLS response should write");
        tls.shutdown()
            .await
            .expect("TLS response should close cleanly");
    });

    let endpoint = quinn::Endpoint::server(build_test_h3_server_config(cert_der, key_der), addr)
        .expect("HTTP/3 endpoint should bind");

    let h3_task = tokio::spawn(async move {
        let connection = loop {
            let incoming = endpoint.accept().await.expect("incoming should exist");
            match incoming.await {
                Ok(connection) => break connection,
                Err(_) => continue,
            }
        };
        let mut h3_conn = h3::server::builder()
            .build(h3_quinn::Connection::new(connection))
            .await
            .expect("HTTP/3 server connection should build");

        let mut request_count = 0usize;
        loop {
            let resolver = match h3_conn.accept().await {
                Ok(Some(resolver)) => resolver,
                Ok(None) => break,
                Err(err) if request_count >= 1 => {
                    let message = err.to_string();
                    if message.contains("H3_NO_ERROR") || message.contains("ApplicationClose") {
                        break;
                    }
                    panic!("HTTP/3 accept after request should close cleanly: {err}");
                }
                Err(err) => panic!("HTTP/3 accept should succeed: {err}"),
            };
            let (request, mut stream) = resolver
                .resolve_request()
                .await
                .expect("HTTP/3 request should resolve");
            assert_eq!(request.uri().path(), "/v1/bootstrap/capabilities");

            let body = json!({
                "transports": ["h3"],
                "wss": { "endpoint": addr.to_string() },
            })
            .to_string();
            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(())
                .expect("HTTP/3 response should build");
            stream
                .send_response(response)
                .await
                .expect("HTTP/3 response headers should send");
            stream
                .send_data(Bytes::from(body))
                .await
                .expect("HTTP/3 response body should send");
            stream.finish().await.expect("HTTP/3 stream should finish");
            request_count += 1;
        }

        assert_eq!(
            request_count, 1,
            "server should handle one retried H3 request"
        );
    });

    let mut cfg = test_client_config(addr.to_string(), &DeviceKeypair::generate());
    cfg.client.server_public_key = server_identity.public_key_b64.clone();
    cfg.client.tls_cert_fingerprint = "sha256:deadbeef".to_owned();

    let body = super::request_bootstrap_json(
        &cfg,
        super::BootstrapScheme::H3,
        &addr.to_string(),
        "GET",
        "/v1/bootstrap/capabilities",
        None,
    )
    .await
    .expect("HTTP/3 bootstrap should recover from a stale pin");

    let parsed: serde_json::Value =
        serde_json::from_str(&body).expect("HTTP/3 bootstrap JSON should parse");
    assert_eq!(parsed["transports"], json!(["h3"]));

    tls_task.await.expect("TLS bootstrap task should join");
    h3_task.await.expect("HTTP/3 server task should join");
    let _ = fs::remove_file(&cfg.client.private_key_path);
    let _ = fs::remove_file(&cfg.client.public_key_path);
}

#[tokio::test]
async fn bound_single_path_uses_requested_local_address() {
    let keypair = DeviceKeypair::generate();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("addr should resolve");

    let expected_public_key = keypair.public_key_b64.clone();
    let server_task = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.expect("accept should succeed");
        assert_eq!(peer_addr.ip().to_string(), "127.0.0.2");
        let stream = server_handshake(stream, &expected_public_key).await;
        let mut transport = NaiveTcpTransport::from_stream(stream);
        let frame = transport.recv().await.expect("frame should arrive");
        transport.send(frame).await.expect("echo should send");
    });

    let cfg = test_client_config(addr.to_string(), &keypair);
    let stream = establish_naive_tcp_session_with_bind(&cfg, "127.0.0.2")
        .await
        .expect("session should authenticate with requested bind address");
    let mut transport = NaiveTcpTransport::from_stream(stream);
    transport
        .send(SessionFrame {
            header: SessionHeader {
                connection_id: 7,
                sequence: 1,
                flags: 0,
            },
            payload: Bytes::from_static(b"bound-hello"),
        })
        .await
        .expect("send should succeed");

    let echoed = transport.recv().await.expect("echo should arrive");
    assert_eq!(&echoed.payload[..], b"bound-hello");

    server_task.await.expect("server task should join");

    let _ = fs::remove_file(&cfg.client.private_key_path);
    let _ = fs::remove_file(&cfg.client.public_key_path);
}

#[tokio::test]
async fn multipath_failover_continues_exchange() {
    let keypair = DeviceKeypair::generate();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("addr should resolve");

    let expected_public_key = keypair.public_key_b64.clone();
    let server_task = tokio::spawn(async move {
        let (first_stream, _) = listener
            .accept()
            .await
            .expect("first accept should succeed");
        let first_stream = server_handshake(first_stream, &expected_public_key).await;
        drop(first_stream);

        let (second_stream, _) = listener
            .accept()
            .await
            .expect("second accept should succeed");
        let second_stream = server_handshake(second_stream, &expected_public_key).await;
        let mut transport = NaiveTcpTransport::from_stream(second_stream);
        let frame = transport
            .recv()
            .await
            .expect("fallback frame should arrive");
        transport
            .send(frame)
            .await
            .expect("fallback echo should send");
    });

    let cfg = test_client_config(addr.to_string(), &keypair);
    let streams = establish_naive_tcp_sessions(&cfg, 2)
        .await
        .expect("both paths should authenticate");
    let mut paths: Vec<NaiveTcpTransport> = streams
        .into_iter()
        .map(NaiveTcpTransport::from_stream)
        .collect();

    let frame = SessionFrame {
        header: SessionHeader {
            connection_id: 9,
            sequence: 2,
            flags: 0,
        },
        payload: Bytes::from_static(b"survive"),
    };

    // Path 0 may already be closed at send time; either send or recv must fail.
    let first_send = paths[0].send(frame.clone()).await;
    if first_send.is_ok() {
        let timed_out = timeout(Duration::from_millis(300), paths[0].recv()).await;
        assert!(timed_out.is_err() || timed_out.unwrap().is_err());
    } else {
        assert!(first_send.is_err());
    }

    paths[1]
        .send(frame)
        .await
        .expect("fallback send should work");
    let echoed = paths[1].recv().await.expect("fallback echo should arrive");
    assert_eq!(&echoed.payload[..], b"survive");

    server_task.await.expect("server task should join");

    let _ = fs::remove_file(&cfg.client.private_key_path);
    let _ = fs::remove_file(&cfg.client.public_key_path);
}

#[tokio::test]
async fn multipath_can_mix_websocket_and_naive_tcp() {
    let keypair = DeviceKeypair::generate();
    let naive_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("naive listener should bind");
    let ws_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("websocket listener should bind");
    let naive_addr = naive_listener
        .local_addr()
        .expect("naive addr should resolve");
    let ws_addr = ws_listener.local_addr().expect("ws addr should resolve");

    let expected_public_key = keypair.public_key_b64.clone();
    let ws_public_key = expected_public_key.clone();
    let server_task = tokio::spawn(async move {
        let (naive_stream, _) = naive_listener
            .accept()
            .await
            .expect("naive accept should succeed");
        let naive_stream = server_handshake(naive_stream, &expected_public_key).await;
        let mut naive_transport = NaiveTcpTransport::from_stream(naive_stream);

        let (ws_stream, _) = ws_listener
            .accept()
            .await
            .expect("websocket accept should succeed");
        let mut ws_transport = websocket_server_handshake(ws_stream, &ws_public_key).await;

        let naive_frame = naive_transport
            .recv()
            .await
            .expect("naive frame should arrive");
        naive_transport
            .send(naive_frame)
            .await
            .expect("naive echo should send");

        let ws_frame = ws_transport.recv().await.expect("ws frame should arrive");
        ws_transport
            .send(ws_frame)
            .await
            .expect("ws echo should send");
    });

    let mut cfg = test_client_config(naive_addr.to_string(), &keypair);
    cfg.client.server_websocket_address = format!("ws://{ws_addr}");
    cfg.client.preferred_protocols = vec!["naive_tcp".to_owned(), "wss".to_owned()];

    let mut paths = establish_transport_paths(&cfg, 2)
        .await
        .expect("mixed protocol paths should establish");

    let frame0 = SessionFrame {
        header: SessionHeader {
            connection_id: 11,
            sequence: 0,
            flags: 0,
        },
        payload: Bytes::from_static(b"naive-path"),
    };
    paths[0]
        .send(frame0)
        .await
        .expect("path 0 send should succeed");
    let echoed0 = paths[0].recv().await.expect("path 0 echo should arrive");
    assert_eq!(&echoed0.payload[..], b"naive-path");

    let frame1 = SessionFrame {
        header: SessionHeader {
            connection_id: 12,
            sequence: 0,
            flags: 0,
        },
        payload: Bytes::from_static(b"websocket-path"),
    };
    paths[1]
        .send(frame1)
        .await
        .expect("path 1 send should succeed");
    let echoed1 = paths[1].recv().await.expect("path 1 echo should arrive");
    assert_eq!(&echoed1.payload[..], b"websocket-path");

    server_task.await.expect("server task should join");

    let _ = fs::remove_file(&cfg.client.private_key_path);
    let _ = fs::remove_file(&cfg.client.public_key_path);
}

#[tokio::test]
async fn bind_aware_path_honors_websocket_first_preference() {
    let keypair = DeviceKeypair::generate();
    let naive_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("naive listener should bind");
    let ws_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("websocket listener should bind");
    let naive_addr = naive_listener
        .local_addr()
        .expect("naive addr should resolve");
    let ws_addr = ws_listener.local_addr().expect("ws addr should resolve");

    let expected_public_key = keypair.public_key_b64.clone();
    let ws_public_key = expected_public_key.clone();
    let naive_task = tokio::spawn(async move {
        let accepted = timeout(Duration::from_millis(500), naive_listener.accept()).await;
        if accepted.is_err() {
            return;
        }

        let (naive_stream, _) = accepted
            .expect("timeout should be handled")
            .expect("naive accept should succeed when connected");
        let naive_stream = server_handshake(naive_stream, &expected_public_key).await;
        let mut naive_transport = NaiveTcpTransport::from_stream(naive_stream);

        // If a NaiveTCP path is selected, a frame would arrive quickly; it should not.
        let naive_result = timeout(Duration::from_millis(300), naive_transport.recv()).await;
        assert!(naive_result.is_err(), "naive path should remain idle");
    });

    let ws_task = tokio::spawn(async move {
        let (ws_stream, _) = ws_listener
            .accept()
            .await
            .expect("websocket accept should succeed");
        let mut ws_transport = websocket_server_handshake(ws_stream, &ws_public_key).await;

        let ws_frame = ws_transport.recv().await.expect("ws frame should arrive");
        ws_transport
            .send(ws_frame)
            .await
            .expect("ws echo should send");
    });

    let mut cfg = test_client_config(naive_addr.to_string(), &keypair);
    cfg.client.server_websocket_address = format!("ws://{ws_addr}");
    cfg.client.preferred_protocols = vec!["wss".to_owned(), "naive_tcp".to_owned()];
    cfg.client.path_bind_addresses = vec!["127.0.0.2".to_owned()];

    let mut paths = establish_transport_paths(&cfg, 1)
        .await
        .expect("path should establish with websocket preference");
    assert_eq!(paths.len(), 1);
    assert!(matches!(paths[0], ClientTransport::WebSocket(_)));

    let frame = SessionFrame {
        header: SessionHeader {
            connection_id: 13,
            sequence: 0,
            flags: 0,
        },
        payload: Bytes::from_static(b"websocket-first"),
    };
    paths[0]
        .send(frame)
        .await
        .expect("websocket send should succeed");
    let echoed = paths[0].recv().await.expect("websocket echo should arrive");
    assert_eq!(&echoed.payload[..], b"websocket-first");

    ws_task.await.expect("ws task should join");
    naive_task.await.expect("naive task should join");

    let _ = fs::remove_file(&cfg.client.private_key_path);
    let _ = fs::remove_file(&cfg.client.public_key_path);
}

#[tokio::test]
async fn mixed_websocket_quic_failover_continues_exchange() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let keypair = DeviceKeypair::generate();
    let ws_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("websocket listener should bind");
    let ws_addr = ws_listener.local_addr().expect("ws addr should resolve");

    let cert = generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .expect("test certificate should generate");
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
    let quic_server_config = build_test_quic_server_config(cert_der.clone(), key_der);
    let quic_endpoint = quinn::Endpoint::server(quic_server_config, ws_addr)
        .expect("QUIC endpoint should bind on same localhost port");
    let quic_accept_endpoint = quic_endpoint.clone();
    let (quic_done_tx, quic_done_rx) = tokio::sync::oneshot::channel::<()>();

    let expected_public_key = keypair.public_key_b64.clone();
    let ws_public_key = expected_public_key.clone();
    let ws_task = tokio::spawn(async move {
        let (ws_stream, _) = ws_listener
            .accept()
            .await
            .expect("websocket accept should succeed");
        let ws_transport = websocket_server_handshake(ws_stream, &ws_public_key).await;
        drop(ws_transport);
    });

    let quic_public_key = expected_public_key.clone();
    let quic_task = tokio::spawn(async move {
        let incoming = quic_accept_endpoint
            .accept()
            .await
            .expect("QUIC accept should yield a connection");
        let connection = incoming.await.expect("QUIC handshake should succeed");
        let mut transport = quic_server_handshake(connection, &quic_public_key).await;
        let frame = transport.recv().await.expect("QUIC frame should arrive");
        transport.send(frame).await.expect("QUIC echo should send");
        let _ = quic_done_rx.await;
    });

    let mut cfg = test_client_config(ws_addr.to_string(), &keypair);
    cfg.client.server_websocket_address = format!("ws://{ws_addr}");
    cfg.client.preferred_protocols = vec!["wss".to_owned(), "h3".to_owned()];
    cfg.client.tls_cert_fingerprint = cert_proof::compute_fingerprint(&cert_der);

    let mut paths = establish_transport_paths(&cfg, 2)
        .await
        .expect("mixed websocket/quic paths should establish");
    assert!(matches!(paths[0], ClientTransport::WebSocket(_)));
    assert!(matches!(paths[1], ClientTransport::Quic(_)));

    let frame = SessionFrame {
        header: SessionHeader {
            connection_id: 14,
            sequence: 0,
            flags: 0,
        },
        payload: Bytes::from_static(b"mixed-failover"),
    };

    let first_send = paths[0].send(frame.clone()).await;
    if first_send.is_ok() {
        let timed_out = timeout(Duration::from_millis(300), paths[0].recv()).await;
        assert!(timed_out.is_err() || timed_out.unwrap().is_err());
    } else {
        assert!(first_send.is_err());
    }

    paths[1]
        .send(frame)
        .await
        .expect("QUIC fallback send should work");
    let echoed = paths[1]
        .recv()
        .await
        .expect("QUIC fallback echo should arrive");
    assert_eq!(&echoed.payload[..], b"mixed-failover");
    let _ = quic_done_tx.send(());

    ws_task.await.expect("ws task should join");
    quic_task.await.expect("quic task should join");

    let _ = fs::remove_file(&cfg.client.private_key_path);
    let _ = fs::remove_file(&cfg.client.public_key_path);
}
