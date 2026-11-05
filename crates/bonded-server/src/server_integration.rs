use crate::auth_handshake::perform_auth_handshake;
use crate::authorized_keys::AuthorizedKeysStore;
use bonded_client::establish_naive_tcp_session;
use bonded_core::auth::{sign_auth_challenge, DeviceKeypair};
use bonded_core::config::ClientConfig;
use bonded_core::session::{SessionFrame, SessionHeader};
use bonded_core::transport::{NaiveTcpTransport, Transport, WebSocketTlsTransport};
use bytes::Bytes;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::Connector;

fn temp_file_path(name: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be valid")
        .as_nanos();
    std::env::temp_dir().join(format!("bonded-{name}-{stamp}.toml"))
}

fn test_tls_configs() -> (TlsAcceptor, Connector) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("test cert should generate");
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.key_pair.serialize_der();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key_der,
            )),
        )
        .expect("server config should build");

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(cert_der))
        .expect("root cert should add");
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    (
        TlsAcceptor::from(Arc::new(server_config)),
        Connector::Rustls(Arc::new(client_config)),
    )
}

#[tokio::test]
async fn authenticated_client_can_exchange_session_frame() {
    let keypair = DeviceKeypair::generate();
    let path = temp_file_path("server-e2e");
    let invites = temp_file_path("server-e2e-invites");
    fs::write(
        &path,
        format!(
            "[[devices]]\ndevice_id = \"linux-cli\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys file should be written");
    fs::write(
        &invites,
        r#"[[tokens]]
token = "pair-me"
expires_at = "unix:9999999999"
uses_remaining = 1
"#,
    )
    .expect("invite tokens file should be written");

    let store = AuthorizedKeysStore::load(&path).expect("authorized keys should load");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("local address should resolve");

    let invites_for_server = invites.clone();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept should succeed");
        let (public_key, stream) = perform_auth_handshake(stream, store, &invites_for_server)
            .await
            .expect("handshake should succeed");
        let mut transport = NaiveTcpTransport::from_stream(stream);
        let frame = transport.recv().await.expect("server should receive frame");
        (public_key, frame)
    });

    let stream = TcpStream::connect(addr)
        .await
        .expect("client should connect to server");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let hello = serde_json::json!({
        "public_key_b64": keypair.public_key_b64,
        "invite_token": "",
    });
    write_half
        .write_all(format!("{}\n", hello).as_bytes())
        .await
        .expect("hello should be written");

    let mut challenge_line = String::new();
    reader
        .read_line(&mut challenge_line)
        .await
        .expect("challenge should be readable");
    let challenge: Value =
        serde_json::from_str(challenge_line.trim_end()).expect("challenge json should parse");
    let challenge_b64 = challenge["challenge_b64"]
        .as_str()
        .expect("challenge should include challenge_b64");

    let signature_b64 =
        sign_auth_challenge(&keypair, challenge_b64).expect("challenge should be signable");
    let proof = serde_json::json!({
        "signature_b64": signature_b64,
    });
    write_half
        .write_all(format!("{}\n", proof).as_bytes())
        .await
        .expect("proof should be written");

    let mut result_line = String::new();
    reader
        .read_line(&mut result_line)
        .await
        .expect("result should be readable");
    let result: Value = serde_json::from_str(result_line.trim_end()).expect("result should parse");
    assert_eq!(result["status"], "ok");

    let stream = reader
        .into_inner()
        .reunite(write_half)
        .expect("stream halves should reunite");
    let mut transport = NaiveTcpTransport::from_stream(stream);
    transport
        .send(SessionFrame {
            header: SessionHeader {
                connection_id: 77,
                sequence: 0,
                flags: 0,
            },
            payload: Bytes::from_static(b"frame-payload"),
        })
        .await
        .expect("client should send framed payload");

    let (public_key, received) = server_task.await.expect("server task should join");
    assert_eq!(public_key, keypair.public_key_b64);
    assert_eq!(received.header.connection_id, 77);
    assert_eq!(received.header.sequence, 0);
    assert_eq!(&received.payload[..], b"frame-payload");

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(invites);
}

#[tokio::test]
async fn authenticated_websocket_client_can_exchange_session_frame() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let keypair = DeviceKeypair::generate();
    let path = temp_file_path("server-ws-e2e");
    let invites = temp_file_path("server-ws-e2e-invites");
    fs::write(
        &path,
        format!(
            "[[devices]]\ndevice_id = \"linux-cli\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys file should be written");
    fs::write(
        &invites,
        r#"[[tokens]]
token = "pair-me"
expires_at = "unix:9999999999"
uses_remaining = 1
"#,
    )
    .expect("invite tokens file should be written");

    let store = AuthorizedKeysStore::load(&path).expect("authorized keys should load");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("local address should resolve");
    let (tls_acceptor, tls_connector) = test_tls_configs();

    let invites_for_server = invites.clone();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept should succeed");
        let mut transport = WebSocketTlsTransport::accept_tls(stream, tls_acceptor)
            .await
            .expect("wss should accept");
        let public_key = crate::auth_handshake::perform_websocket_auth_handshake(
            &mut transport,
            store,
            &invites_for_server,
        )
        .await
        .expect("websocket handshake should succeed");

        let frame = transport
            .recv()
            .await
            .expect("server should receive websocket frame");
        (public_key, frame)
    });

    let mut transport = WebSocketTlsTransport::connect_with_connector(
        &format!("wss://localhost:{}", addr.port()),
        tls_connector,
    )
    .await
    .expect("client websocket should connect");

    let hello = serde_json::json!({
        "public_key_b64": keypair.public_key_b64,
        "invite_token": "",
    });
    transport
        .send_text(&hello.to_string())
        .await
        .expect("hello should be written");

    let challenge_line = transport
        .recv_text()
        .await
        .expect("challenge should be readable");
    let challenge: Value =
        serde_json::from_str(challenge_line.trim_end()).expect("challenge json should parse");
    let challenge_b64 = challenge["challenge_b64"]
        .as_str()
        .expect("challenge should include challenge_b64");

    let signature_b64 =
        sign_auth_challenge(&keypair, challenge_b64).expect("challenge should be signable");
    let proof = serde_json::json!({
        "signature_b64": signature_b64,
    });
    transport
        .send_text(&proof.to_string())
        .await
        .expect("proof should be written");

    let result_line = transport
        .recv_text()
        .await
        .expect("result should be readable");
    let result: Value = serde_json::from_str(result_line.trim_end()).expect("result should parse");
    assert_eq!(result["status"], "ok");

    transport
        .send(SessionFrame {
            header: SessionHeader {
                connection_id: 78,
                sequence: 0,
                flags: 0,
            },
            payload: Bytes::from_static(b"ws-frame-payload"),
        })
        .await
        .expect("client should send websocket framed payload");

    let (public_key, received) = server_task.await.expect("server task should join");
    assert_eq!(public_key, keypair.public_key_b64);
    assert_eq!(received.header.connection_id, 78);
    assert_eq!(received.header.sequence, 0);
    assert_eq!(&received.payload[..], b"ws-frame-payload");

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(invites);
}

#[tokio::test]
#[ignore = "manual diagnostic: requires internet egress from server host and may be flaky in CI"]
async fn localhost_server_and_rust_client_can_probe_public_dns_udp() {
    let keypair = DeviceKeypair::generate();
    let authorized_path = temp_file_path("server-dns-e2e-keys");
    let invites_path = temp_file_path("server-dns-e2e-invites");
    let private_key_path = temp_file_path("server-dns-e2e-private");
    let public_key_path = temp_file_path("server-dns-e2e-public");

    fs::write(
        &authorized_path,
        format!(
            "[[devices]]\ndevice_id = \"rust-e2e\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys file should be written");

    fs::write(
        &invites_path,
        "[[tokens]]\ntoken = \"unused\"\nexpires_at = \"unix:9999999999\"\nuses_remaining = 1\n",
    )
    .expect("invite tokens file should be written");

    fs::write(&private_key_path, format!("{}\n", keypair.private_key_b64))
        .expect("private key file should be written");
    fs::write(&public_key_path, format!("{}\n", keypair.public_key_b64))
        .expect("public key file should be written");

    let bind = pick_ephemeral_bind();
    let store = AuthorizedKeysStore::load(&authorized_path).expect("authorized keys should load");
    let bind_for_server = bind.clone();
    let invite_for_server = invites_path
        .to_str()
        .expect("invite path should be utf-8")
        .to_owned();
    let server_task = tokio::spawn(async move {
        crate::run_server(
            &bind_for_server,
            &invite_for_server,
            Arc::new(DeviceKeypair::generate()),
            store,
            crate::session_registry::SessionRegistry::default(),
            Arc::new(RwLock::new(HashMap::new())),
            None,
            None,
            std::net::SocketAddr::from(([192, 0, 2, 53], 53)),
        )
        .await
    });

    let mut connected = false;
    let mut last_error = String::new();
    for _ in 0..20 {
        match try_establish_client_stream(&bind, &private_key_path, &public_key_path).await {
            Ok(stream) => {
                connected = true;
                let mut transport = NaiveTcpTransport::from_stream(stream);
                let (query, query_id) = build_dns_query_example_com();
                eprintln!(
                    "[DNS Test] Sending query to 8.8.8.8:53, query_id=0x{:04x}, payload_len={}",
                    query_id,
                    query.len()
                );
                let udp_packet = build_ipv4_udp_packet(
                    Ipv4Addr::new(10, 8, 0, 2),
                    Ipv4Addr::new(8, 8, 8, 8),
                    53001,
                    53,
                    4242,
                    &query,
                )
                .expect("dns probe packet should build");

                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 900,
                            sequence: 0,
                            flags: 0,
                        },
                        payload: udp_packet.into(),
                    })
                    .await
                    .expect("dns probe frame should send");

                let recv = timeout(Duration::from_secs(5), transport.recv()).await;
                match recv {
                    Ok(Ok(frame)) => {
                        let parsed = parse_ipv4_udp_packet(&frame.payload)
                            .expect("dns response should be ipv4+udp");
                        assert_eq!(parsed.src_ip, Ipv4Addr::new(8, 8, 8, 8));
                        assert_eq!(parsed.dst_ip, Ipv4Addr::new(10, 8, 0, 2));
                        assert_eq!(parsed.src_port, 53);
                        assert_eq!(parsed.dst_port, 53001);
                        assert!(
                            parsed.payload.len() >= 12,
                            "dns payload too small: {} bytes",
                            parsed.payload.len()
                        );
                        eprintln!(
                            "[DNS Test] Received UDP response, payload_len={}",
                            parsed.payload.len()
                        );

                        // Validate DNS response header
                        let dns_response = &parsed.payload;
                        if dns_response.len() >= 12 {
                            let resp_id = u16::from_be_bytes([dns_response[0], dns_response[1]]);
                            let flags = u16::from_be_bytes([dns_response[2], dns_response[3]]);
                            let qd_count = u16::from_be_bytes([dns_response[4], dns_response[5]]);
                            let an_count = u16::from_be_bytes([dns_response[6], dns_response[7]]);
                            let ns_count = u16::from_be_bytes([dns_response[8], dns_response[9]]);
                            let ar_count = u16::from_be_bytes([dns_response[10], dns_response[11]]);

                            eprintln!(
                                "[DNS Test] Response ID: 0x{:04x} (expected 0x{:04x})",
                                resp_id, query_id
                            );
                            eprintln!("[DNS Test] Flags: 0x{:04x} (QR={}, OPCODE={}, AA={}, TC={}, RD={}, RA={}, RCODE={})",
                                flags,
                                (flags >> 15) & 1,
                                (flags >> 11) & 0xf,
                                (flags >> 10) & 1,
                                (flags >> 9) & 1,
                                (flags >> 8) & 1,
                                (flags >> 7) & 1,
                                flags & 0xf
                            );
                            eprintln!(
                                "[DNS Test] Counts: QD={}, AN={}, NS={}, AR={}",
                                qd_count, an_count, ns_count, ar_count
                            );

                            // Validate response basics
                            assert_eq!(resp_id, query_id, "DNS response ID mismatch");
                            assert_eq!((flags >> 15) & 1, 1, "DNS response flag (QR) not set");
                            let rcode = flags & 0xf;
                            assert_eq!(rcode, 0, "DNS response code indicates error: {}", rcode);

                            if an_count > 0 {
                                eprintln!("[DNS Test] ✓ Response contains {} answer record(s), DNS query succeeded", an_count);
                            } else {
                                eprintln!("[DNS Test] ⚠ Response has no answer records (possible NODATA/NXDOMAIN)");
                            }
                        } else {
                            eprintln!("[DNS Test] ⚠ DNS payload too short to parse header");
                        }
                    }
                    Ok(Err(err)) => {
                        panic!("dns probe frame receive failed: {err}");
                    }
                    Err(_) => {
                        panic!(
                            "timed out waiting for DNS response frame from server. \
                             Check server internet UDP egress and frame_forwarder UDP timeout."
                        );
                    }
                }

                break;
            }
            Err(err) => {
                last_error = err;
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    if !connected {
        panic!("rust client failed to connect/authenticate to local server: {last_error}");
    }

    server_task.abort();

    let _ = fs::remove_file(authorized_path);
    let _ = fs::remove_file(&invites_path);
    let _ = fs::remove_file(private_key_path);
    let _ = fs::remove_file(public_key_path);
}

#[tokio::test]
#[ignore = "manual diagnostic: requires internet egress from server host and may be flaky in CI"]
async fn localhost_server_and_rust_client_can_fetch_example_com_http_over_tcp_packets() {
    const TCP_SYN: u8 = 0x02;
    const TCP_ACK: u8 = 0x10;
    const TCP_PSH: u8 = 0x08;
    const TCP_SYN_ACK: u8 = TCP_SYN | TCP_ACK;
    const TCP_PSH_ACK: u8 = TCP_PSH | TCP_ACK;
    const CLIENT_VIRTUAL_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
    const CLIENT_PORT: u16 = 54322;
    const CLIENT_ISN: u32 = 4000;
    const WINDOW: u16 = 65535;

    let mut example_ipv4 = None;
    let resolved = tokio::net::lookup_host(("example.com", 80))
        .await
        .expect("example.com should resolve");
    for addr in resolved {
        if let SocketAddr::V4(v4) = addr {
            example_ipv4 = Some(*v4.ip());
            break;
        }
    }
    let target_ip = example_ipv4.expect("example.com should resolve to an IPv4 address");

    let keypair = DeviceKeypair::generate();
    let authorized_path = temp_file_path("server-http-ipv4-keys");
    let invites_path = temp_file_path("server-http-ipv4-invites");
    let private_key_path = temp_file_path("server-http-ipv4-private");
    let public_key_path = temp_file_path("server-http-ipv4-public");

    fs::write(
        &authorized_path,
        format!(
            "[[devices]]\ndevice_id = \"http-ipv4-test\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys should write");
    fs::write(
        &invites_path,
        "[[tokens]]\ntoken = \"unused\"\nexpires_at = \"unix:9999999999\"\nuses_remaining = 1\n",
    )
    .expect("invites file should write");
    fs::write(&private_key_path, format!("{}\n", keypair.private_key_b64))
        .expect("private key should write");
    fs::write(&public_key_path, format!("{}\n", keypair.public_key_b64))
        .expect("public key should write");

    let bind = pick_ephemeral_bind();
    let store = AuthorizedKeysStore::load(&authorized_path).expect("authorized keys should load");
    let bind_for_server = bind.clone();
    let invite_for_server = invites_path
        .to_str()
        .expect("path should be utf-8")
        .to_owned();
    let server_task = tokio::spawn(async move {
        crate::run_server(
            &bind_for_server,
            &invite_for_server,
            Arc::new(DeviceKeypair::generate()),
            store,
            crate::session_registry::SessionRegistry::default(),
            Arc::new(RwLock::new(HashMap::new())),
            None,
            None,
            std::net::SocketAddr::from(([192, 0, 2, 53], 53)),
        )
        .await
    });

    let mut connected = false;
    let mut last_error = String::new();

    for _ in 0..20 {
        match try_establish_client_stream(&bind, &private_key_path, &public_key_path).await {
            Ok(stream) => {
                connected = true;
                let mut transport = NaiveTcpTransport::from_stream(stream);

                let syn_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    target_ip,
                    CLIENT_PORT,
                    80,
                    CLIENT_ISN,
                    0,
                    TCP_SYN,
                    WINDOW,
                    &[],
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 11,
                            sequence: 0,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&syn_packet),
                    })
                    .await
                    .expect("SYN frame should send");

                let syn_ack_frame = timeout(Duration::from_secs(6), transport.recv())
                    .await
                    .expect("SYN-ACK should arrive within timeout")
                    .expect("SYN-ACK frame should be readable");
                let syn_ack = parse_ipv4_tcp_packet(&syn_ack_frame.payload)
                    .expect("SYN-ACK should be a valid IPv4/TCP packet");
                assert_eq!(
                    syn_ack.flags & TCP_SYN_ACK,
                    TCP_SYN_ACK,
                    "flags should include SYN+ACK (got 0x{:02x})",
                    syn_ack.flags
                );
                let server_isn = syn_ack.seq;

                let ack_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    target_ip,
                    CLIENT_PORT,
                    80,
                    CLIENT_ISN.wrapping_add(1),
                    server_isn.wrapping_add(1),
                    TCP_ACK,
                    WINDOW,
                    &[],
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 11,
                            sequence: 1,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&ack_packet),
                    })
                    .await
                    .expect("ACK frame should send");

                let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nUser-Agent: bonded-e2e\r\nAccept: */*\r\n\r\n";
                let req_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    target_ip,
                    CLIENT_PORT,
                    80,
                    CLIENT_ISN.wrapping_add(1),
                    server_isn.wrapping_add(1),
                    TCP_PSH_ACK,
                    WINDOW,
                    request,
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 11,
                            sequence: 2,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&req_packet),
                    })
                    .await
                    .expect("HTTP request frame should send");

                let mut http_bytes = Vec::new();
                for _ in 0..12 {
                    let frame = timeout(Duration::from_secs(6), transport.recv())
                        .await
                        .expect("response should arrive within timeout")
                        .expect("response frame should be readable");
                    let pkt = parse_ipv4_tcp_packet(&frame.payload)
                        .expect("response should be valid IPv4/TCP packet");

                    if pkt.payload.is_empty() {
                        continue;
                    }
                    http_bytes.extend_from_slice(&pkt.payload);

                    if http_bytes.windows(2).any(|w| w == b"\r\n") {
                        break;
                    }
                }

                let line_end = http_bytes
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .expect("HTTP status line should be present");
                let status_line = String::from_utf8_lossy(&http_bytes[..line_end]);
                assert!(
                    status_line.starts_with("HTTP/1."),
                    "unexpected status line: {status_line}"
                );

                let status_code = status_line
                    .split_whitespace()
                    .nth(1)
                    .expect("status code should be present")
                    .parse::<u16>()
                    .expect("status code should parse");
                assert!(
                    (200..500).contains(&status_code),
                    "status code should indicate non-server-error response, got {status_code}"
                );

                break;
            }
            Err(err) => {
                last_error = err;
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    assert!(
        connected,
        "rust client failed to connect/authenticate to local server: {last_error}"
    );

    server_task.abort();
    let _ = fs::remove_file(authorized_path);
    let _ = fs::remove_file(&invites_path);
    let _ = fs::remove_file(private_key_path);
    let _ = fs::remove_file(public_key_path);
}

#[tokio::test]
#[ignore = "manual diagnostic: requires internet egress from server host and may be flaky in CI"]
async fn localhost_server_and_rust_client_can_run_smtp_commands_over_tcp_packets() {
    const TCP_SYN: u8 = 0x02;
    const TCP_ACK: u8 = 0x10;
    const TCP_PSH: u8 = 0x08;
    const TCP_SYN_ACK: u8 = TCP_SYN | TCP_ACK;
    const TCP_PSH_ACK: u8 = TCP_PSH | TCP_ACK;
    const CLIENT_VIRTUAL_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
    const CLIENT_PORT: u16 = 54323;
    const CLIENT_ISN: u32 = 7000;
    const WINDOW: u16 = 65535;

    let mut smtp_ipv4 = None;
    let resolved = tokio::net::lookup_host(("smtp.gmail.com", 587))
        .await
        .expect("smtp server should resolve");
    for addr in resolved {
        if let SocketAddr::V4(v4) = addr {
            smtp_ipv4 = Some(*v4.ip());
            break;
        }
    }
    let target_ip = smtp_ipv4.expect("smtp server should resolve to an IPv4 address");

    let keypair = DeviceKeypair::generate();
    let authorized_path = temp_file_path("server-smtp-ipv4-keys");
    let invites_path = temp_file_path("server-smtp-ipv4-invites");
    let private_key_path = temp_file_path("server-smtp-ipv4-private");
    let public_key_path = temp_file_path("server-smtp-ipv4-public");

    fs::write(
        &authorized_path,
        format!(
            "[[devices]]\ndevice_id = \"smtp-ipv4-test\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys should write");
    fs::write(
        &invites_path,
        "[[tokens]]\ntoken = \"unused\"\nexpires_at = \"unix:9999999999\"\nuses_remaining = 1\n",
    )
    .expect("invites file should write");
    fs::write(&private_key_path, format!("{}\n", keypair.private_key_b64))
        .expect("private key should write");
    fs::write(&public_key_path, format!("{}\n", keypair.public_key_b64))
        .expect("public key should write");

    let bind = pick_ephemeral_bind();
    let store = AuthorizedKeysStore::load(&authorized_path).expect("authorized keys should load");
    let bind_for_server = bind.clone();
    let invite_for_server = invites_path
        .to_str()
        .expect("path should be utf-8")
        .to_owned();
    let server_task = tokio::spawn(async move {
        crate::run_server(
            &bind_for_server,
            &invite_for_server,
            Arc::new(DeviceKeypair::generate()),
            store,
            crate::session_registry::SessionRegistry::default(),
            Arc::new(RwLock::new(HashMap::new())),
            None,
            None,
            std::net::SocketAddr::from(([192, 0, 2, 53], 53)),
        )
        .await
    });

    let mut connected = false;
    let mut last_error = String::new();

    for _ in 0..20 {
        match try_establish_client_stream(&bind, &private_key_path, &public_key_path).await {
            Ok(stream) => {
                connected = true;
                let mut transport = NaiveTcpTransport::from_stream(stream);

                let syn_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    target_ip,
                    CLIENT_PORT,
                    587,
                    CLIENT_ISN,
                    0,
                    TCP_SYN,
                    WINDOW,
                    &[],
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 12,
                            sequence: 0,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&syn_packet),
                    })
                    .await
                    .expect("SYN frame should send");

                let syn_ack_frame = timeout(Duration::from_secs(8), transport.recv())
                    .await
                    .expect("SYN-ACK should arrive within timeout")
                    .expect("SYN-ACK frame should be readable");
                let syn_ack = parse_ipv4_tcp_packet(&syn_ack_frame.payload)
                    .expect("SYN-ACK should be a valid IPv4/TCP packet");
                assert_eq!(
                    syn_ack.flags & TCP_SYN_ACK,
                    TCP_SYN_ACK,
                    "flags should include SYN+ACK (got 0x{:02x})",
                    syn_ack.flags
                );
                let server_isn = syn_ack.seq;

                let ack_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    target_ip,
                    CLIENT_PORT,
                    587,
                    CLIENT_ISN.wrapping_add(1),
                    server_isn.wrapping_add(1),
                    TCP_ACK,
                    WINDOW,
                    &[],
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 12,
                            sequence: 1,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&ack_packet),
                    })
                    .await
                    .expect("ACK frame should send");

                let ehlo = b"EHLO bonded.test\r\n";
                let ehlo_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    target_ip,
                    CLIENT_PORT,
                    587,
                    CLIENT_ISN.wrapping_add(1),
                    server_isn.wrapping_add(1),
                    TCP_PSH_ACK,
                    WINDOW,
                    ehlo,
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 12,
                            sequence: 2,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&ehlo_packet),
                    })
                    .await
                    .expect("EHLO frame should send");

                let ehlo_frame = timeout(Duration::from_secs(8), transport.recv())
                    .await
                    .expect("EHLO response should arrive within timeout")
                    .expect("EHLO response frame should be readable");
                let ehlo_resp = parse_ipv4_tcp_packet(&ehlo_frame.payload)
                    .expect("EHLO response should be valid IPv4/TCP packet");
                assert!(
                    !ehlo_resp.payload.is_empty(),
                    "EHLO response payload should not be empty"
                );
                let ehlo_text = String::from_utf8_lossy(&ehlo_resp.payload);
                assert!(
                    ehlo_text.contains("220") || ehlo_text.contains("250"),
                    "expected SMTP banner/EHLO response codes in payload, got: {ehlo_text}"
                );

                let quit = b"QUIT\r\n";
                let quit_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    target_ip,
                    CLIENT_PORT,
                    587,
                    CLIENT_ISN.wrapping_add(1 + ehlo.len() as u32),
                    server_isn.wrapping_add(1),
                    TCP_PSH_ACK,
                    WINDOW,
                    quit,
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 12,
                            sequence: 3,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&quit_packet),
                    })
                    .await
                    .expect("QUIT frame should send");

                let quit_frame = timeout(Duration::from_secs(8), transport.recv())
                    .await
                    .expect("QUIT response should arrive within timeout")
                    .expect("QUIT response frame should be readable");
                let quit_resp = parse_ipv4_tcp_packet(&quit_frame.payload)
                    .expect("QUIT response should be valid IPv4/TCP packet");
                let quit_text = String::from_utf8_lossy(&quit_resp.payload);
                assert!(
                    quit_text.contains("221")
                        || quit_text.contains("250")
                        || quit_text.contains("220"),
                    "expected SMTP QUIT/server response code in payload, got: {quit_text}"
                );

                break;
            }
            Err(err) => {
                last_error = err;
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    assert!(
        connected,
        "rust client failed to connect/authenticate to local server: {last_error}"
    );

    server_task.abort();
    let _ = fs::remove_file(authorized_path);
    let _ = fs::remove_file(&invites_path);
    let _ = fs::remove_file(private_key_path);
    let _ = fs::remove_file(public_key_path);
}

async fn try_establish_client_stream(
    bind: &str,
    private_key_path: &std::path::Path,
    public_key_path: &std::path::Path,
) -> Result<tokio::net::TcpStream, String> {
    let mut cfg = ClientConfig::default();
    cfg.client.server_public_address = bind.to_owned();
    cfg.client.server_websocket_address = bind.to_owned();
    cfg.client.private_key_path = private_key_path.display().to_string();
    cfg.client.public_key_path = public_key_path.display().to_string();
    cfg.client.invite_token = String::new();
    cfg.client.preferred_protocols = vec!["naive_tcp".to_owned()];

    establish_naive_tcp_session(&cfg)
        .await
        .map_err(|err| err.to_string())
}

fn pick_ephemeral_bind() -> String {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("ephemeral bind should work");
    let addr = listener
        .local_addr()
        .expect("ephemeral local address should resolve");
    format!("127.0.0.1:{}", addr.port())
}

fn build_dns_query_example_com() -> (Vec<u8>, u16) {
    let query_id: u16 = 0x1234;
    let payload = vec![
        0x12, 0x34, 0x01, 0x00, // id + standard query with recursion desired
        0x00, 0x01, 0x00, 0x00, // qdcount=1, ancount=0
        0x00, 0x00, 0x00, 0x00, // nscount=0, arcount=0
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // qname
        0x00, 0x01, // qtype=A
        0x00, 0x01, // qclass=IN
    ];
    (payload, query_id)
}

#[derive(Debug, Clone)]
struct Ipv4UdpPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
}

fn parse_ipv4_udp_packet(packet: &[u8]) -> Option<Ipv4UdpPacket> {
    if packet.len() < 28 {
        return None;
    }

    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 {
        return None;
    }

    let header_len = ihl * 4;
    if packet.len() < header_len + 8 {
        return None;
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len + 8 || total_len > packet.len() {
        return None;
    }

    if packet[9] != 17 {
        return None;
    }

    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    let udp_start = header_len;
    let udp_len = u16::from_be_bytes([packet[udp_start + 4], packet[udp_start + 5]]) as usize;
    if udp_len < 8 || udp_start + udp_len > total_len {
        return None;
    }

    let src_port = u16::from_be_bytes([packet[udp_start], packet[udp_start + 1]]);
    let dst_port = u16::from_be_bytes([packet[udp_start + 2], packet[udp_start + 3]]);
    let payload = packet[(udp_start + 8)..(udp_start + udp_len)].to_vec();

    Some(Ipv4UdpPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload,
    })
}

fn build_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    identification: u16,
    udp_payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let ip_header_len = 20usize;
    let udp_header_len = 8usize;
    let total_len = ip_header_len + udp_header_len + udp_payload.len();
    if total_len > u16::MAX as usize {
        anyhow::bail!("udp packet too large for ipv4");
    }

    let udp_len = (udp_header_len + udp_payload.len()) as u16;
    let mut packet = vec![0_u8; total_len];

    packet[0] = 0x45;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&identification.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[10..12].copy_from_slice(&[0, 0]);
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());

    let udp_start = ip_header_len;
    packet[udp_start..udp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[udp_start + 2..udp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());
    packet[udp_start + 6..udp_start + 8].copy_from_slice(&[0, 0]);
    packet[(udp_start + 8)..].copy_from_slice(udp_payload);

    let ip_checksum = checksum_ones_complement(&packet[..ip_header_len]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp_checksum = udp_checksum_ipv4(src_ip, dst_ip, &packet[udp_start..]);
    packet[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    Ok(packet)
}

fn checksum_ones_complement(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }

    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

fn udp_checksum_ipv4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_segment.len() + (udp_segment.len() % 2));
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_segment);
    if udp_segment.len() % 2 == 1 {
        pseudo.push(0);
    }

    let checksum = checksum_ones_complement(&pseudo);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

fn build_ipv4_icmp_echo_request(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    echo_id: u16,
    echo_seq: u16,
    data: &[u8],
) -> Vec<u8> {
    let icmp_len = 8 + data.len();
    let total_len = 20 + icmp_len;
    let mut packet = vec![0u8; total_len];

    // IPv4 header
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes()); // identification
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes()); // DF flag
    packet[8] = 64; // TTL
    packet[9] = 1; // protocol = ICMP
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());
    let ip_cksum = checksum_ones_complement(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // ICMP echo request header + data
    packet[20] = 8; // type = echo request
    packet[21] = 0; // code
    packet[24..26].copy_from_slice(&echo_id.to_be_bytes());
    packet[26..28].copy_from_slice(&echo_seq.to_be_bytes());
    packet[28..].copy_from_slice(data);
    let icmp_cksum = checksum_ones_complement(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp_cksum.to_be_bytes());

    packet
}

#[derive(Debug)]
struct Ipv4IcmpReplyPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    icmp_type: u8,
    echo_id: u16,
    echo_seq: u16,
}

fn parse_ipv4_icmp_packet(packet: &[u8]) -> Option<Ipv4IcmpReplyPacket> {
    if packet.len() < 28 {
        return None;
    }
    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 {
        return None;
    }
    let header_len = ihl * 4;
    if packet[9] != 1 {
        return None; // not ICMP
    }
    if packet.len() < header_len + 8 {
        return None;
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let icmp = &packet[header_len..];
    let icmp_type = icmp[0];
    let echo_id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let echo_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    Some(Ipv4IcmpReplyPacket {
        src_ip,
        dst_ip,
        icmp_type,
        echo_id,
        echo_seq,
    })
}

#[tokio::test]
async fn localhost_server_and_rust_client_can_relay_udp_echo() {
    use tokio::net::UdpSocket;

    // Start a local UDP echo server that reflects one datagram.
    let udp_echo = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp echo server should bind");
    let udp_echo_port = udp_echo
        .local_addr()
        .expect("udp echo addr should resolve")
        .port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        if let Ok((size, peer)) = udp_echo.recv_from(&mut buf).await {
            let _ = udp_echo.send_to(&buf[..size], peer).await;
        }
    });

    let keypair = DeviceKeypair::generate();
    let authorized_path = temp_file_path("server-udp-echo-keys");
    let invites_path = temp_file_path("server-udp-echo-invites");
    let private_key_path = temp_file_path("server-udp-echo-private");
    let public_key_path = temp_file_path("server-udp-echo-public");

    fs::write(
        &authorized_path,
        format!(
            "[[devices]]\ndevice_id = \"udp-echo-test\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys should write");
    fs::write(
        &invites_path,
        "[[tokens]]\ntoken = \"unused\"\nexpires_at = \"unix:9999999999\"\nuses_remaining = 1\n",
    )
    .expect("invites file should write");
    fs::write(&private_key_path, format!("{}\n", keypair.private_key_b64))
        .expect("private key should write");
    fs::write(&public_key_path, format!("{}\n", keypair.public_key_b64))
        .expect("public key should write");

    let bind = pick_ephemeral_bind();
    let store = AuthorizedKeysStore::load(&authorized_path).expect("authorized keys should load");
    let bind_for_server = bind.clone();
    let invite_for_server = invites_path
        .to_str()
        .expect("path should be utf-8")
        .to_owned();
    let server_task = tokio::spawn(async move {
        crate::run_server(
            &bind_for_server,
            &invite_for_server,
            Arc::new(DeviceKeypair::generate()),
            store,
            crate::session_registry::SessionRegistry::default(),
            Arc::new(RwLock::new(HashMap::new())),
            None,
            None,
            std::net::SocketAddr::from(([192, 0, 2, 53], 53)),
        )
        .await
    });

    let udp_payload = b"hello-udp-echo";
    let mut connected = false;
    let mut last_error = String::new();
    for _ in 0..20 {
        match try_establish_client_stream(&bind, &private_key_path, &public_key_path).await {
            Ok(stream) => {
                connected = true;
                let mut transport = NaiveTcpTransport::from_stream(stream);

                let packet = build_ipv4_udp_packet(
                    Ipv4Addr::new(10, 8, 0, 2),
                    Ipv4Addr::LOCALHOST,
                    54321,
                    udp_echo_port,
                    0xabcd,
                    udp_payload,
                )
                .expect("udp packet should build");

                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 1,
                            sequence: 0,
                            flags: 0,
                        },
                        payload: packet.into(),
                    })
                    .await
                    .expect("udp frame should send");

                let frame = timeout(Duration::from_secs(5), transport.recv())
                    .await
                    .expect("udp echo should respond within timeout")
                    .expect("udp response frame should arrive");

                let parsed = parse_ipv4_udp_packet(&frame.payload)
                    .expect("response should be a valid IPv4 UDP packet");
                assert_eq!(parsed.src_ip, Ipv4Addr::LOCALHOST);
                assert_eq!(parsed.dst_ip, Ipv4Addr::new(10, 8, 0, 2));
                assert_eq!(parsed.src_port, udp_echo_port);
                assert_eq!(parsed.dst_port, 54321);
                assert_eq!(&parsed.payload[..], udp_payload);
                break;
            }
            Err(err) => {
                last_error = err;
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    assert!(
        connected,
        "rust client failed to connect to local server: {last_error}"
    );
    server_task.abort();
    let _ = fs::remove_file(authorized_path);
    let _ = fs::remove_file(&invites_path);
    let _ = fs::remove_file(private_key_path);
    let _ = fs::remove_file(public_key_path);
}

#[tokio::test]
async fn localhost_server_and_rust_client_can_relay_icmp_echo_to_localhost() {
    let keypair = DeviceKeypair::generate();
    let authorized_path = temp_file_path("server-icmp-echo-keys");
    let invites_path = temp_file_path("server-icmp-echo-invites");
    let private_key_path = temp_file_path("server-icmp-echo-private");
    let public_key_path = temp_file_path("server-icmp-echo-public");

    fs::write(
        &authorized_path,
        format!(
            "[[devices]]\ndevice_id = \"icmp-echo-test\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys should write");
    fs::write(
        &invites_path,
        "[[tokens]]\ntoken = \"unused\"\nexpires_at = \"unix:9999999999\"\nuses_remaining = 1\n",
    )
    .expect("invites file should write");
    fs::write(&private_key_path, format!("{}\n", keypair.private_key_b64))
        .expect("private key should write");
    fs::write(&public_key_path, format!("{}\n", keypair.public_key_b64))
        .expect("public key should write");

    let bind = pick_ephemeral_bind();
    let store = AuthorizedKeysStore::load(&authorized_path).expect("authorized keys should load");
    let bind_for_server = bind.clone();
    let invite_for_server = invites_path
        .to_str()
        .expect("path should be utf-8")
        .to_owned();
    let server_task = tokio::spawn(async move {
        crate::run_server(
            &bind_for_server,
            &invite_for_server,
            Arc::new(DeviceKeypair::generate()),
            store,
            crate::session_registry::SessionRegistry::default(),
            Arc::new(RwLock::new(HashMap::new())),
            None,
            None,
            std::net::SocketAddr::from(([192, 0, 2, 53], 53)),
        )
        .await
    });

    let echo_id: u16 = 0x4242;
    let echo_seq: u16 = 7;
    let icmp_data = b"bonded-icmp";
    let packet = build_ipv4_icmp_echo_request(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::LOCALHOST,
        echo_id,
        echo_seq,
        icmp_data,
    );

    let mut connected = false;
    let mut last_error = String::new();
    for _ in 0..20 {
        match try_establish_client_stream(&bind, &private_key_path, &public_key_path).await {
            Ok(stream) => {
                connected = true;
                let mut transport = NaiveTcpTransport::from_stream(stream);

                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 2,
                            sequence: 0,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&packet),
                    })
                    .await
                    .expect("icmp frame should send");

                let frame = timeout(Duration::from_secs(5), transport.recv())
                    .await
                    .expect("icmp echo should respond within timeout")
                    .expect("icmp response frame should arrive");

                let parsed = parse_ipv4_icmp_packet(&frame.payload)
                    .expect("response should be a valid IPv4 ICMP packet");
                assert_eq!(
                    parsed.src_ip,
                    Ipv4Addr::LOCALHOST,
                    "src_ip should be 127.0.0.1"
                );
                assert_eq!(
                    parsed.dst_ip,
                    Ipv4Addr::new(10, 8, 0, 2),
                    "dst_ip should be the virtual client address"
                );
                assert_eq!(parsed.icmp_type, 0, "ICMP type should be 0 (echo reply)");
                assert_eq!(parsed.echo_id, echo_id, "echo identifier should match");
                assert_eq!(parsed.echo_seq, echo_seq, "echo sequence should match");
                break;
            }
            Err(err) => {
                last_error = err;
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    assert!(
        connected,
        "rust client failed to connect to local server: {last_error}"
    );
    server_task.abort();
    let _ = fs::remove_file(authorized_path);
    let _ = fs::remove_file(&invites_path);
    let _ = fs::remove_file(private_key_path);
    let _ = fs::remove_file(public_key_path);
}

// ─── TCP VPN packet-level forwarding ────────────────────────────────────────
//
// How VPN TCP forwarding works (required to make the test below pass):
//
//   1. The TUN device on the client captures full IPv4+TCP packets (SYN, ACK,
//      PSH+ACK, FIN, …) and wraps them in SessionFrames.
//   2. frame_forwarder detects protocol=6 (TCP) by inspecting packet[9].
//   3. It maintains a NAT flow table keyed on (src_ip, src_port, dst_ip, dst_port).
//   4. On SYN  → open a real TcpStream to (dst_ip, dst_port); synthesise SYN-ACK
//              with a server-chosen ISN; ack = client_seq + 1.
//   5. On ACK  → update flow state; no response needed.
//   6. On data → write payload to the TcpStream; read response; synthesise a
//              PSH+ACK response packet addressed back to the client virtual IP.
//   7. On FIN  → half-close the TcpStream; synthesise FIN+ACK.
//
// The `upstream_tcp_target` field that exists in the current server is an
// entirely different concept (a raw byte-pipe to a fixed host) and is NOT the
// mechanism used here.

#[derive(Debug)]
struct Ipv4TcpPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack_seq: u32,
    flags: u8,
    payload: Vec<u8>,
}

fn parse_ipv4_tcp_packet(packet: &[u8]) -> Option<Ipv4TcpPacket> {
    if packet.len() < 40 {
        return None;
    }
    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 {
        return None;
    }
    let header_len = ihl * 4;
    if packet[9] != 6 {
        return None; // not TCP
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len > packet.len() {
        return None;
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let tcp = &packet[header_len..total_len];
    if tcp.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack_seq = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let tcp_header_bytes = ((tcp[12] >> 4) as usize) * 4;
    if tcp_header_bytes < 20 || tcp.len() < tcp_header_bytes {
        return None;
    }
    let flags = tcp[13];
    let payload = tcp[tcp_header_bytes..].to_vec();
    Some(Ipv4TcpPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack_seq,
        flags,
        payload,
    })
}

fn build_ipv4_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack_seq: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ip_hlen = 20usize;
    let tcp_hlen = 20usize;
    let total = ip_hlen + tcp_hlen + payload.len();
    let mut pkt = vec![0u8; total];

    // IPv4 header
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF flag
    pkt[8] = 64; // TTL
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_cksum = checksum_ones_complement(&pkt[..ip_hlen]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // TCP header
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&ack_seq.to_be_bytes());
    pkt[32] = 0x50; // data offset=5 (20 bytes), no options
    pkt[33] = flags;
    pkt[34..36].copy_from_slice(&window.to_be_bytes());
    if !payload.is_empty() {
        pkt[40..].copy_from_slice(payload);
    }
    let tcp_cksum = tcp_checksum_ipv4(src_ip, dst_ip, &pkt[ip_hlen..]);
    pkt[36..38].copy_from_slice(&tcp_cksum.to_be_bytes());

    pkt
}

fn tcp_checksum_ipv4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len() + 1);
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0);
    pseudo.push(6); // TCP protocol number
    pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    if tcp_segment.len() % 2 == 1 {
        pseudo.push(0);
    }
    let cksum = checksum_ones_complement(&pseudo);
    if cksum == 0 {
        0xffff
    } else {
        cksum
    }
}

/// End-to-end test for TCP packet-level NAT/proxy through the bonded server.
///
/// Sequence:
///   client → SYN       → server            (server opens real TCP to echo host)
///   client ← SYN-ACK   ← server            (server synthesises reply)
///   client → ACK        → server
///   client → PSH+ACK    → server            (data "hello-tcp-vpn")
///   client ← PSH+ACK    ← server → echo    (server proxies, echo replies)
///
/// To make this test pass, implement parse_ipv4_tcp_packet + a per-flow NAT
/// table in frame_forwarder.rs (see the design comment above).
#[tokio::test]
async fn localhost_server_and_rust_client_can_relay_tcp_as_ipv4_packets() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt as _};

    const TCP_SYN: u8 = 0x02;
    const TCP_ACK: u8 = 0x10;
    const TCP_PSH: u8 = 0x08;
    const TCP_SYN_ACK: u8 = TCP_SYN | TCP_ACK;
    const TCP_PSH_ACK: u8 = TCP_PSH | TCP_ACK;
    const CLIENT_VIRTUAL_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
    const CLIENT_PORT: u16 = 54321;
    const CLIENT_ISN: u32 = 1000;
    const WINDOW: u16 = 65535;

    // Start a local TCP echo server: accept one connection, read, echo the bytes back.
    let echo_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("tcp echo listener should bind");
    let echo_port = echo_listener
        .local_addr()
        .expect("echo addr should resolve")
        .port();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = echo_listener.accept().await {
            let mut buf = vec![0u8; 4096];
            if let Ok(n) = stream.read(&mut buf).await {
                let _ = stream.write_all(&buf[..n]).await;
            }
        }
    });

    let keypair = DeviceKeypair::generate();
    let authorized_path = temp_file_path("server-tcp-ipv4-keys");
    let invites_path = temp_file_path("server-tcp-ipv4-invites");
    let private_key_path = temp_file_path("server-tcp-ipv4-private");
    let public_key_path = temp_file_path("server-tcp-ipv4-public");

    fs::write(
        &authorized_path,
        format!(
            "[[devices]]\ndevice_id = \"tcp-ipv4-test\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys should write");
    fs::write(
        &invites_path,
        "[[tokens]]\ntoken = \"unused\"\nexpires_at = \"unix:9999999999\"\nuses_remaining = 1\n",
    )
    .expect("invites file should write");
    fs::write(&private_key_path, format!("{}\n", keypair.private_key_b64))
        .expect("private key should write");
    fs::write(&public_key_path, format!("{}\n", keypair.public_key_b64))
        .expect("public key should write");

    let bind = pick_ephemeral_bind();
    let echo_target_ip = Ipv4Addr::LOCALHOST;
    let store = AuthorizedKeysStore::load(&authorized_path).expect("authorized keys should load");
    let bind_for_server = bind.clone();
    let invite_for_server = invites_path
        .to_str()
        .expect("path should be utf-8")
        .to_owned();
    let server_task = tokio::spawn(async move {
        crate::run_server(
            &bind_for_server,
            &invite_for_server,
            Arc::new(DeviceKeypair::generate()),
            store,
            crate::session_registry::SessionRegistry::default(),
            Arc::new(RwLock::new(HashMap::new())),
            None,
            None,
            std::net::SocketAddr::from(([192, 0, 2, 53], 53)),
        )
        .await
    });

    let mut connected = false;
    let mut last_error = String::new();
    for _ in 0..20 {
        match try_establish_client_stream(&bind, &private_key_path, &public_key_path).await {
            Ok(stream) => {
                connected = true;
                let mut transport = NaiveTcpTransport::from_stream(stream);

                // ── Step 1: SYN ────────────────────────────────────────────
                let syn_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    echo_target_ip,
                    CLIENT_PORT,
                    echo_port,
                    CLIENT_ISN,
                    0,
                    TCP_SYN,
                    WINDOW,
                    &[],
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 10,
                            sequence: 0,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&syn_packet),
                    })
                    .await
                    .expect("SYN frame should send");

                // ── Step 2: expect SYN-ACK ─────────────────────────────────
                let syn_ack_frame = timeout(Duration::from_secs(5), transport.recv())
                    .await
                    .expect("SYN-ACK should arrive within timeout")
                    .expect("SYN-ACK frame should be readable");
                let syn_ack = parse_ipv4_tcp_packet(&syn_ack_frame.payload)
                    .expect("SYN-ACK should be a valid IPv4/TCP packet");
                assert_eq!(
                    syn_ack.flags & TCP_SYN_ACK,
                    TCP_SYN_ACK,
                    "flags should include SYN+ACK (got 0x{:02x})",
                    syn_ack.flags
                );
                assert_eq!(
                    syn_ack.ack_seq,
                    CLIENT_ISN.wrapping_add(1),
                    "SYN-ACK ack_seq should be client ISN + 1"
                );
                assert_eq!(syn_ack.src_ip, echo_target_ip, "SYN-ACK src_ip");
                assert_eq!(syn_ack.dst_ip, CLIENT_VIRTUAL_IP, "SYN-ACK dst_ip");
                assert_eq!(syn_ack.src_port, echo_port, "SYN-ACK src_port");
                assert_eq!(syn_ack.dst_port, CLIENT_PORT, "SYN-ACK dst_port");
                let server_isn = syn_ack.seq;

                // ── Step 3: ACK to complete the handshake ──────────────────
                let ack_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    echo_target_ip,
                    CLIENT_PORT,
                    echo_port,
                    CLIENT_ISN.wrapping_add(1),
                    server_isn.wrapping_add(1),
                    TCP_ACK,
                    WINDOW,
                    &[],
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 10,
                            sequence: 1,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&ack_packet),
                    })
                    .await
                    .expect("ACK frame should send");

                // ── Step 4: PSH+ACK with payload ───────────────────────────
                let data: &[u8] = b"hello-tcp-vpn";
                let psh_ack_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    echo_target_ip,
                    CLIENT_PORT,
                    echo_port,
                    CLIENT_ISN.wrapping_add(1),
                    server_isn.wrapping_add(1),
                    TCP_PSH_ACK,
                    WINDOW,
                    data,
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 10,
                            sequence: 2,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&psh_ack_packet),
                    })
                    .await
                    .expect("PSH+ACK frame should send");

                // ── Step 5: expect echoed data ─────────────────────────────
                // The server may return a bare ACK before the data frame; drain
                // ACK-only frames until we see one carrying a payload.
                let data_pkt = loop {
                    let frame = timeout(Duration::from_secs(5), transport.recv())
                        .await
                        .expect("data response should arrive within timeout")
                        .expect("data response frame should be readable");
                    let pkt = parse_ipv4_tcp_packet(&frame.payload)
                        .expect("data response should be a valid IPv4/TCP packet");
                    if !pkt.payload.is_empty() {
                        break pkt;
                    }
                };

                assert_eq!(data_pkt.src_ip, echo_target_ip, "response src_ip");
                assert_eq!(data_pkt.dst_ip, CLIENT_VIRTUAL_IP, "response dst_ip");
                assert_eq!(data_pkt.src_port, echo_port, "response src_port");
                assert_eq!(data_pkt.dst_port, CLIENT_PORT, "response dst_port");
                assert_eq!(
                    &data_pkt.payload[..],
                    data,
                    "echoed payload should match sent data"
                );

                break;
            }
            Err(err) => {
                last_error = err;
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    assert!(
        connected,
        "rust client failed to connect to local server: {last_error}"
    );
    server_task.abort();
    let _ = fs::remove_file(authorized_path);
    let _ = fs::remove_file(&invites_path);
    let _ = fs::remove_file(private_key_path);
    let _ = fs::remove_file(public_key_path);
}

/// Read frames until the SYN-ACK for one handshake arrives, skipping
/// stale frames from earlier connections on the same session (bare ACKs
/// for finished data, FIN-ACKs from a connection that just closed).
/// The fake client has no receive queue of its own, so leftovers from
/// an earlier connection would otherwise be mistaken for the next
/// handshake's SYN-ACK.
async fn recv_syn_ack(transport: &mut NaiveTcpTransport, dst_port: u16) -> Ipv4TcpPacket {
    const TCP_SYN_ACK: u8 = 0x02 | 0x10;
    const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);
    for _ in 0..10 {
        let frame = timeout(Duration::from_secs(5), transport.recv())
            .await
            .expect("SYN-ACK should arrive within timeout")
            .expect("SYN-ACK frame should be readable");
        let Some(pkt) = parse_ipv4_tcp_packet(&frame.payload) else {
            continue;
        };
        if pkt.src_ip == GATEWAY_IP
            && pkt.src_port == crate::tunnel_echo::TUN_ECHO_PORT
            && pkt.dst_port == dst_port
            && pkt.flags & TCP_SYN_ACK == TCP_SYN_ACK
        {
            return pkt;
        }
        // Stale frame from an earlier connection: skip it.
    }
    panic!("no SYN-ACK for client port {dst_port} arrived");
}

/// End-to-end test for the tunnel-gateway TCP echo endpoint
/// (10.8.0.1:18099).
///
/// Same harness as
/// `localhost_server_and_rust_client_can_relay_tcp_as_ipv4_packets`,
/// but the far end is the server's own echo listener — no external
/// echo server is started. The client drives raw IPv4/TCP packets
/// through a real NaiveTCP session to the real server binary.
///
/// Proves, through the production dispatch path
/// (`SmoltcpForwarder::dispatch_tcp` → dial-first → smoltcp bridge →
/// loopback echo listener):
///   * a SYN to 10.8.0.1:18099 is SYN-ACKed with the gateway as peer,
///   * a 32 KiB patterned payload sent in 1400-byte segments is echoed
///     back byte-for-byte (multi-segment, exercises the bridge's
///     partial-write handling),
///   * a second chunk on the same connection echoes (the connection
///     stays usable after a large transfer),
///   * an empty close on a second connection does not break the echo
///     (a third connection echoes fine afterwards).
///
/// The client tracks the server's sequence numbers and ACKs echoed
/// data as it arrives, so the server never sees the duplicate ACKs
/// that would trigger retransmits and corrupt the byte comparison.
#[tokio::test]
async fn tunnel_gateway_echo_returns_fixed_payload() {
    const TCP_SYN: u8 = 0x02;
    const TCP_ACK: u8 = 0x10;
    const TCP_PSH: u8 = 0x08;
    const TCP_FIN: u8 = 0x01;
    const TCP_PSH_ACK: u8 = TCP_PSH | TCP_ACK;
    const TCP_FIN_ACK: u8 = TCP_FIN | TCP_ACK;
    const CLIENT_VIRTUAL_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
    const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);
    const ECHO_PORT: u16 = crate::tunnel_echo::TUN_ECHO_PORT;
    const WINDOW: u16 = 65535;
    // One segment at a time, well under the tunnel MTU, so the fake
    // client never overruns smoltcp's receive window.
    const CHUNK: usize = 1400;

    let keypair = DeviceKeypair::generate();
    let authorized_path = temp_file_path("server-echo-keys");
    let invites_path = temp_file_path("server-echo-invites");
    let private_key_path = temp_file_path("server-echo-private");
    let public_key_path = temp_file_path("server-echo-public");

    fs::write(
        &authorized_path,
        format!(
            "[[devices]]\ndevice_id = \"echo-test\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys should write");
    fs::write(
        &invites_path,
        "[[tokens]]\ntoken = \"unused\"\nexpires_at = \"unix:9999999999\"\nuses_remaining = 1\n",
    )
    .expect("invites file should write");
    fs::write(&private_key_path, format!("{}\n", keypair.private_key_b64))
        .expect("private key should write");
    fs::write(&public_key_path, format!("{}\n", keypair.public_key_b64))
        .expect("public key should write");

    let bind = pick_ephemeral_bind();
    let store = AuthorizedKeysStore::load(&authorized_path).expect("authorized keys should load");
    let bind_for_server = bind.clone();
    let invite_for_server = invites_path
        .to_str()
        .expect("path should be utf-8")
        .to_owned();
    let server_task = tokio::spawn(async move {
        crate::run_server(
            &bind_for_server,
            &invite_for_server,
            Arc::new(DeviceKeypair::generate()),
            store,
            crate::session_registry::SessionRegistry::default(),
            Arc::new(RwLock::new(HashMap::new())),
            None,
            None,
            std::net::SocketAddr::from(([192, 0, 2, 53], 53)),
        )
        .await
    });

    let mut connected = false;
    let mut last_error = String::new();
    for _ in 0..20 {
        match try_establish_client_stream(&bind, &private_key_path, &public_key_path).await {
            Ok(stream) => {
                connected = true;
                let mut transport = NaiveTcpTransport::from_stream(stream);

                // ── Connection 1: handshake ────────────────────────
                const CLIENT_PORT: u16 = 54321;
                const CLIENT_ISN: u32 = 1000;
                let syn_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    GATEWAY_IP,
                    CLIENT_PORT,
                    ECHO_PORT,
                    CLIENT_ISN,
                    0,
                    TCP_SYN,
                    WINDOW,
                    &[],
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 10,
                            sequence: 0,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&syn_packet),
                    })
                    .await
                    .expect("SYN frame should send");

                let syn_ack = recv_syn_ack(&mut transport, CLIENT_PORT).await;
                assert_eq!(
                    syn_ack.ack_seq,
                    CLIENT_ISN.wrapping_add(1),
                    "SYN-ACK ack_seq should be client ISN + 1"
                );
                assert_eq!(syn_ack.src_ip, GATEWAY_IP, "SYN-ACK src_ip");
                assert_eq!(syn_ack.dst_ip, CLIENT_VIRTUAL_IP, "SYN-ACK dst_ip");
                assert_eq!(syn_ack.src_port, ECHO_PORT, "SYN-ACK src_port");
                assert_eq!(syn_ack.dst_port, CLIENT_PORT, "SYN-ACK dst_port");
                let server_isn = syn_ack.seq;

                // Server sequence the client has ACKed so far; advanced
                // as echoed data arrives so ACKs stay current.
                let mut client_ack = server_isn.wrapping_add(1);
                let mut client_seq = CLIENT_ISN.wrapping_add(1);
                let mut seq_no = 1u64;

                let ack_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    GATEWAY_IP,
                    CLIENT_PORT,
                    ECHO_PORT,
                    client_seq,
                    client_ack,
                    TCP_ACK,
                    WINDOW,
                    &[],
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 10,
                            sequence: seq_no,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&ack_packet),
                    })
                    .await
                    .expect("ACK frame should send");
                seq_no += 1;

                // ── 32 KiB patterned payload, one segment at a time ──
                let payload: Vec<u8> = (0..32 * 1024).map(|i| (i % 251) as u8).collect();
                let mut received: Vec<u8> = Vec::with_capacity(payload.len());
                for chunk in payload.chunks(CHUNK) {
                    let psh_ack_packet = build_ipv4_tcp_packet(
                        CLIENT_VIRTUAL_IP,
                        GATEWAY_IP,
                        CLIENT_PORT,
                        ECHO_PORT,
                        client_seq,
                        client_ack,
                        TCP_PSH_ACK,
                        WINDOW,
                        chunk,
                    );
                    client_seq = client_seq.wrapping_add(chunk.len() as u32);
                    transport
                        .send(SessionFrame {
                            header: SessionHeader {
                                connection_id: 10,
                                sequence: seq_no,
                                flags: 0,
                            },
                            payload: Bytes::copy_from_slice(&psh_ack_packet),
                        })
                        .await
                        .expect("PSH+ACK frame should send");
                    seq_no += 1;

                    // Drain echoed frames until this chunk is back.
                    let want = received.len() + chunk.len();
                    while received.len() < want {
                        let frame = timeout(Duration::from_secs(5), transport.recv())
                            .await
                            .expect("echoed data should arrive within timeout")
                            .expect("echoed frame should be readable");
                        let pkt = parse_ipv4_tcp_packet(&frame.payload)
                            .expect("echoed frame should be a valid IPv4/TCP packet");
                        if pkt.payload.is_empty() {
                            continue;
                        }
                        assert_eq!(pkt.src_ip, GATEWAY_IP, "echo src_ip");
                        assert_eq!(pkt.src_port, ECHO_PORT, "echo src_port");
                        client_ack =
                            client_ack.max(pkt.seq.wrapping_add(pkt.payload.len() as u32));
                        received.extend_from_slice(&pkt.payload);
                        // ACK echoed data immediately, like a real TCP
                        // stack: without prompt ACKs the server's RTO
                        // fires mid-transfer and retransmits segments
                        // the test would then count twice.
                        let ack_back = build_ipv4_tcp_packet(
                            CLIENT_VIRTUAL_IP,
                            GATEWAY_IP,
                            CLIENT_PORT,
                            ECHO_PORT,
                            client_seq,
                            client_ack,
                            TCP_ACK,
                            WINDOW,
                            &[],
                        );
                        transport
                            .send(SessionFrame {
                                header: SessionHeader {
                                    connection_id: 10,
                                    sequence: seq_no,
                                    flags: 0,
                                },
                                payload: Bytes::copy_from_slice(&ack_back),
                            })
                            .await
                            .expect("ACK frame should send");
                        seq_no += 1;
                    }
                }
                assert_eq!(
                    received, payload,
                    "32 KiB echoed payload must match sent bytes"
                );

                // ── Second chunk on the same connection ─────────────
                let second: &[u8] = b"second-round";
                let psh_ack_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    GATEWAY_IP,
                    CLIENT_PORT,
                    ECHO_PORT,
                    client_seq,
                    client_ack,
                    TCP_PSH_ACK,
                    WINDOW,
                    second,
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 10,
                            sequence: seq_no,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&psh_ack_packet),
                    })
                    .await
                    .expect("second PSH+ACK frame should send");
                seq_no += 1;
                let mut second_received: Vec<u8> = Vec::new();
                while second_received.len() < second.len() {
                    let frame = timeout(Duration::from_secs(5), transport.recv())
                        .await
                        .expect("second echo should arrive within timeout")
                        .expect("second echo frame should be readable");
                    let pkt = parse_ipv4_tcp_packet(&frame.payload)
                        .expect("second echo frame should be a valid IPv4/TCP packet");
                    second_received.extend_from_slice(&pkt.payload);
                }
                assert_eq!(
                    second_received, second,
                    "second chunk must echo on the same connection"
                );

                // ── Connection 2: empty close ───────────────────────
                // Open, handshake, FIN immediately without sending any
                // data. The server must not crash or wedge: a third
                // connection must still echo afterwards. (No FIN is
                // awaited from the server: the bridge holds a CloseWait
                // socket until the client fully closes, exactly like
                // any other proxied TCP flow.)
                const CLIENT_PORT_2: u16 = 54322;
                const CLIENT_ISN_2: u32 = 2000;
                let syn2 = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    GATEWAY_IP,
                    CLIENT_PORT_2,
                    ECHO_PORT,
                    CLIENT_ISN_2,
                    0,
                    TCP_SYN,
                    WINDOW,
                    &[],
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 10,
                            sequence: seq_no,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&syn2),
                    })
                    .await
                    .expect("second SYN frame should send");
                seq_no += 1;
                let syn_ack2 = recv_syn_ack(&mut transport, CLIENT_PORT_2).await;
                let server_isn_2 = syn_ack2.seq;
                let fin_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    GATEWAY_IP,
                    CLIENT_PORT_2,
                    ECHO_PORT,
                    CLIENT_ISN_2.wrapping_add(1),
                    server_isn_2.wrapping_add(1),
                    TCP_FIN_ACK,
                    WINDOW,
                    &[],
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 10,
                            sequence: seq_no,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&fin_packet),
                    })
                    .await
                    .expect("FIN frame should send");
                seq_no += 1;
                sleep(Duration::from_millis(200)).await;

                // ── Connection 3: echo still works ─────────────────
                const CLIENT_PORT_3: u16 = 54323;
                const CLIENT_ISN_3: u32 = 3000;
                let syn3 = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    GATEWAY_IP,
                    CLIENT_PORT_3,
                    ECHO_PORT,
                    CLIENT_ISN_3,
                    0,
                    TCP_SYN,
                    WINDOW,
                    &[],
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 10,
                            sequence: seq_no,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&syn3),
                    })
                    .await
                    .expect("third SYN frame should send");
                seq_no += 1;
                let syn_ack3 = recv_syn_ack(&mut transport, CLIENT_PORT_3).await;
                let server_isn_3 = syn_ack3.seq;
                let ack3 = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    GATEWAY_IP,
                    CLIENT_PORT_3,
                    ECHO_PORT,
                    CLIENT_ISN_3.wrapping_add(1),
                    server_isn_3.wrapping_add(1),
                    TCP_ACK,
                    WINDOW,
                    &[],
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 10,
                            sequence: seq_no,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&ack3),
                    })
                    .await
                    .expect("third ACK frame should send");
                seq_no += 1;
                let third: &[u8] = b"after-empty-close";
                let psh3 = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    GATEWAY_IP,
                    CLIENT_PORT_3,
                    ECHO_PORT,
                    CLIENT_ISN_3.wrapping_add(1),
                    server_isn_3.wrapping_add(1),
                    TCP_PSH_ACK,
                    WINDOW,
                    third,
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 10,
                            sequence: seq_no,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&psh3),
                    })
                    .await
                    .expect("third PSH+ACK frame should send");
                let mut third_received: Vec<u8> = Vec::new();
                while third_received.len() < third.len() {
                    let frame = timeout(Duration::from_secs(5), transport.recv())
                        .await
                        .expect("third echo should arrive within timeout")
                        .expect("third echo frame should be readable");
                    let pkt = parse_ipv4_tcp_packet(&frame.payload)
                        .expect("third echo frame should be a valid IPv4/TCP packet");
                    third_received.extend_from_slice(&pkt.payload);
                }
                assert_eq!(
                    third_received, third,
                    "echo must still work after an empty close"
                );

                break;
            }
            Err(err) => {
                last_error = err;
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    assert!(
        connected,
        "rust client failed to connect to local server: {last_error}"
    );
    server_task.abort();
    let _ = fs::remove_file(authorized_path);
    let _ = fs::remove_file(&invites_path);
    let _ = fs::remove_file(private_key_path);
    let _ = fs::remove_file(public_key_path);
}

/// A SYN to a non-echo port on the tunnel gateway must NOT be echoed:
/// it follows the existing dial-first path to 10.8.0.1, the dial
/// fails (the gateway is not a real host), and the client gets a RST
/// — never a SYN-ACK and never echoed data.
#[tokio::test]
async fn tunnel_gateway_non_echo_port_is_not_echoed() {
    const TCP_SYN: u8 = 0x02;
    const TCP_RST: u8 = 0x04;
    const TCP_ACK: u8 = 0x10;
    const CLIENT_VIRTUAL_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
    const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);
    const NON_ECHO_PORT: u16 = 18098;
    const CLIENT_PORT: u16 = 54321;
    const CLIENT_ISN: u32 = 1000;
    const WINDOW: u16 = 65535;

    let keypair = DeviceKeypair::generate();
    let authorized_path = temp_file_path("server-noecho-keys");
    let invites_path = temp_file_path("server-noecho-invites");
    let private_key_path = temp_file_path("server-noecho-private");
    let public_key_path = temp_file_path("server-noecho-public");

    fs::write(
        &authorized_path,
        format!(
            "[[devices]]\ndevice_id = \"noecho-test\"\npublic_key = \"{}\"\n",
            keypair.public_key_b64
        ),
    )
    .expect("authorized keys should write");
    fs::write(
        &invites_path,
        "[[tokens]]\ntoken = \"unused\"\nexpires_at = \"unix:9999999999\"\nuses_remaining = 1\n",
    )
    .expect("invites file should write");
    fs::write(&private_key_path, format!("{}\n", keypair.private_key_b64))
        .expect("private key should write");
    fs::write(&public_key_path, format!("{}\n", keypair.public_key_b64))
        .expect("public key should write");

    let bind = pick_ephemeral_bind();
    let store = AuthorizedKeysStore::load(&authorized_path).expect("authorized keys should load");
    let bind_for_server = bind.clone();
    let invite_for_server = invites_path
        .to_str()
        .expect("path should be utf-8")
        .to_owned();
    let server_task = tokio::spawn(async move {
        crate::run_server(
            &bind_for_server,
            &invite_for_server,
            Arc::new(DeviceKeypair::generate()),
            store,
            crate::session_registry::SessionRegistry::default(),
            Arc::new(RwLock::new(HashMap::new())),
            None,
            None,
            std::net::SocketAddr::from(([192, 0, 2, 53], 53)),
        )
        .await
    });

    let mut connected = false;
    let mut last_error = String::new();
    for _ in 0..20 {
        match try_establish_client_stream(&bind, &private_key_path, &public_key_path).await {
            Ok(stream) => {
                connected = true;
                let mut transport = NaiveTcpTransport::from_stream(stream);

                let syn_packet = build_ipv4_tcp_packet(
                    CLIENT_VIRTUAL_IP,
                    GATEWAY_IP,
                    CLIENT_PORT,
                    NON_ECHO_PORT,
                    CLIENT_ISN,
                    0,
                    TCP_SYN,
                    WINDOW,
                    &[],
                );
                transport
                    .send(SessionFrame {
                        header: SessionHeader {
                            connection_id: 10,
                            sequence: 0,
                            flags: 0,
                        },
                        payload: Bytes::copy_from_slice(&syn_packet),
                    })
                    .await
                    .expect("SYN frame should send");

                // The dial to 10.8.0.1:18098 fails (5 s dial budget at
                // most), so the answer must be a RST, not a SYN-ACK.
                let rst_frame = timeout(Duration::from_secs(15), transport.recv())
                    .await
                    .expect("RST should arrive within timeout")
                    .expect("RST frame should be readable");
                let rst = parse_ipv4_tcp_packet(&rst_frame.payload)
                    .expect("RST should be a valid IPv4/TCP packet");
                assert_eq!(rst.src_ip, GATEWAY_IP, "RST src_ip");
                assert_eq!(rst.src_port, NON_ECHO_PORT, "RST src_port");
                assert_eq!(rst.dst_port, CLIENT_PORT, "RST dst_port");
                assert!(
                    rst.flags & TCP_RST != 0,
                    "non-echo gateway port must RST, got flags 0x{:02x}",
                    rst.flags
                );
                assert!(
                    rst.flags & TCP_SYN == 0,
                    "non-echo gateway port must never SYN-ACK"
                );

                break;
            }
            Err(err) => {
                last_error = err;
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    assert!(
        connected,
        "rust client failed to connect to local server: {last_error}"
    );
    server_task.abort();
    let _ = fs::remove_file(authorized_path);
    let _ = fs::remove_file(&invites_path);
    let _ = fs::remove_file(private_key_path);
    let _ = fs::remove_file(public_key_path);
}
