use crate::session_registry::SessionRegistry;
use crate::smoltcp_forwarder::{
    IcmpProbeSnapshot, SessionContext, TcpFlowSnapshot, UdpFlowSnapshot,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info};

pub async fn run_status_server(
    bind: &str,
    sessions: SessionRegistry,
    forwarders: Arc<RwLock<HashMap<u64, Arc<SessionContext>>>>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(bind = %bind, "status listener bound");

    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => {
                error!(bind = %bind, error = %err, "failed to accept status connection");
                continue;
            }
        };

        let sessions = sessions.clone();
        let forwarders = forwarders.clone();

        tokio::spawn(async move {
            // Drain the request so the kernel can send FIN instead of RST.
            let mut request = Vec::with_capacity(1024);
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        request.extend_from_slice(&buf[..n]);
                        // HTTP headers end with \r\n\r\n; stop reading once seen.
                        if request.windows(4).any(|w| w == b"\r\n\r\n") || request.len() >= 8192 {
                            break;
                        }
                    }
                }
            }

            let target = parse_request_target(&request).unwrap_or("/");
            let (udp_flows, tcp_flows, icmp_probes) = {
                let mut udp_flows = Vec::new();
                let mut tcp_flows = Vec::new();
                let mut icmp_probes = Vec::new();
                let guard = forwarders
                    .read()
                    .expect("forwarder registry lock should not be poisoned");

                for ctx in guard.values() {
                    let snapshot = ctx.forwarder.snapshot();
                    udp_flows.extend(snapshot.udp_flows);
                    tcp_flows.extend(snapshot.tcp_flows);
                    icmp_probes.extend(snapshot.icmp_probes);
                }

                tcp_flows.sort_by(|left, right| {
                    left.session_id
                        .cmp(&right.session_id)
                        .then_with(|| left.client_src.cmp(&right.client_src))
                        .then_with(|| left.client_dst.cmp(&right.client_dst))
                });
                udp_flows.sort_by(|left, right| {
                    left.session_id
                        .cmp(&right.session_id)
                        .then_with(|| left.client_src.cmp(&right.client_src))
                        .then_with(|| left.client_dst.cmp(&right.client_dst))
                });

                (udp_flows, tcp_flows, icmp_probes)
            };

            let (status_line, content_type, body) = match target {
                "/" => (
                    "200 OK",
                    "text/html; charset=utf-8",
                    render_status_page(&sessions, &udp_flows, &tcp_flows, &icmp_probes),
                ),
                "/api/status" => (
                    "200 OK",
                    "application/json; charset=utf-8",
                    render_status_json(&sessions, &udp_flows, &tcp_flows, &icmp_probes),
                ),
                _ => (
                    "404 Not Found",
                    "text/plain; charset=utf-8",
                    "not found".to_owned(),
                ),
            };

            let body_bytes = body.as_bytes();
            let response = format!(
                "HTTP/1.1 {}\r\ncontent-type: {}\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                status_line,
                content_type,
                body_bytes.len(),
                body
            );

            if let Err(err) = stream.write_all(response.as_bytes()).await {
                error!(peer = %peer, error = %err, "failed to write status response");
                return;
            }
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
        });
    }
}

fn render_status_page(
    sessions: &SessionRegistry,
    udp_flows: &[UdpFlowSnapshot],
    tcp_flows: &[TcpFlowSnapshot],
    icmp_probes: &[IcmpProbeSnapshot],
) -> String {
    let session_rows = sessions
        .snapshot()
        .into_iter()
        .map(|entry| {
            format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                escape_html(&entry.session_id.to_string()),
                escape_html(&abbreviate_key(&entry.client_key))
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let udp_rows = udp_flows
        .iter()
        .map(|entry| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&entry.session_id.to_string()),
                escape_html(&entry.client_src),
                escape_html(&entry.client_dst),
                escape_html(&entry.bound_socket),
                escape_html(&entry.created_ago),
                escape_html(&entry.last_client_ago),
                escape_html(entry.last_remote_ago.as_deref().unwrap_or("never")),
                escape_html(&entry.client_to_remote_packets.to_string()),
                escape_html(&entry.remote_to_client_packets.to_string())
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let tcp_rows = tcp_flows
        .iter()
        .map(|entry| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{} B</td><td>{}</td><td>{} B</td><td>{}</td><td>{} B</td></tr>",
                escape_html(&entry.session_id.to_string()),
                escape_html(&entry.client_src),
                escape_html(&entry.client_dst),
                escape_html(&entry.created_ago),
                escape_html(&entry.last_activity_ago),
                escape_html(&entry.client_to_remote_packets.to_string()),
                escape_html(&entry.remote_to_client_packets.to_string()),
                escape_html(&entry.bridge_read_chunks.to_string()),
                escape_html(&entry.bridge_read_avg_bytes.to_string()),
                escape_html(&entry.bridge_read_bytes.to_string()),
                escape_html(&entry.bridge_to_smoltcp_chunks.to_string()),
                escape_html(&entry.bridge_to_smoltcp_avg_bytes.to_string()),
                escape_html(&entry.bridge_to_smoltcp_bytes.to_string())
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let icmp_rows = icmp_probes
        .iter()
        .take(64)
        .map(|entry| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&entry.session_id.to_string()),
                escape_html(&entry.client_src),
                escape_html(&entry.client_dst),
                escape_html(&entry.echo_identifier.to_string()),
                escape_html(&entry.echo_sequence.to_string()),
                escape_html(&entry.outcome),
                escape_html(&entry.observed_ago)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Bonded Server Status</title>
<style>
body {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; margin: 24px; background: #f8fafc; color: #111827; }}
h1 {{ margin-bottom: 8px; }}
.card {{ background: #ffffff; border: 1px solid #d1d5db; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ border-bottom: 1px solid #e5e7eb; text-align: left; padding: 8px; vertical-align: top; }}
th {{ background: #f3f4f6; }}
small {{ color: #6b7280; }}
</style>
</head>
<body>
<h1>Bonded Server Status</h1>
<small>Live updates every 2 seconds via <code>/api/status</code>.</small>
<div class="card">
<h2 id="sessions-title">Authenticated Sessions ({})</h2>
<table>
<thead><tr><th>Session ID</th><th>Client Key</th></tr></thead>
<tbody id="sessions-body">{}</tbody>
</table>
</div>
<div class="card">
<h2 id="udp-title">Active UDP Flows ({})</h2>
<table>
<thead><tr><th>Session ID</th><th>Client Source</th><th>Remote Target</th><th>Server UDP Socket</th><th>Created</th><th>Last Client Packet</th><th>Last Remote Packet</th><th>Client->Remote Packets</th><th>Remote->Client Packets</th></tr></thead>
<tbody id="udp-body">{}</tbody>
</table>
</div>
<div class="card">
<h2 id="tcp-title">Active TCP Flows ({})</h2>
<table>
<thead><tr><th>Session ID</th><th>Client Source</th><th>Remote Target</th><th>Created</th><th>Last Activity</th><th>Client->Remote Packets</th><th>Remote->Client Packets</th><th>Bridge Reads</th><th>Bridge Read Avg</th><th>Bridge Read Bytes</th><th>Smoltcp Writes</th><th>Smoltcp Write Avg</th><th>Smoltcp Write Bytes</th></tr></thead>
<tbody id="tcp-body">{}</tbody>
</table>
</div>
<div class="card">
<h2 id="icmp-title">Recent ICMP Probes ({})</h2>
<table>
<thead><tr><th>Session ID</th><th>Client Source</th><th>Remote Target</th><th>Echo ID</th><th>Seq</th><th>Outcome</th><th>Observed</th></tr></thead>
<tbody id="icmp-body">{}</tbody>
</table>
</div>
<script>
const el = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#x27;");

function setRows(id, rows, emptyMessage, columns) {{
    if (!rows.length) {{
        el(id).innerHTML = `<tr><td colspan="${{columns}}">${{escapeHtml(emptyMessage)}}</td></tr>`;
        return;
    }}
    el(id).innerHTML = rows.join("\n");
}}

function render(data) {{
    el("sessions-title").textContent = `Authenticated Sessions (${{data.sessions_count}})`;
    el("udp-title").textContent = `Active UDP Flows (${{data.udp_flows_count}})`;
    el("tcp-title").textContent = `Active TCP Flows (${{data.tcp_flows_count}})`;
    el("icmp-title").textContent = `Recent ICMP Probes (${{data.icmp_probes_count}})`;

    setRows(
        "sessions-body",
        data.sessions.map((entry) => `<tr><td>${{escapeHtml(entry.session_id)}}</td><td>${{escapeHtml(entry.client_key_abbrev)}}</td></tr>`),
        "No active authenticated sessions.",
        2
    );
    setRows(
        "udp-body",
        data.udp_flows.map((entry) => `<tr><td>${{escapeHtml(entry.session_id)}}</td><td>${{escapeHtml(entry.client_src)}}</td><td>${{escapeHtml(entry.client_dst)}}</td><td>${{escapeHtml(entry.bound_socket)}}</td><td>${{escapeHtml(entry.created_ago)}}</td><td>${{escapeHtml(entry.last_client_ago)}}</td><td>${{escapeHtml(entry.last_remote_ago ?? "never")}}</td><td>${{escapeHtml(entry.client_to_remote_packets)}}</td><td>${{escapeHtml(entry.remote_to_client_packets)}}</td></tr>`),
        "No active UDP flows.",
        9
    );
    setRows(
        "tcp-body",
        data.tcp_flows.map((entry) => `<tr><td>${{escapeHtml(entry.session_id)}}</td><td>${{escapeHtml(entry.client_src)}}</td><td>${{escapeHtml(entry.client_dst)}}</td><td>${{escapeHtml(entry.created_ago)}}</td><td>${{escapeHtml(entry.last_activity_ago)}}</td><td>${{escapeHtml(entry.client_to_remote_packets)}}</td><td>${{escapeHtml(entry.remote_to_client_packets)}}</td><td>${{escapeHtml(entry.bridge_read_chunks)}}</td><td>${{escapeHtml(entry.bridge_read_avg_bytes)}} B</td><td>${{escapeHtml(entry.bridge_read_bytes)}}</td><td>${{escapeHtml(entry.bridge_to_smoltcp_chunks)}}</td><td>${{escapeHtml(entry.bridge_to_smoltcp_avg_bytes)}} B</td><td>${{escapeHtml(entry.bridge_to_smoltcp_bytes)}}</td></tr>`),
        "No active TCP flows.",
        13
    );
    setRows(
        "icmp-body",
        data.icmp_probes.map((entry) => `<tr><td>${{escapeHtml(entry.session_id)}}</td><td>${{escapeHtml(entry.client_src)}}</td><td>${{escapeHtml(entry.client_dst)}}</td><td>${{escapeHtml(entry.echo_identifier)}}</td><td>${{escapeHtml(entry.echo_sequence)}}</td><td>${{escapeHtml(entry.outcome)}}</td><td>${{escapeHtml(entry.observed_ago)}}</td></tr>`),
        "No recent ICMP probes.",
        7
    );
}}

async function refresh() {{
    try {{
        const response = await fetch("/api/status", {{ cache: "no-store" }});
        if (!response.ok) {{
            return;
        }}
        const data = await response.json();
        render(data);
    }} catch (_) {{
        // Keep the last rendered state on transient failures.
    }}
}}

setInterval(refresh, 2000);
</script>
</body>
</html>"#,
        sessions.active_sessions(),
        if session_rows.is_empty() {
            "<tr><td colspan=\"2\">No active authenticated sessions.</td></tr>".to_owned()
        } else {
            session_rows
        },
        udp_flows.len(),
        if udp_rows.is_empty() {
            "<tr><td colspan=\"9\">No active UDP flows.</td></tr>".to_owned()
        } else {
            udp_rows
        },
        tcp_flows.len(),
        if tcp_rows.is_empty() {
            "<tr><td colspan=\"13\">No active TCP flows.</td></tr>".to_owned()
        } else {
            tcp_rows
        },
        icmp_probes.len(),
        if icmp_rows.is_empty() {
            "<tr><td colspan=\"7\">No recent ICMP probes.</td></tr>".to_owned()
        } else {
            icmp_rows
        }
    )
}

fn render_status_json(
    sessions: &SessionRegistry,
    udp_flows: &[UdpFlowSnapshot],
    tcp_flows: &[TcpFlowSnapshot],
    icmp_probes: &[IcmpProbeSnapshot],
) -> String {
    let sessions = sessions
        .snapshot()
        .into_iter()
        .map(|entry| {
            json!({
                "session_id": entry.session_id,
                "client_key": entry.client_key,
                "client_key_abbrev": abbreviate_key(&entry.client_key),
            })
        })
        .collect::<Vec<_>>();

    let udp_flows = udp_flows
        .iter()
        .map(|entry| {
            json!({
                "session_id": entry.session_id,
                "client_src": entry.client_src,
                "client_dst": entry.client_dst,
                "bound_socket": entry.bound_socket,
                "created_ago": entry.created_ago,
                "last_client_ago": entry.last_client_ago,
                "last_remote_ago": entry.last_remote_ago,
                "client_to_remote_packets": entry.client_to_remote_packets,
                "remote_to_client_packets": entry.remote_to_client_packets,
            })
        })
        .collect::<Vec<_>>();

    let tcp_flows = tcp_flows
        .iter()
        .map(|entry| {
            json!({
                "session_id": entry.session_id,
                "client_src": entry.client_src,
                "client_dst": entry.client_dst,
                "created_ago": entry.created_ago,
                "last_activity_ago": entry.last_activity_ago,
                "client_to_remote_packets": entry.client_to_remote_packets,
                "remote_to_client_packets": entry.remote_to_client_packets,
                "bridge_read_chunks": entry.bridge_read_chunks,
                "bridge_read_bytes": entry.bridge_read_bytes,
                "bridge_read_avg_bytes": entry.bridge_read_avg_bytes,
                "bridge_to_smoltcp_chunks": entry.bridge_to_smoltcp_chunks,
                "bridge_to_smoltcp_bytes": entry.bridge_to_smoltcp_bytes,
                "bridge_to_smoltcp_avg_bytes": entry.bridge_to_smoltcp_avg_bytes,
            })
        })
        .collect::<Vec<_>>();

    let icmp_probes = icmp_probes
        .iter()
        .take(64)
        .map(|entry| {
            json!({
                "session_id": entry.session_id,
                "client_src": entry.client_src,
                "client_dst": entry.client_dst,
                "echo_identifier": entry.echo_identifier,
                "echo_sequence": entry.echo_sequence,
                "outcome": entry.outcome,
                "observed_ago": entry.observed_ago,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "sessions_count": sessions.len(),
        "udp_flows_count": udp_flows.len(),
        "tcp_flows_count": tcp_flows.len(),
        "icmp_probes_count": icmp_probes.len(),
        "sessions": sessions,
        "udp_flows": udp_flows,
        "tcp_flows": tcp_flows,
        "icmp_probes": icmp_probes,
    })
    .to_string()
}

fn parse_request_target(request: &[u8]) -> Option<&str> {
    let request = std::str::from_utf8(request).ok()?;
    let request_line = request.lines().next()?;
    let mut parts = request_line.split_whitespace();
    let _method = parts.next()?;
    parts.next()
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn abbreviate_key(key: &str) -> String {
    if key.len() <= 24 {
        return key.to_owned();
    }

    format!("{}...{}", &key[..12], &key[key.len() - 8..])
}
