//! Local HTTP integration server for Lancer cross-tool interop.
//!
//! Every Lancer-clone GUI exposes a tiny HTTP server on an auto-allocated
//! `127.0.0.1:<port>` (written to `%TEMP%/lancer-agentic-radar.port`) so the
//! mothership GUI and sibling tools can discover it and exchange payloads:
//!
//! * `GET  /v1/state`               — current job / progress + summary counts
//! * `POST /v1/import`              — accept a target path / record from a sibling tool
//! * `GET  /v1/export?format=json|csv|sarif|markdown|html` — pull the current report
//!
//! Implemented as a dependency-free HTTP/1.1 handler over a Tokio listener so we
//! don't pull in a web framework.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ar_core::{Report, ReportFormat};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// State shared between the GUI thread and the HTTP server.
#[derive(Default)]
pub struct SharedState {
    pub report: Option<Report>,
    pub status: String,
    pub busy: bool,
    pub last_input: Option<PathBuf>,
    /// A target path / record pushed in by a sibling tool via `/v1/import`,
    /// polled and consumed by the GUI.
    pub pending_import: Option<String>,
    pub port: u16,
}

pub type Shared = Arc<Mutex<SharedState>>;

pub fn new_shared() -> Shared {
    Arc::new(Mutex::new(SharedState {
        status: "idle".into(),
        ..Default::default()
    }))
}

/// Spawn the integration server on a background thread with its own Tokio
/// runtime. Returns the bound port (0 if it failed to start).
pub fn start(shared: Shared) -> u16 {
    // Bind synchronously first so we can return the real port to the GUI.
    let std_listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("integration server: bind failed: {e}");
            return 0;
        }
    };
    let port = std_listener.local_addr().map(|a| a.port()).unwrap_or(0);
    if let Ok(mut s) = shared.lock() {
        s.port = port;
    }
    if let Err(e) = std_listener.set_nonblocking(true) {
        tracing::warn!("integration server: set_nonblocking failed: {e}");
    }
    write_port_file(port);

    let shared2 = shared.clone();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                tracing::warn!("integration server: runtime failed: {e}");
                return;
            }
        };
        rt.block_on(async move {
            let listener = match TcpListener::from_std(std_listener) {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!("integration server: listener failed: {e}");
                    return;
                }
            };
            tracing::info!("integration server listening on 127.0.0.1:{port}");
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let s = shared2.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle(stream, s).await {
                                tracing::debug!("integration request error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::debug!("accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        });
    });
    port
}

fn write_port_file(port: u16) {
    let path = std::env::temp_dir().join("lancer-agentic-radar.port");
    let _ = std::fs::write(path, port.to_string());
}

/// Remove the port file on shutdown (best-effort).
pub fn cleanup_port_file() {
    let path = std::env::temp_dir().join("lancer-agentic-radar.port");
    let _ = std::fs::remove_file(path);
}

async fn handle(mut stream: TcpStream, shared: Shared) -> std::io::Result<()> {
    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let raw = String::from_utf8_lossy(&buf[..n]);
    let (method, path, body) = parse_request(&raw);

    let (status, content_type, payload) = route(&method, &path, body, &shared);

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(payload.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

fn parse_request(raw: &str) -> (String, String, &str) {
    let mut lines = raw.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("");
    (method, path, body)
}

fn route(
    method: &str,
    path: &str,
    body: &str,
    shared: &Shared,
) -> (&'static str, &'static str, String) {
    let (route_path, query) = match path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path, ""),
    };

    match (method, route_path) {
        ("GET", "/v1/state") => {
            let json = state_json(shared);
            ("200 OK", "application/json", json)
        }
        ("POST", "/v1/import") => {
            // Body may be a bare path or a JSON object { "path": "..." }.
            let imported = extract_import(body);
            if let Ok(mut s) = shared.lock() {
                s.pending_import = Some(imported.clone());
            }
            (
                "200 OK",
                "application/json",
                format!("{{\"imported\":{}}}", json_str(&imported)),
            )
        }
        ("GET", "/v1/export") => export(query, shared),
        ("GET", "/") | ("GET", "/health") => {
            ("200 OK", "text/plain", "lancer-agentic-radar".to_string())
        }
        ("OPTIONS", _) => ("204 No Content", "text/plain", String::new()),
        _ => ("404 Not Found", "text/plain", "not found".to_string()),
    }
}

fn state_json(shared: &Shared) -> String {
    let guard = shared.lock().ok();
    let (status, busy, port, summary) = match guard {
        Some(s) => {
            let summary = s.report.as_ref().map(|r| {
                let counts = r.severity_counts();
                serde_json::json!({
                    "agents": r.stats.agents,
                    "tools": r.stats.tools,
                    "findings": r.active_findings().count(),
                    "severities": counts.iter().map(|(k,v)| (k.as_str().to_string(), *v)).collect::<std::collections::BTreeMap<_,_>>(),
                })
            });
            (s.status.clone(), s.busy, s.port, summary)
        }
        None => ("unknown".to_string(), false, 0, None),
    };
    serde_json::json!({
        "tool": "lancer-agentic-radar",
        "status": status,
        "busy": busy,
        "port": port,
        "report": summary,
    })
    .to_string()
}

fn extract_import(body: &str) -> String {
    let body = body.trim().trim_end_matches('\0');
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(p) = v.get("path").and_then(|x| x.as_str()) {
            return p.to_string();
        }
        if let Some(p) = v.get("target").and_then(|x| x.as_str()) {
            return p.to_string();
        }
    }
    body.to_string()
}

fn export(query: &str, shared: &Shared) -> (&'static str, &'static str, String) {
    let fmt = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("format="))
        .unwrap_or("json");
    let guard = shared.lock().ok();
    let report = match guard.as_ref().and_then(|s| s.report.as_ref()) {
        Some(r) => r,
        None => {
            return (
                "200 OK",
                "application/json",
                "{\"error\":\"no report available\"}".to_string(),
            )
        }
    };
    match fmt {
        "csv" => ("200 OK", "text/csv", export_csv(report)),
        "json" => ("200 OK", "application/json", ar_report::render(report, ReportFormat::Json)),
        "sarif" => (
            "200 OK",
            "application/sarif+json",
            ar_report::render(report, ReportFormat::Sarif),
        ),
        "markdown" | "md" => (
            "200 OK",
            "text/markdown",
            ar_report::render(report, ReportFormat::Markdown),
        ),
        "html" => ("200 OK", "text/html", ar_report::render(report, ReportFormat::Html)),
        _ => (
            "400 Bad Request",
            "text/plain",
            format!("unsupported format: {fmt}"),
        ),
    }
}

fn export_csv(report: &Report) -> String {
    let mut s = String::from("detector_id,category,severity,title,agent,tool,location\n");
    for f in report.active_findings() {
        s.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            csv_cell(&f.detector_id),
            csv_cell(f.category.id()),
            csv_cell(f.severity.as_str()),
            csv_cell(&f.title),
            csv_cell(f.agent.as_ref().map(|a| a.as_str()).unwrap_or("")),
            csv_cell(f.tool.as_ref().map(|t| t.as_str()).unwrap_or("")),
            csv_cell(&f.location.display_path()),
        ));
    }
    s
}

fn csv_cell(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn json_str(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}
