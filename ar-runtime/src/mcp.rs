//! MCP (Model Context Protocol) transport probes.
//!
//! MCP servers advertise their tools at runtime via a JSON-RPC `tools/list`
//! call. Static parsing can only read declared `mcp.json` manifests; to capture
//! *runtime* advertisements (and scan their descriptions for tool-poisoning
//! payloads) we must actually connect to the server.
//!
//! The plan (§"Engineering hard parts" #11) calls for a `McpTransport`
//! abstraction spanning the three MCP transports:
//!
//! * **stdio** — spawn the server subprocess, write a JSON-RPC request to its
//!   stdin, read the framed reply from stdout. Fully implemented here via
//!   [`tokio::process`].
//! * **SSE** — issue an HTTP GET and best-effort-parse the response body as the
//!   JSON-RPC result (an approximation of a long-lived SSE stream sufficient for
//!   one-shot tool enumeration).
//! * **WebSocket** — returns [`RuntimeError::Unsupported`]. This is the plan's
//!   explicitly allowed `[N/A]` divergence: no WebSocket client crate is in this
//!   crate's frozen dependency set, so the transport is stubbed behind a clear
//!   error rather than pulling in an out-of-budget dependency.
//!
//! The free function [`list_tools`] dispatches on the [`McpTransport`] enum from
//! `ar-core` and is what [`crate::list_mcp_tools`] re-exports.

use crate::error::RuntimeError;
use ar_core::McpTransport;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;

/// Conceptual transport abstraction. Implementors connect to an MCP server and
/// return its advertised `(tool_name, description)` pairs.
///
/// In practice the three concrete transports differ enough (subprocess vs.
/// HTTP) that the runtime dispatches via [`list_tools`] on the `ar-core`
/// [`McpTransport`] enum; this trait documents the shared contract and is
/// implemented for unit-style reuse.
#[allow(async_fn_in_trait)]
pub trait McpTransportProbe {
    /// Enumerate advertised tools as `(name, description)` pairs.
    async fn list_tools(&self) -> Result<Vec<(String, String)>, RuntimeError>;
}

/// How long (seconds) to wait for an MCP server to answer a `tools/list`.
const MCP_TIMEOUT_SECS: u64 = 20;

/// The JSON-RPC request we send to enumerate tools.
fn tools_list_request() -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    })
    .to_string()
}

/// Dispatch tool enumeration on the configured [`McpTransport`].
pub async fn list_tools(transport: &McpTransport) -> Result<Vec<(String, String)>, RuntimeError> {
    match transport {
        McpTransport::Stdio(cmd) => list_tools_stdio(cmd).await,
        McpTransport::Sse(url) => list_tools_sse(url).await,
        McpTransport::WebSocket(_) => Err(RuntimeError::Unsupported(
            "websocket transport requires the optional ws feature".to_string(),
        )),
    }
}

/// stdio transport: spawn the server, pipe a JSON-RPC `tools/list` over stdin,
/// and read the first JSON-RPC reply line from stdout.
///
/// `command` is a shell-style command line; the first whitespace-delimited
/// token is the executable and the rest are arguments. (Quoting is not
/// honored — supply pre-split paths/args without spaces, matching the simple
/// `stdio:///path/to/server` form in the plan's Workflow C.)
pub async fn list_tools_stdio(command: &str) -> Result<Vec<(String, String)>, RuntimeError> {
    let mut parts = command.split_whitespace();
    let program = parts
        .next()
        .ok_or_else(|| RuntimeError::Mcp("empty stdio command".to_string()))?;
    let args: Vec<&str> = parts.collect();

    let mut child = tokio::process::Command::new(program)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| RuntimeError::Mcp(format!("failed to spawn MCP server '{program}': {e}")))?;

    // Write the request (newline-delimited JSON-RPC, the common stdio framing).
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| RuntimeError::Mcp("could not open MCP server stdin".to_string()))?;
        let mut line = tools_list_request();
        line.push('\n');
        stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| RuntimeError::Mcp(format!("write to MCP stdin failed: {e}")))?;
        stdin
            .flush()
            .await
            .map_err(|e| RuntimeError::Mcp(format!("flush MCP stdin failed: {e}")))?;
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| RuntimeError::Mcp("could not open MCP server stdout".to_string()))?;
    let mut reader = BufReader::new(stdout);

    // Read newline-delimited frames until we find one whose JSON carries a
    // `result.tools` array (servers may emit notifications/log lines first).
    let read_fut = async {
        let mut found: Option<Vec<(String, String)>> = None;
        let mut buf = String::new();
        loop {
            buf.clear();
            let n = reader
                .read_line(&mut buf)
                .await
                .map_err(|e| RuntimeError::Mcp(format!("read from MCP stdout failed: {e}")))?;
            if n == 0 {
                break; // EOF
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(buf.trim()) {
                if let Some(tools) = parse_tools_value(&v) {
                    found = Some(tools);
                    break;
                }
            }
        }
        Ok::<_, RuntimeError>(found)
    };

    let result = timeout(Duration::from_secs(MCP_TIMEOUT_SECS), read_fut).await;

    // Best-effort cleanup of the subprocess regardless of outcome.
    let _ = child.start_kill();

    match result {
        Ok(Ok(Some(tools))) => Ok(tools),
        Ok(Ok(None)) => Err(RuntimeError::Mcp(
            "MCP server produced no tools/list result before EOF".to_string(),
        )),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(RuntimeError::Mcp(format!(
            "MCP server did not respond within {MCP_TIMEOUT_SECS}s"
        ))),
    }
}

/// SSE / HTTP transport: GET the endpoint and best-effort-parse the body as a
/// JSON-RPC `tools/list` result. Real SSE streams prefix each datum with
/// `data: `; we strip those prefixes and try to parse the remaining JSON.
pub async fn list_tools_sse(url: &str) -> Result<Vec<(String, String)>, RuntimeError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(MCP_TIMEOUT_SECS))
        .user_agent(concat!("lancer-agentic-radar/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| RuntimeError::Http(e.to_string()))?;

    let body = client
        .get(url)
        .header("Accept", "text/event-stream, application/json")
        .send()
        .await
        .map_err(|e| RuntimeError::Http(e.to_string()))?
        .text()
        .await
        .map_err(|e| RuntimeError::Http(e.to_string()))?;

    parse_sse_body(&body)
        .ok_or_else(|| RuntimeError::Mcp("no tools/list result found in SSE response".to_string()))
}

/// Parse an SSE/JSON body, returning the advertised tools if present.
///
/// Handles three shapes: (a) a single JSON document, (b) SSE `data:` lines each
/// carrying a JSON datum, (c) newline-delimited JSON. Public for testability.
pub fn parse_sse_body(body: &str) -> Option<Vec<(String, String)>> {
    // (a) Whole body is JSON.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body.trim()) {
        if let Some(t) = parse_tools_value(&v) {
            return Some(t);
        }
    }
    // (b)/(c) Line-oriented: strip optional `data:` prefix, parse each line.
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let json_part = line.strip_prefix("data:").map(str::trim).unwrap_or(line);
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_part) {
            if let Some(t) = parse_tools_value(&v) {
                return Some(t);
            }
        }
    }
    None
}

/// Extract `(name, description)` pairs from a JSON-RPC `tools/list` value.
///
/// Accepts both the spec shape `{"result":{"tools":[...]}}` and a bare
/// `{"tools":[...]}`. Returns `None` if no `tools` array is present (so callers
/// can keep scanning further frames).
pub fn parse_tools_value(v: &serde_json::Value) -> Option<Vec<(String, String)>> {
    let tools = v
        .get("result")
        .and_then(|r| r.get("tools"))
        .or_else(|| v.get("tools"))?
        .as_array()?;

    let mut out = Vec::with_capacity(tools.len());
    for t in tools {
        let name = t
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let description = t
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        out.push((name, description));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spec_shape_result_tools() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[
                {"name":"search","description":"web search"},
                {"name":"exec","description":"run a shell command"}
            ]}}"#,
        )
        .unwrap();
        let tools = parse_tools_value(&v).unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].0, "search");
        assert_eq!(tools[1].1, "run a shell command");
    }

    #[test]
    fn parses_bare_tools_shape() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"tools":[{"name":"t","description":"d"}]}"#).unwrap();
        let tools = parse_tools_value(&v).unwrap();
        assert_eq!(tools, vec![("t".to_string(), "d".to_string())]);
    }

    #[test]
    fn returns_none_without_tools_array() {
        let v: serde_json::Value = serde_json::from_str(r#"{"jsonrpc":"2.0","id":1}"#).unwrap();
        assert!(parse_tools_value(&v).is_none());
    }

    #[test]
    fn parses_sse_data_lines() {
        let body = "event: message\ndata: {\"result\":{\"tools\":[{\"name\":\"x\",\"description\":\"y\"}]}}\n\n";
        let tools = parse_sse_body(body).unwrap();
        assert_eq!(tools, vec![("x".to_string(), "y".to_string())]);
    }

    #[tokio::test]
    async fn websocket_is_unsupported() {
        let t = McpTransport::WebSocket("ws://example/mcp".to_string());
        let err = list_tools(&t).await.unwrap_err();
        match err {
            RuntimeError::Unsupported(m) => assert!(m.contains("websocket")),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
