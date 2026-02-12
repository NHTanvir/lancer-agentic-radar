//! Error type for the dynamic-probe runtime.

use thiserror::Error;

/// Errors raised while running dynamic probes against a live agent endpoint or
/// an MCP server.
///
/// We deliberately carry `String` payloads (rather than `#[from]` wrapping
/// `reqwest::Error` / `serde_json::Error`) so the public surface stays stable
/// regardless of the HTTP/serde crate versions, and so callers in the binary
/// can render a single human message. Wrap fallible IO with
/// `.map_err(|e| RuntimeError::Http(e.to_string()))` (or the variant that fits).
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// An HTTP request (agent endpoint or SSE MCP transport) failed.
    #[error("http error: {0}")]
    Http(String),
    /// An MCP transport / JSON-RPC interaction failed.
    #[error("mcp error: {0}")]
    Mcp(String),
    /// A requested capability is not available in this build (e.g. the
    /// WebSocket MCP transport, which needs the optional `ws` feature).
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Any other runtime failure.
    #[error("{0}")]
    Other(String),
}

impl RuntimeError {
    /// Convenience constructor for [`RuntimeError::Other`].
    pub fn other(msg: impl Into<String>) -> Self {
        RuntimeError::Other(msg.into())
    }
}
