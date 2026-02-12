//! Error type for the prompt-hardening engine.

use thiserror::Error;

/// Errors that can occur while hardening prompts.
///
/// The offline (rule-based) rewriter is infallible; these variants only arise
/// on the LLM-driven path ([`crate::harden_graph_llm`]). Even there, transport
/// failures are recovered from per-prompt by falling back to the offline
/// rewriter, so a returned `Err` is reserved for unrecoverable setup problems.
#[derive(Debug, Error)]
pub enum HardenError {
    /// An HTTP-level failure talking to the (OpenAI-compatible) chat API.
    #[error("hardening HTTP error: {0}")]
    Http(String),
    /// Any other hardening failure (serialization, malformed response, etc.).
    #[error("hardening error: {0}")]
    Other(String),
}
