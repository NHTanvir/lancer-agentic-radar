//! Error type for the parser crate.

use thiserror::Error;

/// Errors that can arise while scanning / parsing agent definitions.
///
/// Foreign serde errors are mapped into the string-carrying variants via
/// `.map_err(...)` at call sites so this enum stays dependency-light and easy
/// to construct.
#[derive(Debug, Error)]
pub enum ParseError {
    /// Filesystem I/O failure while walking or reading a file.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// A YAML document failed to parse / had an unexpected shape.
    #[error("yaml error: {0}")]
    Yaml(String),
    /// A JSON document failed to parse / had an unexpected shape.
    #[error("json error: {0}")]
    Json(String),
    /// The requested framework / construct is not supported.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Any other parser-level failure.
    #[error("{0}")]
    Other(String),
}

impl ParseError {
    /// Build an [`ParseError::Other`] from anything string-like.
    pub fn other(msg: impl Into<String>) -> Self {
        ParseError::Other(msg.into())
    }
    /// Build an [`ParseError::Unsupported`].
    pub fn unsupported(msg: impl Into<String>) -> Self {
        ParseError::Unsupported(msg.into())
    }
}
