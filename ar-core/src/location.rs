//! Source locations attached to nodes and findings.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Where in the scanned project a node / finding originates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SourceLocation {
    /// Path to the file, relative to the scan root where possible.
    pub file: PathBuf,
    /// 1-based line number, if known.
    pub line: Option<u32>,
    /// 1-based column, if known.
    pub column: Option<u32>,
    /// A short excerpt of the offending source, for evidence.
    pub snippet: Option<String>,
}

impl SourceLocation {
    pub fn new(file: impl Into<PathBuf>) -> Self {
        SourceLocation {
            file: file.into(),
            line: None,
            column: None,
            snippet: None,
        }
    }

    pub fn at_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }

    /// SARIF/editor-style `path:line:col` rendering.
    pub fn display_path(&self) -> String {
        let mut s = self.file.display().to_string();
        if let Some(l) = self.line {
            s.push(':');
            s.push_str(&l.to_string());
            if let Some(c) = self.column {
                s.push(':');
                s.push_str(&c.to_string());
            }
        }
        s
    }
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_path())
    }
}
