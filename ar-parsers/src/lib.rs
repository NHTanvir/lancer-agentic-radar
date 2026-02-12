//! # ar-parsers
//!
//! Framework parsers for **lancer-agentic-radar**. Each sub-module recognizes
//! one agent framework's source/config and reconstructs the uniform
//! [`ar_core::AgentGraph`] (agents, tools, memory, RAG, edges) that the
//! detector layer reasons about.
//!
//! The parsers are deliberately regex / serde / string-heuristic based rather
//! than full AST/tree-sitter walkers: this keeps them robust against the
//! constant API churn of the agent frameworks, dependency-light, and fast.
//! Analysis is best-effort and conservative — constructs that can't be
//! statically resolved are recorded as [`ar_core::NodeKind::Unknown`] nodes so
//! the detector layer can surface an "audit needed" finding rather than
//! silently dropping them.
//!
//! ## Entry points
//! * [`scan_path`] — walk a file/dir, auto-detect framework(s), build & merge
//!   one graph.
//! * [`detect_frameworks`] — report which frameworks appear under a path.
//! * [`parse_source`] — parse a single source string for a known framework.

pub mod common; // shared helpers
pub mod detect; // framework auto-detection
pub mod langchain;
pub mod langgraph;
pub mod crewai;
pub mod autogen;
pub mod semantic_kernel;
pub mod vercel_ai;
pub mod pydantic_ai;
pub mod openai_assistants;
pub mod anthropic_cu;
pub mod mcp;
pub mod openai_agents_sdk;
pub mod n8n;
pub mod error;

pub use error::ParseError;

use ar_core::{AgentGraph, Framework, ParseOptions};
use std::path::Path;

/// Walk a file or directory, auto-detect framework(s), build & MERGE one
/// [`AgentGraph`].
///
/// Recurses directories with `walkdir`, skipping `target` / `.git` /
/// `node_modules` / `dist` / `build` (and a few other vendor dirs). RAG sources
/// are trust-classified via `opts.trust`. Unresolved constructs become
/// `Unknown` nodes. The merged graph is de-duplicated via
/// [`AgentGraph::dedup`]. Trust propagation is intentionally NOT run here — the
/// binary owns that pass.
pub fn scan_path(input: &Path, opts: &ParseOptions) -> Result<AgentGraph, ParseError> {
    detect::scan_path(input, opts)
}

/// Detect which frameworks appear under `input` (extension + structural
/// fingerprints).
pub fn detect_frameworks(input: &Path) -> Vec<Framework> {
    detect::detect_frameworks(input)
}

/// Parse a single source string for a specific framework into a partial graph.
pub fn parse_source(
    framework: Framework,
    content: &str,
    path: &Path,
    opts: &ParseOptions,
) -> AgentGraph {
    detect::parse_for(framework, content, path, opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_source_dispatches() {
        let g = parse_source(
            Framework::LangChain,
            "from langchain.agents import initialize_agent\nagent = initialize_agent(tools, llm)",
            Path::new("a.py"),
            &ParseOptions::default(),
        );
        assert!(!g.agents.is_empty());
    }

    #[test]
    fn detect_frameworks_on_missing_path_is_empty() {
        let fws = detect_frameworks(Path::new("does-not-exist-xyz"));
        assert!(fws.is_empty());
    }
}
