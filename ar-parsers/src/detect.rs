//! Framework auto-detection and the directory-walking scan driver.

use crate::error::ParseError;
use crate::{
    anthropic_cu, autogen, crewai, langchain, langgraph, mcp, n8n, openai_agents_sdk,
    openai_assistants, pydantic_ai, semantic_kernel, vercel_ai,
};
use ar_core::{AgentGraph, Framework, ParseOptions};
use std::collections::BTreeSet;
use std::path::Path;
use walkdir::WalkDir;

/// Directories that are never worth descending into during a scan.
const SKIP_DIRS: [&str; 8] = [
    "target",
    ".git",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
];

/// File extensions worth opening (everything else is skipped on the walk).
fn interesting_ext(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("py") | Some("pyi") | Some("ts") | Some("tsx") | Some("js") | Some("jsx")
            | Some("mjs") | Some("cs") | Some("json") | Some("yaml") | Some("yml")
            | Some("mcp")
    ) || path
        .file_name()
        .and_then(|f| f.to_str())
        .map(|f| f.ends_with(".mcp.json"))
        .unwrap_or(false)
}

/// Run every framework's `detect` against `(path, content)` and collect hits.
pub fn detect_in(path: &Path, content: &str) -> Vec<Framework> {
    let mut out = Vec::new();
    if langchain::detect(path, content) {
        out.push(Framework::LangChain);
    }
    if langgraph::detect(path, content) {
        out.push(Framework::LangGraph);
    }
    if crewai::detect(path, content) {
        out.push(Framework::CrewAI);
    }
    if autogen::detect(path, content) {
        out.push(Framework::AutoGen);
    }
    if semantic_kernel::detect(path, content) {
        out.push(Framework::SemanticKernel);
    }
    if vercel_ai::detect(path, content) {
        out.push(Framework::VercelAI);
    }
    if pydantic_ai::detect(path, content) {
        out.push(Framework::PydanticAI);
    }
    if openai_agents_sdk::detect(path, content) {
        out.push(Framework::OpenAIAgentsSdk);
    }
    if openai_assistants::detect(path, content) {
        out.push(Framework::OpenAIAssistants);
    }
    if anthropic_cu::detect(path, content) {
        out.push(Framework::AnthropicComputerUse);
    }
    if mcp::detect(path, content) {
        out.push(Framework::Mcp);
    }
    if n8n::detect(path, content) {
        out.push(Framework::N8n);
    }
    out
}

/// Parse a single file's content for a specific framework.
pub fn parse_for(
    fw: Framework,
    content: &str,
    path: &Path,
    opts: &ParseOptions,
) -> AgentGraph {
    match fw {
        Framework::LangChain => langchain::parse(content, path, opts),
        Framework::LangGraph => langgraph::parse(content, path, opts),
        Framework::CrewAI => crewai::parse(content, path, opts),
        Framework::AutoGen => autogen::parse(content, path, opts),
        Framework::SemanticKernel => semantic_kernel::parse(content, path, opts),
        Framework::VercelAI => vercel_ai::parse(content, path, opts),
        Framework::PydanticAI => pydantic_ai::parse(content, path, opts),
        Framework::OpenAIAgentsSdk => openai_agents_sdk::parse(content, path, opts),
        Framework::OpenAIAssistants => openai_assistants::parse(content, path, opts),
        Framework::AnthropicComputerUse => anthropic_cu::parse(content, path, opts),
        Framework::Mcp => mcp::parse(content, path, opts),
        Framework::N8n => n8n::parse(content, path, opts),
    }
}

/// Whether a directory entry should be skipped on the walk.
fn is_skipped(path: &Path) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|s| SKIP_DIRS.contains(&s))
            .unwrap_or(false)
    })
}

/// Detect frameworks present under `input` (a file or directory).
pub fn detect_frameworks(input: &Path) -> Vec<Framework> {
    let mut set: BTreeSet<usize> = BTreeSet::new(); // index into Framework::ALL
    let index_of = |fw: Framework| Framework::ALL.iter().position(|f| *f == fw).unwrap_or(0);

    let mut consider = |path: &Path| {
        if !interesting_ext(path) {
            return;
        }
        if let Ok(content) = std::fs::read_to_string(path) {
            for fw in detect_in(path, &content) {
                set.insert(index_of(fw));
            }
        }
    };

    if input.is_file() {
        consider(input);
    } else {
        for entry in WalkDir::new(input)
            .into_iter()
            .filter_entry(|e| !is_skipped(e.path()))
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                consider(entry.path());
            }
        }
    }

    set.into_iter().map(|i| Framework::ALL[i]).collect()
}

/// Walk a file or directory, detect framework(s), build & MERGE one
/// [`AgentGraph`]. Honors `opts.framework` (force) and `opts.mcp_only`.
pub fn scan_path(input: &Path, opts: &ParseOptions) -> Result<AgentGraph, ParseError> {
    let mut merged = AgentGraph::new();

    let handle = |path: &Path, merged: &mut AgentGraph| {
        if !interesting_ext(path) {
            return;
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return, // skip unreadable/binary files
        };

        // Decide which frameworks to run for this file.
        let frameworks: Vec<Framework> = if let Some(forced) = opts.framework {
            if opts.mcp_only && forced != Framework::Mcp {
                vec![]
            } else {
                vec![forced]
            }
        } else {
            let mut fws = detect_in(path, &content);
            if opts.mcp_only {
                fws.retain(|f| *f == Framework::Mcp);
            }
            fws
        };

        for fw in frameworks {
            let part = parse_for(fw, &content, path, opts);
            if !part.is_empty() || !part.unknowns.is_empty() {
                merged.merge(part);
            }
        }
    };

    if input.is_file() {
        handle(input, &mut merged);
    } else if input.is_dir() {
        for entry in WalkDir::new(input)
            .into_iter()
            .filter_entry(|e| !is_skipped(e.path()))
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                handle(entry.path(), &mut merged);
            }
        }
    } else {
        return Err(ParseError::other(format!(
            "input path does not exist: {}",
            input.display()
        )));
    }

    merged.dedup();
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_picks_langchain() {
        let p = Path::new("agent.py");
        let fws = detect_in(p, "from langchain.agents import initialize_agent");
        assert!(fws.contains(&Framework::LangChain));
    }

    #[test]
    fn detect_picks_mcp_by_filename() {
        let p = Path::new("mcp.json");
        let fws = detect_in(p, r#"{"mcpServers":{}}"#);
        assert!(fws.contains(&Framework::Mcp));
    }
}
