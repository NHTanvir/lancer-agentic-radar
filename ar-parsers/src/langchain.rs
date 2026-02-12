//! LangChain (Python) parser.
//!
//! Recognizes `Tool(...)`, `@tool`-decorated functions, `initialize_agent`,
//! `create_react_agent`, `create_openai_functions_agent`, `AgentExecutor`, and
//! resolves the tool list passed to the agent constructor. Detects Chroma /
//! FAISS / Pinecone / Weaviate RAG retrievers and `ConversationBufferMemory` /
//! `RedisChatMessageHistory` memory stores.

use crate::common::{
    call_args, extract_model, extract_system_prompt, ident_list, infer_effects, locate, make_rag,
    mint_id, unquote,
};
use ar_core::{
    AgentGraph, AgentNode, Edge, EdgeKind, Framework, MemoryStore, ParseOptions, ToolNode,
    ToolSource,
};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

const FW: Framework = Framework::LangChain;

/// Structural fingerprint for LangChain Python source.
pub fn detect(path: &Path, content: &str) -> bool {
    if !is_python(path) {
        return false;
    }
    let re = Regex::new(
        r"(?i)from\s+langchain|import\s+langchain|initialize_agent|create_react_agent|create_openai_functions_agent|create_tool_calling_agent|AgentExecutor|langchain\.tools",
    )
    .unwrap();
    re.is_match(content) && !content.contains("StateGraph")
}

fn is_python(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("py") | Some("pyi")
    )
}

/// Parse LangChain source into a partial [`AgentGraph`].
pub fn parse(content: &str, path: &Path, opts: &ParseOptions) -> AgentGraph {
    let mut g = AgentGraph::new();
    let mut tool_ids: HashMap<String, String> = HashMap::new();

    parse_tools(content, path, &mut g, &mut tool_ids);
    parse_memory(content, path, &mut g);
    let rags = parse_rag(content, path, opts, &mut g);
    let agents = parse_agents(content, path, &mut g);

    // Wire agents to their tools, rag, memory.
    wire(content, &agents, &tool_ids, &rags, &mut g);

    g
}

/// Tool definitions: `@tool`-decorated funcs + `Tool(name=..., func=...)`.
fn parse_tools(
    content: &str,
    path: &Path,
    g: &mut AgentGraph,
    tool_ids: &mut HashMap<String, String>,
) {
    // @tool decorated functions
    let tool_dec =
        Regex::new(r#"(?m)^\s*@tool(?:\(([^)]*)\))?\s*\n\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"#)
            .unwrap();
    for c in tool_dec.captures_iter(content) {
        let deco_args = c.get(1).map(|m| m.as_str()).unwrap_or("");
        let fname = c.get(2).map(|m| m.as_str()).unwrap_or("tool");
        let sig = c.get(3).map(|m| m.as_str()).unwrap_or("");
        let body = function_body(content, c.get(0).unwrap().end());
        let combined = format!("{deco_args}\n{body}");
        let (effects, resolved) = infer_effects(&combined);
        let id = mint_id("tool", path, fname);
        let mut t = ToolNode::new(id.clone(), fname);
        t.source = ToolSource::Native;
        t.effects = effects;
        t.effects_resolved = resolved;
        t.signature = Some(sig.trim().to_string());
        t.has_input_schema = sig.contains(':'); // typed params ~ schema-ish
        t.location = locate(path, content, c.get(0).unwrap().as_str());
        // docstring as description
        if let Some(doc) = first_docstring(&body) {
            t.description = Some(doc);
        }
        tool_ids.insert(fname.to_string(), id.clone());
        g.add_tool(t);
    }

    // Tool(name="x", func=fn) or StructuredTool(...)
    let tool_ctor = Regex::new(r#"\b(?:Structured)?Tool(?:\.from_function)?\s*\("#).unwrap();
    for m in tool_ctor.find_iter(content) {
        // The match ends just past the opening `(`.
        let args = crate::common::balanced(content, m.end() - 1, '(', ')').unwrap_or_default();
        let name = unquote(
            &crate::common::kwarg_string(&args, "name").unwrap_or_else(|| "tool".to_string()),
        );
        let id = mint_id("tool", path, &name);
        let mut t = ToolNode::new(id.clone(), name.clone());
        t.source = ToolSource::Native;
        let (effects, resolved) = infer_effects(&args);
        t.effects = effects;
        t.effects_resolved = resolved;
        if let Some(d) = crate::common::kwarg_string(&args, "description") {
            t.description = Some(d);
        }
        t.location = locate(path, content, m.as_str());
        tool_ids.entry(name).or_insert_with(|| id.clone());
        g.add_tool(t);
    }
}

/// Memory stores.
fn parse_memory(content: &str, path: &Path, g: &mut AgentGraph) {
    for kind in [
        "ConversationBufferMemory",
        "ConversationBufferWindowMemory",
        "ConversationSummaryMemory",
        "RedisChatMessageHistory",
        "ChatMessageHistory",
    ] {
        if content.contains(kind) {
            let id = mint_id("memory", path, kind);
            let mut m = MemoryStore::new(id, kind, kind);
            m.cross_session = kind.contains("Redis");
            m.location = locate(path, content, kind);
            g.add_memory(m);
        }
    }
}

/// RAG / vector-store retrievers. Returns the minted rag ids.
fn parse_rag(content: &str, path: &Path, opts: &ParseOptions, g: &mut AgentGraph) -> Vec<String> {
    let mut ids = Vec::new();
    for kind in ["Chroma", "FAISS", "Pinecone", "Weaviate", "Qdrant", "Milvus"] {
        if content.contains(kind) {
            let r = make_rag(opts, path, content, kind, kind, kind);
            ids.push(r.id.as_str().to_string());
            g.add_rag(r);
        }
    }
    ids
}

/// Agents constructed via the various LangChain entry points.
fn parse_agents(content: &str, path: &Path, g: &mut AgentGraph) -> Vec<AgentInfo> {
    let mut agents = Vec::new();
    let ctor = Regex::new(
        r"\b(initialize_agent|create_react_agent|create_openai_functions_agent|create_tool_calling_agent|create_structured_chat_agent|AgentExecutor)\s*\(",
    )
    .unwrap();
    let mut seen = 0usize;
    for m in ctor.find_iter(content) {
        let ctor_name = m.as_str().trim_end_matches(|c| c == '(' || c == ' ').trim();
        let args = call_args(&content[m.start()..], ctor_name).unwrap_or_default();
        let name = format!("langchain_agent_{seen}");
        seen += 1;
        let id = mint_id("agent", path, &name);
        let mut a = AgentNode::new(id.clone(), name.clone(), FW);
        if let Some(sp) = extract_system_prompt(&args).or_else(|| extract_system_prompt(content)) {
            a.set_system_prompt(sp);
        }
        a.model = extract_model(&args).or_else(|| extract_model(content));
        a.accepts_user_input = true; // LangChain agents are user-facing by default
        a.location = locate(path, content, m.as_str());
        g.add_agent(a);
        agents.push(AgentInfo {
            id,
            tool_args: args,
        });
    }
    agents
}

struct AgentInfo {
    id: String,
    /// The agent constructor's full argument text (used to resolve tool lists).
    tool_args: String,
}

/// Wire agents to tools/rag/memory via edges.
fn wire(
    content: &str,
    agents: &[AgentInfo],
    tool_ids: &HashMap<String, String>,
    rags: &[String],
    g: &mut AgentGraph,
) {
    // Resolve any `tools = [...]` module-level list assignment for fallback.
    let module_tools = resolve_tools_var(content);

    for a in agents {
        // tools=[...] inside the agent constructor
        let mut names = extract_tools_arg(&a.tool_args);
        if names.is_empty() {
            names = module_tools.clone();
        }
        if names.is_empty() {
            // every known tool is a plausible callee (conservative)
            names = tool_ids.keys().cloned().collect();
        }
        for n in &names {
            if let Some(tid) = tool_ids.get(n) {
                g.add_edge(Edge::new(a.id.clone(), tid.clone(), EdgeKind::Calls));
            } else {
                // Unresolved tool reference → Unknown node + edge.
                let uid = mint_id("unknown", Path::new("?"), n);
                g.add_unknown(uid.clone(), format!("unresolved tool `{n}`"));
                g.add_edge(Edge::new(a.id.clone(), uid, EdgeKind::Calls));
            }
        }
        for rid in rags {
            g.add_edge(Edge::new(a.id.clone(), rid.clone(), EdgeKind::Reads));
        }
        for m in &g.memory.clone() {
            g.add_edge(Edge::new(a.id.clone(), m.id.clone(), EdgeKind::Reads));
        }
    }
}

/// Extract the `tools=[...]` argument from a constructor arg string.
fn extract_tools_arg(args: &str) -> Vec<String> {
    if let Some(inner) = bracket_after(args, "tools") {
        return ident_list(&inner);
    }
    // initialize_agent(tools, llm, ...) → positional first arg list
    if let Some(start) = args.find('[') {
        if start < 4 {
            if let Some(end) = args[start..].find(']') {
                return ident_list(&args[start + 1..start + end]);
            }
        }
    }
    Vec::new()
}

/// Resolve a module-level `tools = [...]` (plus `tools.append(x)`).
fn resolve_tools_var(content: &str) -> Vec<String> {
    let re = Regex::new(r"(?m)^\s*tools\s*=\s*\[([^\]]*)\]").unwrap();
    let mut out = Vec::new();
    if let Some(c) = re.captures(content) {
        out.extend(ident_list(c.get(1).map(|m| m.as_str()).unwrap_or("")));
    }
    let app = Regex::new(r"tools\.append\(\s*([A-Za-z_]\w*)").unwrap();
    for c in app.captures_iter(content) {
        if let Some(m) = c.get(1) {
            out.push(m.as_str().to_string());
        }
    }
    out
}

/// Find `key=[...]` and return the inner list text.
fn bracket_after(args: &str, key: &str) -> Option<String> {
    let re = Regex::new(&format!(r"(?i)\b{}\s*=\s*\[", regex::escape(key))).unwrap();
    let m = re.find(args)?;
    let open = m.end() - 1;
    let rest = &args[open + 1..];
    rest.find(']').map(|e| rest[..e].to_string())
}

/// Approximate a Python function body: from `start` to the next line that is
/// non-blank and indented at column 0 (dedent), capped to a window.
fn function_body(content: &str, start: usize) -> String {
    let tail = &content[start.min(content.len())..];
    let mut end = tail.len();
    let mut idx = 0usize;
    for line in tail.split_inclusive('\n').skip(1) {
        idx += line.len();
        let trimmed = line.trim_end_matches('\n');
        if !trimmed.trim().is_empty()
            && !trimmed.starts_with(' ')
            && !trimmed.starts_with('\t')
            && !trimmed.starts_with(')')
        {
            end = idx;
            break;
        }
        if idx > 2000 {
            end = idx;
            break;
        }
    }
    tail[..end.min(tail.len())].to_string()
}

/// First triple-quoted docstring in a body, if any.
fn first_docstring(body: &str) -> Option<String> {
    let re = Regex::new(r#"(?s)(?:"""(.*?)"""|'''(.*?)''')"#).unwrap();
    re.captures(body).and_then(|c| {
        c.get(1)
            .or_else(|| c.get(2))
            .map(|m| m.as_str().trim().to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_tool_and_agent() {
        let src = r#"
from langchain.agents import initialize_agent, Tool

@tool
def shell(cmd: str):
    """Run a shell command."""
    import subprocess
    subprocess.run(cmd, shell=True)

tools = [shell]
agent = initialize_agent(tools, llm, agent="zero-shot-react-description")
"#;
        let g = parse(src, Path::new("a.py"), &ParseOptions::default());
        assert!(!g.agents.is_empty());
        assert!(g.tools.iter().any(|t| t.name == "shell" && t.effects.shell_exec));
        assert!(g
            .edges
            .iter()
            .any(|e| e.kind == EdgeKind::Calls));
    }

    #[test]
    fn detects_langchain() {
        let src = "from langchain.agents import AgentExecutor";
        assert!(detect(Path::new("x.py"), src));
    }
}
