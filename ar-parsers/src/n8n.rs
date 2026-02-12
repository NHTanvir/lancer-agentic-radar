//! n8n workflow parser (JSON export).
//!
//! Parses the `nodes[]` array and the `connections` map of an n8n workflow
//! export. Recognizes:
//! * `@n8n/n8n-nodes-langchain.agent` → agent node
//! * tool sub-nodes (`*.toolHttpRequest`, `*.toolCode`, `*.toolWorkflow`, …) →
//!   tool nodes
//! * MCP client nodes → MCP-sourced tools
//! * chat / webhook trigger nodes → `Triggers` edge into the workflow
//! * vector-store nodes (Pinecone/Qdrant/Supabase/PGVector) → RAG sources
//! * memory nodes (`*.memory*`) → memory stores
//!
//! Edges are built from the `connections` object.

use crate::common::mint_id;
use ar_core::{
    AgentGraph, AgentNode, Edge, EdgeKind, Framework, MemoryStore, ParseOptions, RAGSource,
    SourceLocation, ToolEffects, ToolNode, ToolSource,
};
use serde_json::Value as Json;
use std::collections::HashMap;
use std::path::Path;

const FW: Framework = Framework::N8n;

/// Detect an n8n workflow JSON export.
pub fn detect(path: &Path, content: &str) -> bool {
    if path.extension().and_then(|e| e.to_str()) != Some("json") {
        return false;
    }
    let v: Json = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return false,
    };
    json_is_n8n(&v)
}

fn json_is_n8n(v: &Json) -> bool {
    let o = match v.as_object() {
        Some(o) => o,
        None => return false,
    };
    let has_nodes = o.get("nodes").and_then(|n| n.as_array()).is_some();
    let has_conns = o.contains_key("connections");
    if has_nodes && has_conns {
        return true;
    }
    // node-type fingerprint even without connections
    if let Some(nodes) = o.get("nodes").and_then(|n| n.as_array()) {
        return nodes.iter().any(|n| {
            n.get("type")
                .and_then(|t| t.as_str())
                .map(|t| t.contains("n8n-nodes"))
                .unwrap_or(false)
        });
    }
    false
}

/// Classify an n8n node type string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeClass {
    Agent,
    Tool,
    Mcp,
    Trigger,
    Rag,
    Memory,
    Other,
}

fn classify(ty: &str) -> NodeClass {
    let t = ty.to_ascii_lowercase();
    if t.ends_with(".agent") || t.contains("langchain.agent") || t.contains("openaiassistant") {
        NodeClass::Agent
    } else if t.contains("mcpclient") || t.contains("mcptool") || t.contains(".mcp") {
        NodeClass::Mcp
    } else if t.contains("vectorstore")
        || t.contains("pinecone")
        || t.contains("qdrant")
        || t.contains("supabase")
        || t.contains("pgvector")
        || t.contains("weaviate")
        || t.contains("documentdefault")
    {
        NodeClass::Rag
    } else if t.contains("memory") {
        NodeClass::Memory
    } else if t.contains("trigger") || t.contains("webhook") || t.contains("chattrigger") {
        NodeClass::Trigger
    } else if t.contains("tool") || t.contains(".code") || t.contains("httprequest") {
        NodeClass::Tool
    } else {
        NodeClass::Other
    }
}

/// Parse an n8n workflow into a partial [`AgentGraph`].
pub fn parse(content: &str, path: &Path, opts: &ParseOptions) -> AgentGraph {
    let mut g = AgentGraph::new();
    let v: Json = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return g,
    };
    let o = match v.as_object() {
        Some(o) => o,
        None => return g,
    };

    // node display-name -> (kind, node-id)
    let mut by_name: HashMap<String, (NodeClass, String)> = HashMap::new();

    if let Some(nodes) = o.get("nodes").and_then(|n| n.as_array()) {
        for node in nodes {
            let ty = node.get("type").and_then(|x| x.as_str()).unwrap_or("");
            let nm = node
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or(ty)
                .to_string();
            let class = classify(ty);
            let nid = match class {
                NodeClass::Agent => {
                    let id = mint_id("agent", path, &nm);
                    let mut a = AgentNode::new(id.clone(), nm.clone(), FW);
                    a.accepts_user_input = true;
                    if let Some(sp) = node_prompt(node) {
                        a.set_system_prompt(sp);
                    }
                    a.model = node_model(node);
                    a.location = SourceLocation::new(path);
                    g.add_agent(a);
                    id
                }
                NodeClass::Tool => {
                    let id = mint_id("tool", path, &nm);
                    let mut t = ToolNode::new(id.clone(), nm.clone());
                    t.source = ToolSource::Native;
                    t.effects = tool_effects_for(ty);
                    t.effects_resolved = t.effects.is_known();
                    t.location = SourceLocation::new(path);
                    g.add_tool(t);
                    id
                }
                NodeClass::Mcp => {
                    let id = mint_id("tool", path, &nm);
                    let mut t = ToolNode::new(id.clone(), nm.clone());
                    t.source = ToolSource::Mcp(nm.clone());
                    t.location = SourceLocation::new(path);
                    g.add_tool(t);
                    id
                }
                NodeClass::Rag => {
                    let id = mint_id("rag", path, &nm);
                    let kind = rag_kind_for(ty);
                    let mut r = RAGSource::new(id.clone(), nm.clone(), kind);
                    if let Some(src) = node_source(node) {
                        r.trust = opts.trust.classify(&src);
                        r.document_source = Some(src);
                    }
                    r.location = SourceLocation::new(path);
                    g.add_rag(r);
                    id
                }
                NodeClass::Memory => {
                    let id = mint_id("memory", path, &nm);
                    let mut m = MemoryStore::new(id.clone(), nm.clone(), mem_kind_for(ty));
                    m.cross_session = true;
                    m.location = SourceLocation::new(path);
                    g.add_memory(m);
                    id
                }
                NodeClass::Trigger => {
                    // Triggers are modelled as Unknown source nodes feeding the
                    // workflow (untrusted entry point).
                    let id = mint_id("unknown", path, &nm);
                    g.add_unknown(id.clone(), format!("trigger node `{nm}` ({ty})"));
                    id
                }
                NodeClass::Other => {
                    let id = mint_id("unknown", path, &nm);
                    g.add_unknown(id.clone(), format!("n8n node `{nm}` ({ty})"));
                    id
                }
            };
            by_name.insert(nm, (class, nid));
        }
    }

    // Build edges from the connections map.
    if let Some(conns) = o.get("connections").and_then(|c| c.as_object()) {
        for (from_name, outs) in conns {
            let Some((_fc, from_id)) = by_name.get(from_name) else {
                continue;
            };
            let from_id = from_id.clone();
            // outs is a map: { "main": [[{node, type, index}, ...]], "ai_tool": [...] }
            if let Some(out_obj) = outs.as_object() {
                for (conn_type, groups) in out_obj {
                    if let Some(groups) = groups.as_array() {
                        for group in groups {
                            if let Some(items) = group.as_array() {
                                for item in items {
                                    let to_name =
                                        item.get("node").and_then(|x| x.as_str()).unwrap_or("");
                                    if let Some((to_class, to_id)) = by_name.get(to_name) {
                                        let kind =
                                            edge_kind(conn_type, *to_class, from_name, &by_name);
                                        // n8n sub-node connections point sub→agent;
                                        // we normalize to agent→sub for Calls/Reads.
                                        let (a, b) = orient(kind, &from_id, to_id, *to_class);
                                        g.add_edge(Edge::new(a, b, kind));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    g
}

/// Decide the edge kind from the n8n connection-type string + the target class.
fn edge_kind(
    conn_type: &str,
    to_class: NodeClass,
    _from: &str,
    _by_name: &HashMap<String, (NodeClass, String)>,
) -> EdgeKind {
    let c = conn_type.to_ascii_lowercase();
    if c.contains("tool") {
        EdgeKind::Calls
    } else if c.contains("memory") || to_class == NodeClass::Memory {
        EdgeKind::Reads
    } else if c.contains("vectorstore") || c.contains("document") || to_class == NodeClass::Rag {
        EdgeKind::Reads
    } else {
        match to_class {
            NodeClass::Tool | NodeClass::Mcp => EdgeKind::Calls,
            NodeClass::Rag => EdgeKind::Reads,
            NodeClass::Memory => EdgeKind::Reads,
            NodeClass::Agent => EdgeKind::Triggers,
            _ => EdgeKind::Triggers,
        }
    }
}

/// In n8n, AI sub-nodes (tool/memory/rag) connect *into* the agent; flip the
/// direction so the graph reads agent→capability for Calls/Reads.
fn orient(kind: EdgeKind, from_id: &str, to_id: &str, to_class: NodeClass) -> (String, String) {
    let from_is_capability = matches!(
        classify_id(from_id),
        NodeClass::Tool | NodeClass::Mcp | NodeClass::Rag | NodeClass::Memory
    );
    match kind {
        EdgeKind::Calls | EdgeKind::Reads | EdgeKind::Writes => {
            if from_is_capability && to_class == NodeClass::Agent {
                (to_id.to_string(), from_id.to_string())
            } else {
                (from_id.to_string(), to_id.to_string())
            }
        }
        _ => (from_id.to_string(), to_id.to_string()),
    }
}

/// Recover a node class from its minted id prefix.
fn classify_id(id: &str) -> NodeClass {
    if id.starts_with("tool:") {
        NodeClass::Tool
    } else if id.starts_with("rag:") {
        NodeClass::Rag
    } else if id.starts_with("memory:") {
        NodeClass::Memory
    } else if id.starts_with("agent:") {
        NodeClass::Agent
    } else {
        NodeClass::Other
    }
}

fn tool_effects_for(ty: &str) -> ToolEffects {
    let t = ty.to_ascii_lowercase();
    let mut e = ToolEffects::default();
    if t.contains("httprequest") || t.contains("http") {
        e.net_egress = true;
    }
    if t.contains("code") {
        e.code_eval = true;
    }
    if t.contains("emailsend") || t.contains("gmail") || t.contains("smtp") {
        e.email = true;
    }
    if t.contains("postgres") || t.contains("mysql") || t.contains("mongodb") || t.contains("supabase") {
        e.db_write = true;
    }
    if t.contains("filesystem") || t.contains("writebinaryfile") {
        e.writes_fs = true;
    }
    if t.contains("stripe") || t.contains("paypal") {
        e.payment = true;
    }
    e
}

fn rag_kind_for(ty: &str) -> &'static str {
    let t = ty.to_ascii_lowercase();
    if t.contains("pinecone") {
        "Pinecone"
    } else if t.contains("qdrant") {
        "Qdrant"
    } else if t.contains("supabase") {
        "Supabase"
    } else if t.contains("pgvector") {
        "PGVector"
    } else if t.contains("weaviate") {
        "Weaviate"
    } else {
        "VectorStore"
    }
}

fn mem_kind_for(ty: &str) -> &'static str {
    let t = ty.to_ascii_lowercase();
    if t.contains("redis") {
        "RedisMemory"
    } else if t.contains("postgres") {
        "PostgresMemory"
    } else if t.contains("window") {
        "BufferWindowMemory"
    } else {
        "Memory"
    }
}

fn node_prompt(node: &Json) -> Option<String> {
    let params = node.get("parameters")?;
    for key in ["systemMessage", "system_prompt", "text", "prompt"] {
        if let Some(s) = params.get(key).and_then(|x| x.as_str()) {
            if !s.trim().is_empty() {
                return Some(s.to_string());
            }
        }
        // options.systemMessage
        if let Some(s) = params
            .get("options")
            .and_then(|o| o.get(key))
            .and_then(|x| x.as_str())
        {
            if !s.trim().is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn node_model(node: &Json) -> Option<String> {
    let params = node.get("parameters")?;
    params
        .get("model")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            params
                .get("model")
                .and_then(|m| m.get("value"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        })
}

fn node_source(node: &Json) -> Option<String> {
    let params = node.get("parameters")?;
    for key in ["indexName", "namespace", "tableName", "url", "collection"] {
        if let Some(s) = params.get(key).and_then(|x| x.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_workflow() {
        let src = r#"
{
  "nodes": [
    { "name": "When chat message received", "type": "@n8n/n8n-nodes-langchain.chatTrigger", "parameters": {} },
    { "name": "AI Agent", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": { "options": { "systemMessage": "You are helpful." } } },
    { "name": "HTTP Tool", "type": "@n8n/n8n-nodes-langchain.toolHttpRequest", "parameters": {} },
    { "name": "Pinecone", "type": "@n8n/n8n-nodes-langchain.vectorStorePinecone", "parameters": { "indexName": "https://public-index" } }
  ],
  "connections": {
    "When chat message received": { "main": [[{ "node": "AI Agent", "type": "main", "index": 0 }]] },
    "HTTP Tool": { "ai_tool": [[{ "node": "AI Agent", "type": "ai_tool", "index": 0 }]] },
    "Pinecone": { "ai_vectorStore": [[{ "node": "AI Agent", "type": "ai_vectorStore", "index": 0 }]] }
  }
}
"#;
        assert!(detect(Path::new("wf.json"), src));
        let g = parse(src, Path::new("wf.json"), &ParseOptions::default());
        assert!(g.agents.iter().any(|a| a.name == "AI Agent" && a.system_prompt.is_some()));
        assert!(g.tools.iter().any(|t| t.name == "HTTP Tool" && t.effects.net_egress));
        assert!(g.rag.iter().any(|r| r.kind == "Pinecone"));
        // agent → tool Calls edge after orientation flip
        assert!(g.edges.iter().any(|e| e.kind == EdgeKind::Calls));
        assert!(g.edges.iter().any(|e| e.kind == EdgeKind::Triggers));
    }
}
