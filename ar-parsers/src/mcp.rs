//! MCP (Model Context Protocol) parser.
//!
//! Parses `mcp.json` / `.mcp` manifests and client config files: the `servers`
//! / `mcpServers` map and any advertised `tools`, `resources`, `prompts`. Each
//! advertised tool becomes a [`ToolNode`] with [`ToolSource::Mcp`] carrying the
//! server name; resources become RAG sources; prompts become memory stores.
//!
//! This module only *captures* tool description text — scanning it for
//! injection patterns is the detector layer's job.

use crate::common::{infer_effects, mint_id};
use ar_core::{
    AgentGraph, AgentNode, Edge, EdgeKind, Framework, MemoryStore, ParseOptions, RAGSource,
    SourceLocation, ToolNode, ToolSource,
};
use serde_json::Value as Json;
use std::path::Path;

const FW: Framework = Framework::Mcp;

/// Detect an MCP manifest / client config.
pub fn detect(path: &Path, content: &str) -> bool {
    let fname = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if fname == "mcp.json" || fname.ends_with(".mcp") || fname.ends_with(".mcp.json") {
        return true;
    }
    if path.extension().and_then(|e| e.to_str()) == Some("json") {
        if let Ok(v) = serde_json::from_str::<Json>(content) {
            return json_is_mcp(&v);
        }
    }
    false
}

fn json_is_mcp(v: &Json) -> bool {
    let o = match v.as_object() {
        Some(o) => o,
        None => return false,
    };
    o.contains_key("mcpServers")
        || o.contains_key("servers")
        || (o.contains_key("command") && (o.contains_key("args") || o.contains_key("transport")))
        || o.get("tools").and_then(|t| t.as_array()).is_some()
}

/// Parse an MCP config into a partial [`AgentGraph`].
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

    // A synthetic MCP "client" agent that calls the advertised tools.
    let aid = mint_id("agent", path, "mcp_client");
    let mut a = AgentNode::new(aid.clone(), "MCP Client", FW);
    a.accepts_user_input = true;
    a.location = SourceLocation::new(path);
    g.add_agent(a);

    // server maps: mcpServers / servers
    let mut handled = false;
    for key in ["mcpServers", "servers"] {
        if let Some(servers) = o.get(key).and_then(|x| x.as_object()) {
            handled = true;
            for (server_name, sv) in servers {
                parse_server(server_name, sv, path, content, &aid, opts, &mut g);
            }
        }
    }
    // top-level single-server form: { command, args, tools: [...] }
    if !handled {
        let server_name = o
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or("server")
            .to_string();
        parse_server(&server_name, &v, path, content, &aid, opts, &mut g);
    }

    g
}

fn parse_server(
    server_name: &str,
    sv: &Json,
    path: &Path,
    _content: &str,
    agent_id: &str,
    opts: &ParseOptions,
    g: &mut AgentGraph,
) {
    // Tools advertised by this server.
    if let Some(tools) = sv.get("tools").and_then(|t| t.as_array()) {
        for (i, tv) in tools.iter().enumerate() {
            let name = tv
                .get("name")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{server_name}_tool_{i}"));
            let tid = mint_id("tool", path, &format!("{server_name}_{name}"));
            let mut t = ToolNode::new(tid.clone(), name);
            t.source = ToolSource::Mcp(server_name.to_string());
            if let Some(d) = tv
                .get("description")
                .and_then(|x| x.as_str())
                .or_else(|| tv.get("title").and_then(|x| x.as_str()))
            {
                t.description = Some(d.to_string());
                let (e, r) = infer_effects(d);
                t.effects = e;
                t.effects_resolved = r;
            }
            t.has_input_schema = tv.get("inputSchema").is_some() || tv.get("input_schema").is_some();
            t.location = SourceLocation::new(path);
            g.add_tool(t);
            g.add_edge(Edge::new(agent_id.to_string(), tid, EdgeKind::Calls));
        }
    }

    // Resources → RAG sources.
    if let Some(res) = sv.get("resources").and_then(|t| t.as_array()) {
        for (i, rv) in res.iter().enumerate() {
            let uri = rv
                .get("uri")
                .and_then(|x| x.as_str())
                .or_else(|| rv.get("name").and_then(|x| x.as_str()))
                .unwrap_or("resource")
                .to_string();
            let rid = mint_id("rag", path, &format!("{server_name}_res_{i}"));
            let mut r = RAGSource::new(rid.clone(), uri.clone(), "mcp-resource");
            r.trust = opts.trust.classify(&uri);
            r.document_source = Some(uri);
            r.location = SourceLocation::new(path);
            g.add_rag(r);
            g.add_edge(Edge::new(agent_id.to_string(), rid, EdgeKind::Reads));
        }
    }

    // Prompts → memory stores (server-provided context).
    if let Some(prompts) = sv.get("prompts").and_then(|t| t.as_array()) {
        for (i, pv) in prompts.iter().enumerate() {
            let name = pv
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("prompt")
                .to_string();
            let mid = mint_id("memory", path, &format!("{server_name}_prompt_{i}"));
            let mut m = MemoryStore::new(mid, format!("{server_name}:{name}"), "mcp-prompt");
            m.location = SourceLocation::new(path);
            g.add_memory(m);
        }
    }

    // If the server advertised nothing, still record an Unknown placeholder so
    // the supply-chain risk is visible.
    let has_any = sv.get("tools").is_some()
        || sv.get("resources").is_some()
        || sv.get("prompts").is_some();
    if !has_any {
        let cmd = sv
            .get("command")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let uid = mint_id("unknown", path, &format!("{server_name}_runtime_tools"));
        g.add_unknown(
            uid.clone(),
            format!("MCP server `{server_name}` ({cmd}) advertises tools at runtime — dynamic probe needed"),
        );
        g.add_edge(Edge::new(agent_id.to_string(), uid, EdgeKind::Calls));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mcp_servers() {
        let src = r#"
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "tools": [
        { "name": "read_file", "description": "Read a file from disk", "inputSchema": {} },
        { "name": "write_file", "description": "Write content to a file" }
      ]
    }
  }
}
"#;
        assert!(detect(Path::new("mcp.json"), src));
        let g = parse(src, Path::new("mcp.json"), &ParseOptions::default());
        assert!(g.tools.iter().any(|t| t.name == "read_file"
            && matches!(&t.source, ToolSource::Mcp(s) if s == "filesystem")));
        assert!(g.tools.iter().any(|t| t.has_input_schema));
    }

    #[test]
    fn unknown_when_no_advertisements() {
        let src = r#"{"mcpServers":{"x":{"command":"node","args":["s.js"]}}}"#;
        let g = parse(src, Path::new("mcp.json"), &ParseOptions::default());
        assert!(!g.unknowns.is_empty());
    }
}
