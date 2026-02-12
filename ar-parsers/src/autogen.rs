//! Microsoft AutoGen (Python) parser, including `autogen-agentchat`.
//!
//! Recognizes `ConversableAgent`, `UserProxyAgent`, `AssistantAgent`
//! constructors and `register_tool` / `register_function` tool registrations.
//! Inter-agent handoffs (`handoffs=[...]`, `register_nested_chats`) become
//! `Handoff` edges.

use crate::common::{call_args, extract_model, extract_system_prompt, infer_effects, locate, mint_id, slug, unquote};
use ar_core::{
    AgentGraph, AgentNode, Edge, EdgeKind, Framework, ParseOptions, ToolNode, ToolSource,
};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

const FW: Framework = Framework::AutoGen;

/// Detect AutoGen Python source.
pub fn detect(path: &Path, content: &str) -> bool {
    if !matches!(path.extension().and_then(|e| e.to_str()), Some("py") | Some("pyi")) {
        return false;
    }
    Regex::new(
        r"(?i)\bautogen\b|autogen_agentchat|ConversableAgent|UserProxyAgent|AssistantAgent|register_function|register_tool",
    )
    .unwrap()
    .is_match(content)
}

/// Parse AutoGen source into a partial [`AgentGraph`].
pub fn parse(content: &str, path: &Path, _opts: &ParseOptions) -> AgentGraph {
    let mut g = AgentGraph::new();
    // var name -> agent id, so register_function(caller=agent) resolves.
    let mut agent_by_var: HashMap<String, String> = HashMap::new();
    let mut tool_ids: HashMap<String, String> = HashMap::new();
    // (from agent id, handoff target token) collected for post-loop resolution.
    let mut pending_handoffs: Vec<(String, String)> = Vec::new();

    // Agent constructors: `var = AssistantAgent(name="x", ...)`.
    let ctor = Regex::new(
        r#"(?m)([A-Za-z_]\w*)\s*=\s*(ConversableAgent|UserProxyAgent|AssistantAgent|MultimodalConversableAgent|RetrieveUserProxyAgent)\s*\("#,
    )
    .unwrap();
    for c in ctor.captures_iter(content) {
        let var = c.get(1).unwrap().as_str();
        let kind = c.get(2).unwrap().as_str();
        let args = call_args(&content[c.get(2).unwrap().start()..], kind).unwrap_or_default();
        let name = crate::common::kwarg_string(&args, "name")
            .map(|s| unquote(&s))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| var.to_string());
        let id = mint_id("agent", path, &slug(&name));
        let mut a = AgentNode::new(id.clone(), name, FW);
        if let Some(sp) = extract_system_prompt(&args) {
            a.set_system_prompt(sp);
        }
        a.model = extract_model(&args).or_else(|| extract_model(content));
        a.accepts_user_input = kind.contains("UserProxy") || kind.contains("RetrieveUser");
        a.location = locate(path, content, c.get(0).unwrap().as_str());
        agent_by_var.insert(var.to_string(), id.clone());
        g.add_agent(a);

        // handoffs=[agentB, agentC] — resolved after all agents are seen.
        if let Some(list) = bracket_after(&args, "handoffs") {
            for h in crate::common::ident_list(&list) {
                pending_handoffs.push((id.clone(), unquote(&h)));
            }
        }
    }

    // register_function / register_tool(name=..., caller=agentVar, executor=...)
    let reg = Regex::new(r"(?i)\b(register_function|register_tool|register_for_llm|register_for_execution)\s*\(").unwrap();
    for m in reg.find_iter(content) {
        let args = crate::common::balanced(content, m.end() - 1, '(', ')').unwrap_or_default();
        let tname = crate::common::kwarg_string(&args, "name")
            .map(|s| unquote(&s))
            .or_else(|| first_ident(&args))
            .unwrap_or_else(|| "tool".to_string());
        let tid = tool_ids
            .entry(tname.clone())
            .or_insert_with(|| {
                let tid = mint_id("tool", path, &tname);
                let mut t = ToolNode::new(tid.clone(), tname.clone());
                t.source = ToolSource::Native;
                let (e, r) = infer_effects(content);
                t.effects = e;
                t.effects_resolved = r;
                if let Some(d) = crate::common::kwarg_string(&args, "description") {
                    t.description = Some(d);
                }
                t.location = locate(path, content, m.as_str());
                g.add_tool(t);
                tid
            })
            .clone();
        // caller=agentVar → Calls edge
        if let Some(caller) = kwarg_ident(&args, "caller").or_else(|| kwarg_ident(&args, "agent")) {
            if let Some(aid) = agent_by_var.get(&caller) {
                g.add_edge(Edge::new(aid.clone(), tid.clone(), EdgeKind::Calls));
            }
        } else {
            // attach to all agents conservatively
            for aid in agent_by_var.values() {
                g.add_edge(Edge::new(aid.clone(), tid.clone(), EdgeKind::Calls));
            }
        }
    }

    // Resolve pending handoff targets: prefer a declared agent var, else mint
    // an Unknown audit node for the unresolved target.
    for (from_id, target) in pending_handoffs {
        if let Some(to_id) = agent_by_var.get(&target) {
            g.add_edge(Edge::new(from_id, to_id.clone(), EdgeKind::Handoff));
        } else {
            let uid = mint_id("unknown", path, &slug(&target));
            if g.kind_of(&ar_core::NodeId::new(uid.clone())).is_none() {
                g.add_unknown(uid.clone(), format!("unresolved handoff target `{target}`"));
            }
            g.add_edge(Edge::new(from_id, uid, EdgeKind::Handoff));
        }
    }

    g
}

fn first_ident(args: &str) -> Option<String> {
    let re = Regex::new(r"^\s*([A-Za-z_]\w*)").unwrap();
    re.captures(args).map(|c| c.get(1).unwrap().as_str().to_string())
}

fn kwarg_ident(args: &str, key: &str) -> Option<String> {
    let re = Regex::new(&format!(r"(?i)\b{}\s*=\s*([A-Za-z_]\w*)", regex::escape(key))).unwrap();
    re.captures(args).map(|c| c.get(1).unwrap().as_str().to_string())
}

fn bracket_after(args: &str, key: &str) -> Option<String> {
    let re = Regex::new(&format!(r"(?i)\b{}\s*=\s*\[", regex::escape(key))).unwrap();
    let m = re.find(args)?;
    let rest = &args[m.end()..];
    rest.find(']').map(|e| rest[..e].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_agents_and_tools() {
        let src = r#"
from autogen import AssistantAgent, UserProxyAgent
assistant = AssistantAgent(name="assistant", system_message="You help.")
user = UserProxyAgent(name="user")
def run_shell(cmd: str):
    import subprocess
    subprocess.run(cmd, shell=True)
register_function(run_shell, caller=assistant, name="run_shell")
"#;
        let g = parse(src, Path::new("ag.py"), &ParseOptions::default());
        assert!(g.agents.iter().any(|a| a.name == "assistant" && a.system_prompt.is_some()));
        assert!(g.agents.iter().any(|a| a.accepts_user_input));
        assert!(g.tools.iter().any(|t| t.name == "run_shell"));
        assert!(g.edges.iter().any(|e| e.kind == EdgeKind::Calls));
    }
}
