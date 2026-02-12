//! `--self-test` / `self-test` — runs the upstream-parity matrix against a
//! bundled reference target and prints pass/fail per upstream feature group.
//!
//! Returns exit code 0 if every group passes, 1 otherwise.

use ar_core::{
    AgentGraph, AgentNode, Config, DetectorCategory, Edge, EdgeKind, Framework, ParseOptions,
    Report, ReportFormat, ScanMeta, Severity, ToolNode,
};

struct Group {
    name: String,
    pass: bool,
    detail: String,
}

pub fn run() -> anyhow::Result<i32> {
    let mut groups: Vec<Group> = Vec::new();

    // --- Framework parser coverage -----------------------------------------
    for f in Framework::ALL {
        let sample = sample_source(f);
        let opts = ParseOptions {
            framework: Some(f),
            ..ParseOptions::default()
        };
        let path = std::path::Path::new(sample_filename(f));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ar_parsers::parse_source(f, &sample, path, &opts)
        }));
        let (pass, detail) = match result {
            Ok(g) => (
                true,
                format!(
                    "{} agent(s), {} tool(s)",
                    g.agents.len(),
                    g.tools.len()
                ),
            ),
            Err(_) => (false, "parser panicked".to_string()),
        };
        groups.push(Group {
            name: format!("parser:{}", f.id()),
            pass,
            detail,
        });
    }

    // --- Detector registry coverage ----------------------------------------
    let reg = ar_detectors::registry();
    let mut covered: std::collections::BTreeSet<DetectorCategory> = Default::default();
    for d in &reg {
        covered.insert(d.category);
    }
    // Every catalog category except the pure post-process meta + resolution
    // should have at least one sub-check.
    let mut missing = Vec::new();
    for c in DetectorCategory::ALL {
        if matches!(c, DetectorCategory::Resolution) {
            continue;
        }
        if !covered.contains(&c) {
            missing.push(c.id());
        }
    }
    groups.push(Group {
        name: "detectors:catalog".into(),
        pass: missing.is_empty() && reg.len() >= 40,
        detail: if missing.is_empty() {
            format!("{} sub-checks across {} categories", reg.len(), covered.len())
        } else {
            format!("missing categories: {}", missing.join(", "))
        },
    });

    // --- Detector firing on a known-bad graph ------------------------------
    let bad = build_vulnerable_graph();
    let findings = ar_detectors::run_all(&bad, &Config::default());
    groups.push(Group {
        name: "detectors:fire".into(),
        pass: !findings.is_empty(),
        detail: format!("{} finding(s) on the reference vulnerable graph", findings.len()),
    });

    // --- Report format coverage --------------------------------------------
    let report = Report::new(
        ScanMeta {
            tool_version: env!("CARGO_PKG_VERSION").into(),
            timestamp: Some(crate::pipeline::now_rfc3339()),
            ..Default::default()
        },
        bad.clone(),
        findings.clone(),
    );
    for fmt in ReportFormat::ALL {
        let out = ar_report::render(&report, fmt);
        let marker = match fmt {
            ReportFormat::Json => "\"findings\"",
            ReportFormat::Sarif => "2.1.0",
            ReportFormat::Markdown => "#",
            ReportFormat::Html => "<html",
        };
        groups.push(Group {
            name: format!("report:{}", fmt.id()),
            pass: !out.is_empty() && out.contains(marker),
            detail: format!("{} bytes", out.len()),
        });
    }

    // --- Graph emitters ----------------------------------------------------
    let mermaid = ar_report::mermaid(&bad);
    let dot = ar_report::dot(&bad);
    groups.push(Group {
        name: "graph:mermaid+dot".into(),
        pass: mermaid.contains("flowchart") && dot.contains("digraph"),
        detail: format!("mermaid {} B / dot {} B", mermaid.len(), dot.len()),
    });

    // --- Print matrix ------------------------------------------------------
    let mut failed = 0usize;
    println!("lancer-agentic-radar self-test (upstream parity matrix)\n");
    for g in &groups {
        let tag = if g.pass { "PASS" } else { "FAIL" };
        if !g.pass {
            failed += 1;
        }
        println!("  [{tag}] {:<28} {}", g.name, g.detail);
    }
    println!(
        "\n{} group(s): {} passed, {} failed",
        groups.len(),
        groups.len() - failed,
        failed
    );

    Ok(if failed == 0 { 0 } else { 1 })
}

fn sample_filename(f: Framework) -> &'static str {
    match f {
        Framework::VercelAI => "agent.ts",
        Framework::SemanticKernel => "Plugin.cs",
        Framework::OpenAIAssistants | Framework::AnthropicComputerUse => "assistant.json",
        Framework::Mcp => "mcp.json",
        Framework::N8n => "workflow.json",
        _ => "agent.py",
    }
}

/// Minimal per-framework source snippets so the parity matrix runs without any
/// on-disk fixtures.
fn sample_source(f: Framework) -> String {
    match f {
        Framework::LangChain => r#"
from langchain.agents import initialize_agent, Tool
def run_shell(cmd): import subprocess; return subprocess.run(cmd, shell=True)
tools = [Tool(name="shell", func=run_shell, description="runs a shell command")]
agent = initialize_agent(tools, llm, system_message="You are a helpful assistant.")
"#
        .into(),
        Framework::LangGraph => r#"
from langgraph.graph import StateGraph
g = StateGraph(dict)
g.add_node("planner", planner)
g.add_node("exec", exec_node)
g.add_edge("planner", "exec")
g.add_conditional_edges("exec", route, {"loop": "planner", "end": END})
"#
        .into(),
        Framework::CrewAI => r#"
from crewai import Agent, Task, Crew
researcher = Agent(role="Researcher", goal="research", backstory="b", tools=[search_tool])
writer = Agent(role="Writer", goal="write", tools=[email_tool])
crew = Crew(agents=[researcher, writer])
"#
        .into(),
        Framework::AutoGen => r#"
from autogen import AssistantAgent, UserProxyAgent
assistant = AssistantAgent("assistant", system_message="You are helpful.")
user = UserProxyAgent("user", code_execution_config={"work_dir": "x"})
"#
        .into(),
        Framework::SemanticKernel => r#"
public class MathPlugin {
  [KernelFunction] public string Add(int a, int b) => (a+b).ToString();
}
"#
        .into(),
        Framework::VercelAI => r#"
import { generateText } from 'ai';
const result = await generateText({ model, tools: { getWeather: weatherTool, runShell: shellTool } });
"#
        .into(),
        Framework::PydanticAI => r#"
from pydantic_ai import Agent
agent = Agent('openai:gpt-4o', system_prompt='You are a support agent.')
@agent.tool
def lookup(ctx, q: str) -> str: return db.query(q)
"#
        .into(),
        Framework::OpenAIAssistants => r#"
{ "name": "assistant", "model": "gpt-4o",
  "instructions": "You are helpful.",
  "tools": [ {"type": "function"}, {"type": "code_interpreter"}, {"type": "file_search"} ] }
"#
        .into(),
        Framework::OpenAIAgentsSdk => r#"
from agents import Agent, Runner, function_tool, WebSearchTool, handoff
@function_tool
def get_user(id: str) -> str: return db.get(id)
support = Agent(name="support", instructions="Help users.", tools=[get_user, WebSearchTool()])
triage = Agent(name="triage", instructions="Route.", handoffs=[handoff(support)])
"#
        .into(),
        Framework::AnthropicComputerUse => r#"
{ "tools": [ {"type": "computer_20250124", "name": "computer"},
             {"type": "bash_20250124", "name": "bash"} ] }
"#
        .into(),
        Framework::Mcp => r#"
{ "mcpServers": { "files": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"] } } }
"#
        .into(),
        Framework::N8n => r#"
{ "nodes": [
   {"name":"Chat","type":"@n8n/n8n-nodes-langchain.chatTrigger"},
   {"name":"AI Agent","type":"@n8n/n8n-nodes-langchain.agent"},
   {"name":"HTTP","type":"n8n-nodes-base.httpRequest"} ],
  "connections": { "Chat": {"main":[[{"node":"AI Agent"}]]}, "AI Agent": {"main":[[{"node":"HTTP"}]]} } }
"#
        .into(),
    }
}

/// A deliberately-vulnerable graph used to confirm detectors fire and reports
/// render — the bundled "reference target" for the parity matrix.
fn build_vulnerable_graph() -> AgentGraph {
    let mut g = AgentGraph::new();
    let mut agent = AgentNode::new("agent:researcher", "Researcher", Framework::CrewAI);
    agent.accepts_user_input = true;
    agent.set_system_prompt("You are a researcher. {user_input}");
    let aid = g.add_agent(agent);

    let mut shell = ToolNode::new("tool:shell", "run_shell");
    shell.effects.shell_exec = true;
    shell.effects_resolved = true;
    shell.description = Some("Runs an arbitrary shell command".into());
    let tid = g.add_tool(shell);

    let mut fetch = ToolNode::new("tool:fetch", "fetch_url");
    fetch.effects.net_egress = true;
    fetch.effects_resolved = true;
    let fid = g.add_tool(fetch);

    g.add_edge(Edge::new(aid.clone(), tid, EdgeKind::Calls));
    g.add_edge(Edge::new(aid, fid, EdgeKind::Calls));
    g.propagate_trust();
    g
}

// Keep Severity referenced so the import is used even if the matrix changes.
#[allow(dead_code)]
fn _severity_anchor() -> Severity {
    Severity::Critical
}
