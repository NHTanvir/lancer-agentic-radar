//! Exercises the public ar-core surface the way downstream crates do. This is
//! the contract every other crate in the workspace programs against.

use ar_core::{
    AgentGraph, AgentNode, Edge, EdgeKind, Finding, Framework, NodeId, Severity, ToolNode,
    TrustLabel,
};
use ar_core::finding::DetectorCategory;

#[test]
fn severity_orders_critical_highest() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Info < Severity::Low);
    assert_eq!("critical".parse::<Severity>().unwrap(), Severity::Critical);
}

#[test]
fn framework_round_trips() {
    for f in Framework::ALL {
        assert_eq!(f.id().parse::<Framework>().unwrap(), f);
    }
}

#[test]
fn trust_join_is_conservative() {
    assert_eq!(
        TrustLabel::Trusted.join(TrustLabel::Untrusted),
        TrustLabel::Untrusted
    );
    assert_eq!(
        TrustLabel::Trusted.join(TrustLabel::Mixed),
        TrustLabel::Mixed
    );
    assert!(TrustLabel::Mixed.is_tainted());
    assert!(!TrustLabel::Trusted.is_tainted());
}

#[test]
fn graph_build_propagate_and_query() {
    let mut g = AgentGraph::new();

    let mut agent = AgentNode::new("agent:researcher", "Researcher", Framework::CrewAI);
    agent.accepts_user_input = true;
    agent.set_system_prompt("You are a researcher.");
    assert!(agent.system_prompt_sha256.is_some());
    let aid = g.add_agent(agent);

    let mut shell = ToolNode::new("tool:shell", "run_shell");
    shell.effects.shell_exec = true;
    shell.effects_resolved = true;
    let tid = g.add_tool(shell);

    g.add_edge(Edge::new(aid.clone(), tid.clone(), EdgeKind::Calls));

    // The researcher accepts user input → untrusted source reaching a shell
    // tool is a trust-boundary crossing.
    g.propagate_trust();
    let crossings = g.edges_crossing_trust_boundary();
    assert_eq!(crossings.len(), 1);

    let tools = g.tools_of(&aid);
    assert_eq!(tools.len(), 1);
    assert!(tools[0].effects.is_privileged());

    assert_eq!(g.kind_of(&aid), Some(ar_core::NodeKind::Agent));
    assert_eq!(g.name_of(&tid), "run_shell");
}

#[test]
fn cycle_detection_flags_self_handoff() {
    let mut g = AgentGraph::new();
    let a = g.add_agent(AgentNode::new("a", "A", Framework::AutoGen));
    let b = g.add_agent(AgentNode::new("b", "B", Framework::AutoGen));
    g.add_edge(Edge::new(a.clone(), b.clone(), EdgeKind::Handoff));
    g.add_edge(Edge::new(b.clone(), a.clone(), EdgeKind::Handoff));
    let cycles = g.cycles();
    assert_eq!(cycles.len(), 1);
    assert_eq!(cycles[0].len(), 2);
}

#[test]
fn finding_builder_and_fingerprint() {
    let f = Finding::new(
        "tb-tool-output-to-next-tool-input",
        DetectorCategory::TrustBoundary,
        Severity::High,
        "Tool output flows into a shell tool",
        "Untrusted output of fetch_url reaches run_shell without sanitization.",
    )
    .with_agent(NodeId::new("agent:researcher"))
    .with_tool(NodeId::new("tool:shell"))
    .with_evidence("fetch_url -> run_shell");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.fingerprint().len(), 64);
    // Findings serialize to JSON cleanly.
    let json = serde_json::to_string(&f).unwrap();
    assert!(json.contains("trust-boundary"));
}
