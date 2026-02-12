//! Graph visualization: Mermaid `flowchart TB` and DOT/Graphviz emitters.
//!
//! Both renderers walk the same [`ar_core::AgentGraph`] and produce a node per
//! agent / tool / memory store / RAG source / unknown, plus an edge per
//! [`ar_core::Edge`]. Node shapes encode the node kind, tool nodes carry effect
//! badges (`SHELL`, `NET`, `FS-W`, …) and agents are labelled with their model
//! and the first eight characters of their system-prompt SHA-256. Edges are
//! colored by their propagated [`ar_core::TrustLabel`] — green for `Trusted`,
//! orange for `Mixed`, red for `Untrusted`.

use ar_core::{AgentGraph, Edge, NodeId, TrustLabel};

/// Sanitize a node id into a Mermaid/DOT-safe identifier: every character that
/// is not ASCII-alphanumeric becomes `_`. A leading digit is prefixed with `n`
/// so the id is always a valid token.
fn sanitize_id(id: &str) -> String {
    let mut out = String::with_capacity(id.len() + 1);
    for c in id.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('n');
    } else if out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, 'n');
    }
    out
}

/// Escape a label for embedding inside a Mermaid node `[...]` / `(...)` block.
/// Mermaid is sensitive to quotes, brackets and pipes, so we wrap the text in
/// double quotes and neutralize the dangerous characters.
fn mermaid_label(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '|' => out.push('/'),
            '[' => out.push('('),
            ']' => out.push(')'),
            '{' => out.push('('),
            '}' => out.push(')'),
            '\n' | '\r' => out.push(' '),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Escape a label for a DOT attribute value (already inside double quotes).
fn dot_label(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// First eight hex characters of a system-prompt SHA-256, or empty if absent.
fn short_sha(sha: &Option<String>) -> String {
    match sha {
        Some(s) if s.len() >= 8 => s[..8].to_string(),
        Some(s) => s.clone(),
        None => String::new(),
    }
}

/// Build the human-readable label lines for an agent node.
fn agent_label_text(name: &str, model: &Option<String>, sha: &Option<String>) -> String {
    let mut parts = vec![name.to_string()];
    if let Some(m) = model {
        parts.push(format!("model: {m}"));
    }
    let s = short_sha(sha);
    if !s.is_empty() {
        parts.push(format!("sp#{s}"));
    }
    parts.join("\n")
}

/// Effect badges + a privileged-call marker suffix for a tool label.
fn tool_badge_text(t: &ar_core::ToolNode) -> String {
    let badges = t.effects.badges();
    if badges.is_empty() {
        String::new()
    } else {
        format!(" [{}]", badges.join(","))
    }
}

/// Trust label that should color an edge, derived conservatively: an edge
/// flowing tainted data into a privileged tool is treated as `Untrusted` (red)
/// regardless of the source label, matching the report rubric.
fn edge_trust(graph: &AgentGraph, e: &Edge) -> TrustLabel {
    if let Some(t) = graph.tool(&e.to) {
        if t.effects.is_privileged() && e.trust.is_tainted() {
            return TrustLabel::Untrusted;
        }
    }
    e.trust
}

/// Render the tool topology as a Mermaid `flowchart TB`.
///
/// Agents are rounded rectangles, tools are rectangles carrying their effect
/// badges, memory stores are cylinders, RAG sources are parallelograms and
/// unresolved nodes are dashed. Edge colors are applied with per-edge
/// `linkStyle` directives keyed off the propagated trust label.
pub fn mermaid(graph: &AgentGraph) -> String {
    let mut out = String::new();
    out.push_str("flowchart TB\n");

    // -- nodes --------------------------------------------------------------
    for a in &graph.agents {
        let nid = sanitize_id(a.id.as_str());
        let label = agent_label_text(&a.name, &a.model, &a.system_prompt_sha256);
        out.push_str(&format!("    {nid}({})\n", mermaid_label(&label)));
        out.push_str(&format!("    class {nid} agent;\n"));
    }
    for t in &graph.tools {
        let nid = sanitize_id(t.id.as_str());
        let label = format!("{}{}", t.name, tool_badge_text(t));
        out.push_str(&format!("    {nid}[{}]\n", mermaid_label(&label)));
        let cls = if t.effects.is_privileged() {
            "toolpriv"
        } else {
            "tool"
        };
        out.push_str(&format!("    class {nid} {cls};\n"));
    }
    for m in &graph.memory {
        let nid = sanitize_id(m.id.as_str());
        let label = format!("{} ({})", m.name, m.kind);
        out.push_str(&format!("    {nid}[({})]\n", mermaid_label(&label)));
        out.push_str(&format!("    class {nid} memory;\n"));
    }
    for r in &graph.rag {
        let nid = sanitize_id(r.id.as_str());
        let label = format!("{} ({})", r.name, r.kind);
        out.push_str(&format!("    {nid}[/{}/]\n", mermaid_label(&label)));
        out.push_str(&format!("    class {nid} rag;\n"));
    }
    for (uid, ulabel) in &graph.unknowns {
        let nid = sanitize_id(uid.as_str());
        out.push_str(&format!("    {nid}[{}]\n", mermaid_label(ulabel)));
        out.push_str(&format!("    class {nid} unknown;\n"));
    }

    // -- edges --------------------------------------------------------------
    // We also remember the trust color for each edge by its emission order so a
    // matching `linkStyle <index>` can recolor it.
    let mut link_styles: Vec<(usize, &'static str)> = Vec::new();
    let mut edge_index = 0usize;
    for e in &graph.edges {
        let from = sanitize_id(e.from.as_str());
        let to = sanitize_id(e.to.as_str());
        let trust = edge_trust(graph, e);
        let edge_label = match &e.label {
            Some(l) => format!("{} ({})", e.kind.as_str(), l),
            None => e.kind.as_str().to_string(),
        };
        out.push_str(&format!(
            "    {from} -->|{}| {to}\n",
            mermaid_label(&edge_label)
        ));
        link_styles.push((edge_index, trust.edge_color()));
        edge_index += 1;
    }

    // -- styling ------------------------------------------------------------
    out.push_str("    classDef agent fill:#1e3a8a,stroke:#3b82f6,color:#e0e7ff;\n");
    out.push_str("    classDef tool fill:#374151,stroke:#9ca3af,color:#f3f4f6;\n");
    out.push_str("    classDef toolpriv fill:#7f1d1d,stroke:#ef4444,color:#fee2e2;\n");
    out.push_str("    classDef memory fill:#064e3b,stroke:#10b981,color:#d1fae5;\n");
    out.push_str("    classDef rag fill:#4c1d95,stroke:#a78bfa,color:#ede9fe;\n");
    out.push_str(
        "    classDef unknown fill:#1f2937,stroke:#6b7280,color:#9ca3af,stroke-dasharray: 5 5;\n",
    );
    for (idx, color) in link_styles {
        out.push_str(&format!(
            "    linkStyle {idx} stroke:{color},stroke-width:2px;\n"
        ));
    }

    out
}

/// Render the tool topology as a DOT/Graphviz `digraph`.
pub fn dot(graph: &AgentGraph) -> String {
    let mut out = String::new();
    out.push_str("digraph agent_graph {\n");
    out.push_str("    rankdir=TB;\n");
    out.push_str("    bgcolor=\"#0b1020\";\n");
    out.push_str(
        "    node [fontname=\"Helvetica\", fontcolor=\"#f3f4f6\", style=\"filled,rounded\"];\n",
    );
    out.push_str("    edge [fontname=\"Helvetica\", fontcolor=\"#cbd5e1\"];\n");

    for a in &graph.agents {
        let nid = sanitize_id(a.id.as_str());
        let label = agent_label_text(&a.name, &a.model, &a.system_prompt_sha256);
        out.push_str(&format!(
            "    {nid} [label=\"{}\", shape=box, style=\"filled,rounded\", fillcolor=\"#1e3a8a\", color=\"#3b82f6\"];\n",
            dot_label(&label)
        ));
    }
    for t in &graph.tools {
        let nid = sanitize_id(t.id.as_str());
        let label = format!("{}{}", t.name, tool_badge_text(t));
        let (fill, color) = if t.effects.is_privileged() {
            ("#7f1d1d", "#ef4444")
        } else {
            ("#374151", "#9ca3af")
        };
        out.push_str(&format!(
            "    {nid} [label=\"{}\", shape=box, style=filled, fillcolor=\"{fill}\", color=\"{color}\"];\n",
            dot_label(&label)
        ));
    }
    for m in &graph.memory {
        let nid = sanitize_id(m.id.as_str());
        let label = format!("{} ({})", m.name, m.kind);
        out.push_str(&format!(
            "    {nid} [label=\"{}\", shape=cylinder, style=filled, fillcolor=\"#064e3b\", color=\"#10b981\"];\n",
            dot_label(&label)
        ));
    }
    for r in &graph.rag {
        let nid = sanitize_id(r.id.as_str());
        let label = format!("{} ({})", r.name, r.kind);
        out.push_str(&format!(
            "    {nid} [label=\"{}\", shape=parallelogram, style=filled, fillcolor=\"#4c1d95\", color=\"#a78bfa\"];\n",
            dot_label(&label)
        ));
    }
    for (uid, ulabel) in &graph.unknowns {
        let nid = sanitize_id(uid.as_str());
        out.push_str(&format!(
            "    {nid} [label=\"{}\", shape=box, style=\"filled,dashed\", fillcolor=\"#1f2937\", color=\"#6b7280\"];\n",
            dot_label(ulabel)
        ));
    }

    for e in &graph.edges {
        let from = sanitize_id(e.from.as_str());
        let to = sanitize_id(e.to.as_str());
        let trust = edge_trust(graph, e);
        let edge_label = match &e.label {
            Some(l) => format!("{} ({})", e.kind.as_str(), l),
            None => e.kind.as_str().to_string(),
        };
        out.push_str(&format!(
            "    {from} -> {to} [label=\"{}\", color=\"{}\", penwidth=2.0];\n",
            dot_label(&edge_label),
            trust.edge_color()
        ));
    }

    out.push_str("}\n");
    out
}

/// Whether a node id appears anywhere in the graph (small helper used by tests
/// and downstream sanity checks).
pub fn graph_has_node(graph: &AgentGraph, id: &NodeId) -> bool {
    graph.kind_of(id).is_some()
}
