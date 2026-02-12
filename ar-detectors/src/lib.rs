//! # ar-detectors
//!
//! The static security detectors for **lancer-agentic-radar**. Each detector is
//! a pure check over an [`ar_core::AgentGraph`] that emits
//! [`ar_core::Finding`]s; they are grouped into the 18 categories of the plan's
//! detector catalog (~50 sub-checks total).
//!
//! ## Facade
//!
//! - [`registry`] — static [`DetectorMeta`] for every sub-check (drives
//!   `--self-test` and the GUI catalog).
//! - [`run_all`] — run every *enabled* detector over a graph, apply the OWASP
//!   Agentic 2026 compliance tagging, honour config suppression + inline
//!   `# ar-ignore` hints + `min_confidence`, dedup, and return the findings.
//!
//! Detectors never mutate the graph; the only post-processing happens in
//! [`run_all`].

pub mod detector;
pub mod registry;

// One module per detector category (plan §"Detector catalog" items 1-18).
pub mod prompt_injection;
pub mod tool_poisoning;
pub mod rag_poisoning;
pub mod memory_poisoning;
pub mod trust_boundary;
pub mod excessive_authority;
pub mod missing_validation;
pub mod missing_output_filter;
pub mod secret_leakage;
pub mod jailbreak_pathway;
pub mod indirect_injection;
pub mod recursion_bomb;
pub mod infinite_loop;
pub mod resource_exhaustion;
pub mod owasp_agentic;
pub mod n8n_risks;
pub mod handoff_abuse;
pub mod prompt_hardening;

pub use detector::{Detector, DetectorMeta};

use ar_core::{AgentGraph, Config, Finding};

/// Metadata for every registered detector sub-check.
///
/// Built from [`registry::all_detectors`], so it stays in lock-step with what
/// [`run_all`] actually executes.
pub fn registry() -> Vec<DetectorMeta> {
    registry::all_detectors()
        .iter()
        .map(|d| DetectorMeta::of(&**d))
        .collect()
}

/// Run all enabled detectors over `graph`, apply compliance tagging, config
/// suppression, inline `# ar-ignore` hints and `min_confidence` filtering, then
/// dedup. Suppressed findings are kept (with `suppressed = true`) rather than
/// dropped, so the report can still account for them.
pub fn run_all(graph: &AgentGraph, cfg: &Config) -> Vec<Finding> {
    // 1-3. Run every enabled detector and collect findings.
    let mut findings: Vec<Finding> = Vec::new();
    for d in registry::all_detectors() {
        if !cfg.detectors.enabled(d.id(), d.category().id()) {
            continue;
        }
        findings.extend(d.detect(graph));
    }

    // 4. Compliance tagging via the OWASP Agentic meta-detector (idempotent).
    owasp_agentic::tag_compliance(&mut findings);

    // 5. min_confidence: mark below-threshold findings suppressed.
    if let Some(min) = cfg.min_confidence {
        let floor = confidence_rank(min);
        for f in findings.iter_mut() {
            if confidence_rank(f.confidence) < floor {
                f.suppressed = true;
            }
        }
    }

    // 6. Inline `# ar-ignore: <id>` suppression hints in the finding's snippet.
    for f in findings.iter_mut() {
        if finding_is_ignored(f) {
            f.suppressed = true;
        }
    }

    // 7. Dedup: same detector_id + same agent + same tool + same title.
    dedup_findings(&mut findings);

    findings
}

/// Ordinal rank for a [`ar_core::Confidence`] (`Confidence` does not derive
/// `Ord` in ar-core, so we compare via this ladder).
fn confidence_rank(c: ar_core::Confidence) -> u8 {
    match c {
        ar_core::Confidence::Low => 0,
        ar_core::Confidence::Medium => 1,
        ar_core::Confidence::High => 2,
    }
}

/// Whether the finding's source snippet carries a `# ar-ignore` hint that
/// targets this finding (either `# ar-ignore` blanket, or `# ar-ignore: <id>`
/// naming this detector or its category).
fn finding_is_ignored(f: &Finding) -> bool {
    let snippet = match &f.location.snippet {
        Some(s) => s,
        None => return false,
    };
    let lc = snippet.to_ascii_lowercase();
    // Support `# ar-ignore`, `// ar-ignore`, `ar-ignore`, with optional id list.
    let Some(pos) = lc.find("ar-ignore") else {
        return false;
    };
    let rest = lc[pos + "ar-ignore".len()..].trim_start();
    // Bare `ar-ignore` (no colon / no ids) suppresses everything on the line.
    if !rest.starts_with(':') {
        return true;
    }
    let ids = &rest[1..];
    let cat = f.category.id();
    let det = f.detector_id.to_ascii_lowercase();
    // Match any comma/space-separated id token equal to the detector or category.
    ids.split(|c: char| c == ',' || c.is_whitespace())
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .any(|t| t == det.as_str() || t == cat || t == "all")
}

/// Drop later findings that duplicate an earlier one on
/// (detector_id, agent, tool, title). Order of first occurrence is preserved.
fn dedup_findings(findings: &mut Vec<Finding>) {
    use std::collections::HashSet;
    let mut seen: HashSet<(String, Option<String>, Option<String>, String)> = HashSet::new();
    findings.retain(|f| {
        let key = (
            f.detector_id.clone(),
            f.agent.as_ref().map(|a| a.0.clone()),
            f.tool.as_ref().map(|t| t.0.clone()),
            f.title.clone(),
        );
        seen.insert(key)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ar_core::{
        AgentGraph, AgentNode, Config, Edge, EdgeKind, Framework, NodeId, SourceLocation,
        ToolEffects, ToolNode,
    };

    /// Build a small graph: an untrusted agent calling a shell tool.
    fn untrusted_agent_with_shell_tool() -> AgentGraph {
        let mut g = AgentGraph::new();

        let mut agent = AgentNode::new("agent:assistant", "Assistant", Framework::LangChain);
        agent.accepts_user_input = true;
        agent.set_system_prompt("You are a helpful assistant. {input}");
        agent.location = SourceLocation::new("agent.py").at_line(10);
        let agent_id = g.add_agent(agent);

        let mut shell = ToolNode::new("tool:run_shell", "run_shell");
        shell.effects = ToolEffects {
            shell_exec: true,
            ..ToolEffects::default()
        };
        shell.effects_resolved = true;
        shell.location = SourceLocation::new("tools.py").at_line(3);
        let shell_id = g.add_tool(shell);

        g.add_edge(Edge::new(agent_id.clone(), shell_id.clone(), EdgeKind::Calls));
        g
    }

    #[test]
    fn trust_boundary_and_excessive_authority_fire() {
        let g = untrusted_agent_with_shell_tool();
        let cfg = Config::default();
        let findings = run_all(&g, &cfg);
        let ids: Vec<&str> = findings.iter().map(|f| f.detector_id.as_str()).collect();

        assert!(
            ids.contains(&"tb-tool-output-to-next-tool-input"),
            "expected trust-boundary finding; got {ids:?}"
        );
        assert!(
            ids.contains(&"ea-shell-tool-without-allowlist"),
            "expected excessive-authority finding; got {ids:?}"
        );
    }

    #[test]
    fn every_finding_has_an_agentic_tag() {
        let g = untrusted_agent_with_shell_tool();
        let findings = run_all(&g, &Config::default());
        assert!(!findings.is_empty(), "expected at least one finding");
        for f in &findings {
            assert!(
                !f.compliance.owasp_agentic_2026.is_empty(),
                "finding {} has no OWASP Agentic tag",
                f.detector_id
            );
        }
    }

    #[test]
    fn registry_lists_all_subchecks() {
        let metas = registry();
        let ids: Vec<&str> = metas.iter().map(|m| m.id).collect();
        // Spot-check a few required ids across categories.
        for want in [
            "pi-user-in-system-prompt",
            "tp-mcp-untrusted-server",
            "rp-untrusted-document-source",
            "mp-memory-no-tenant-isolation",
            "tb-tool-output-to-next-tool-input",
            "ea-shell-tool-without-allowlist",
            "miv-no-schema-on-tool-args",
            "mof-no-pii-redaction",
            "sl-hardcoded-api-key",
            "jb-system-prompt-overridable",
            "ii-rag-output-unsanitized",
            "rb-mutual-recursion",
            "il-while-true-no-timeout",
            "re-no-max-steps",
            "n8n-webhook-trigger-public-without-auth",
            "oa-handoff-without-input-filter",
            "ph-no-role-separator",
        ] {
            assert!(ids.contains(&want), "registry missing `{want}`");
        }
    }

    #[test]
    fn config_exclusion_suppresses_a_detector() {
        let g = untrusted_agent_with_shell_tool();
        let mut cfg = Config::default();
        cfg.detectors.exclude = vec!["ea-shell-tool-without-allowlist".to_string()];
        let findings = run_all(&g, &cfg);
        assert!(
            !findings
                .iter()
                .any(|f| f.detector_id == "ea-shell-tool-without-allowlist"),
            "excluded detector still fired"
        );
    }

    #[test]
    fn inline_ar_ignore_marks_suppressed() {
        let mut g = AgentGraph::new();
        let mut tool = ToolNode::new("tool:sh", "sh");
        tool.effects = ToolEffects {
            shell_exec: true,
            ..ToolEffects::default()
        };
        // Snippet carries an inline ignore hint for the shell detector.
        tool.location =
            SourceLocation::new("tools.py").with_snippet("subprocess.run(cmd)  # ar-ignore: ea-shell-tool-without-allowlist");
        let tid = g.add_tool(tool);
        let mut agent = AgentNode::new("agent:a", "A", Framework::LangChain);
        agent.accepts_user_input = true;
        let aid = g.add_agent(agent);
        g.add_edge(Edge::new(aid, tid, EdgeKind::Calls));

        let findings = run_all(&g, &Config::default());
        let shell = findings
            .iter()
            .find(|f| f.detector_id == "ea-shell-tool-without-allowlist")
            .expect("detector should still produce a (suppressed) finding");
        assert!(shell.suppressed, "inline ar-ignore should mark suppressed");
        // Ensure NodeId import is exercised (keeps the import meaningful).
        let _ = NodeId::new("x");
    }
}
