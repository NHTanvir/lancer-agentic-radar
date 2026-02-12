//! Auditor-friendly Markdown report: title, scan metadata, table of contents,
//! a severity summary table, a graph-stats line, an embedded Mermaid diagram,
//! per-category finding sections and a compliance section.

use ar_core::{Finding, Report, Severity};
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Escape a `|` so it does not break a Markdown table cell, and flatten
/// newlines into spaces so single-row cells stay on one line.
fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace(['\n', '\r'], " ")
}

/// Render the human-readable compliance codes attached to a finding as a
/// comma-separated string (empty string if none).
fn compliance_inline(f: &Finding) -> String {
    let mut codes: Vec<String> = Vec::new();
    for c in &f.compliance.owasp_agentic_2026 {
        codes.push(c.code().to_string());
    }
    for c in &f.compliance.owasp_llm_2025 {
        codes.push(c.code().to_string());
    }
    for a in &f.compliance.eu_ai_act {
        codes.push(a.code().to_string());
    }
    for n in &f.compliance.nist_ai_rmf {
        codes.push(n.clone());
    }
    for c in &f.compliance.csa_aicm {
        codes.push(c.clone());
    }
    for m in &f.compliance.mitre_atlas {
        codes.push(m.clone());
    }
    if let Some(v) = &f.compliance.aivss {
        codes.push(v.vector_string());
    }
    codes.join(", ")
}

/// Render the full Markdown report.
pub fn render(report: &Report) -> String {
    let mut out = String::new();

    // -- title --------------------------------------------------------------
    out.push_str("# lancer-agentic-radar — Security Report\n\n");

    // -- scan metadata ------------------------------------------------------
    out.push_str("## Scan Metadata\n\n");
    let path = report.meta.scanned_path.display().to_string();
    let _ = writeln!(out, "- **Scanned path:** `{}`", cell(&path));
    let _ = writeln!(out, "- **Tool version:** {}", cell(&report.meta.tool_version));
    if let Some(ts) = &report.meta.timestamp {
        let _ = writeln!(out, "- **Timestamp:** {}", cell(ts));
    }
    if let Some(fw) = &report.meta.framework {
        let _ = writeln!(out, "- **Forced framework:** {}", fw.display_name());
    }
    if !report.meta.frameworks_detected.is_empty() {
        let fws: Vec<&str> = report
            .meta
            .frameworks_detected
            .iter()
            .map(|f| f.display_name())
            .collect();
        let _ = writeln!(out, "- **Frameworks detected:** {}", fws.join(", "));
    }
    let _ = writeln!(out, "- **Dynamic confirmation:** {}", report.meta.dynamic);
    let _ = writeln!(out, "- **Hardened:** {}", report.meta.hardened);
    if !report.meta.compliance_modes.is_empty() {
        let modes: Vec<&str> = report
            .meta
            .compliance_modes
            .iter()
            .map(|m| m.title())
            .collect();
        let _ = writeln!(out, "- **Compliance modes:** {}", modes.join(", "));
    }
    out.push('\n');

    // -- table of contents --------------------------------------------------
    out.push_str("## Table of Contents\n\n");
    out.push_str("1. [Severity Summary](#severity-summary)\n");
    out.push_str("2. [Workflow Graph](#workflow-graph)\n");
    out.push_str("3. [Findings](#findings)\n");
    out.push_str("4. [Compliance](#compliance)\n\n");

    // -- severity summary ---------------------------------------------------
    out.push_str("## Severity Summary\n\n");
    let counts = report.severity_counts();
    let total: usize = counts.values().sum();
    out.push_str("| Severity | Count |\n");
    out.push_str("| --- | --- |\n");
    // Descending: Critical first.
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let c = counts.get(&sev).copied().unwrap_or(0);
        let _ = writeln!(out, "| {} | {} |", sev.as_str(), c);
    }
    let _ = writeln!(out, "| **Total** | **{total}** |");
    out.push('\n');

    // -- graph stats --------------------------------------------------------
    out.push_str("## Workflow Graph\n\n");
    let s = &report.stats;
    let _ = writeln!(
        out,
        "**Graph stats:** {} agents · {} tools · {} memory stores · {} RAG sources · {} edges · {} unresolved nodes\n",
        s.agents, s.tools, s.memory_stores, s.rag_sources, s.edges, s.unknown_nodes
    );

    // -- embedded mermaid ---------------------------------------------------
    out.push_str("```mermaid\n");
    out.push_str(&crate::mermaid(&report.graph));
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("```\n\n");

    // -- findings -----------------------------------------------------------
    out.push_str("## Findings\n\n");
    let by_cat = report.findings_by_category();
    if by_cat.is_empty() {
        out.push_str("_No active findings._\n\n");
    } else {
        for (cat, findings) in &by_cat {
            let _ = writeln!(out, "### {} ({})\n", cat.title(), findings.len());
            for &f in findings {
                let _ = writeln!(out, "#### {} — `{}`\n", cell(&f.title), f.severity.as_str());
                let _ = writeln!(out, "- **Detector:** `{}`", cell(&f.detector_id));
                let _ = writeln!(
                    out,
                    "- **Confidence:** {}",
                    format!("{:?}", f.confidence).to_lowercase()
                );
                let loc = f.location.display_path();
                if !loc.is_empty() {
                    let _ = writeln!(out, "- **Location:** `{}`", cell(&loc));
                }
                if let Some(agent) = &f.agent {
                    let _ = writeln!(out, "- **Agent:** `{}`", cell(agent.as_str()));
                }
                if let Some(tool) = &f.tool {
                    let _ = writeln!(out, "- **Tool:** `{}`", cell(tool.as_str()));
                }
                let _ = writeln!(out, "\n{}\n", f.description);
                if let Some(ev) = &f.evidence {
                    out.push_str("**Evidence:**\n\n```\n");
                    out.push_str(ev);
                    if !ev.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str("```\n\n");
                }
                if let Some(fix) = &f.fix_suggestion {
                    let _ = writeln!(out, "**Fix:** {fix}\n");
                }
                if let Some(patch) = &f.remediation_patch {
                    out.push_str("**Suggested patch:**\n\n```\n");
                    out.push_str(patch);
                    if !patch.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str("```\n\n");
                }
                let codes = compliance_inline(f);
                if !codes.is_empty() {
                    let _ = writeln!(out, "**Compliance:** {codes}\n");
                }
            }
        }
    }

    // -- compliance ---------------------------------------------------------
    out.push_str("## Compliance\n\n");
    render_compliance_table(&mut out, "OWASP Agentic 2026", &report.compliance_summary.owasp_agentic_2026);
    render_compliance_table(&mut out, "OWASP LLM 2025", &report.compliance_summary.owasp_llm_2025);
    render_compliance_table(&mut out, "EU AI Act", &report.compliance_summary.eu_ai_act);
    render_compliance_table(&mut out, "NIST AI RMF", &report.compliance_summary.nist_ai_rmf);
    render_compliance_table(&mut out, "CSA AICM", &report.compliance_summary.csa_aicm);
    render_compliance_table(&mut out, "MITRE ATLAS", &report.compliance_summary.mitre_atlas);

    // OWASP Agentic 2026 coverage list (every category, with counts).
    out.push_str("### OWASP Agentic 2026 coverage\n\n");
    for cat in ar_core::OwaspAgentic2026::ALL {
        let count = report
            .compliance_summary
            .owasp_agentic_2026
            .get(cat.code())
            .copied()
            .unwrap_or(0);
        let marker = if count > 0 { "x" } else { " " };
        let _ = writeln!(
            out,
            "- [{marker}] {} {} — {count} finding(s)",
            cat.code(),
            cat.title()
        );
    }
    out.push('\n');

    out
}

/// Render a `### <title>` section with a two-column code/count table. A section
/// with no entries renders an explicit "no findings mapped" note so the report
/// is self-describing.
fn render_compliance_table(out: &mut String, title: &str, map: &BTreeMap<String, usize>) {
    let _ = writeln!(out, "### {title}\n");
    // For OWASP Agentic the map is pre-seeded with every category at 0; show
    // all rows. For others, only rows that have at least one mapping carry
    // signal, but printing zero rows is fine too.
    let non_zero: Vec<(&String, &usize)> = map.iter().filter(|(_, &c)| c > 0).collect();
    if non_zero.is_empty() {
        out.push_str("_No findings mapped._\n\n");
        return;
    }
    out.push_str("| Code | Findings |\n");
    out.push_str("| --- | --- |\n");
    for (code, count) in non_zero {
        let _ = writeln!(out, "| {} | {} |", cell(code), count);
    }
    out.push('\n');
}
