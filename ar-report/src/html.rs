//! Standalone dark-mode HTML report.
//!
//! The page is fully self-contained: an inline `<style>` block (no external
//! CSS), per-finding collapsible evidence via `<details>`/`<summary>`, severity
//! color badges using [`ar_core::Severity::color`], an embedded Mermaid diagram
//! rendered client-side via the mermaid.js CDN script, and a compliance
//! coverage section. All dynamic text is HTML-escaped.

use ar_core::{Finding, Report, Severity};
use std::collections::BTreeMap;
use std::fmt::Write as _;

const MERMAID_CDN: &str = "https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js";

/// HTML-escape arbitrary text for safe embedding in element content or
/// attribute values.
fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// A colored severity badge `<span>`.
fn severity_badge(sev: Severity) -> String {
    format!(
        "<span class=\"badge\" style=\"background:{}\">{}</span>",
        sev.color(),
        esc(sev.as_str())
    )
}

/// Compliance codes for a finding as escaped `<code>` chips.
fn compliance_chips(f: &Finding) -> String {
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
    codes
        .iter()
        .map(|c| format!("<code class=\"chip\">{}</code>", esc(c)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render the full HTML report.
pub fn render(report: &Report) -> String {
    let mut out = String::new();

    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    out.push_str("<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str("<title>lancer-agentic-radar report</title>\n");
    out.push_str(&style_block());
    out.push_str("</head>\n<body>\n");

    out.push_str("<header><h1>lancer-agentic-radar — Security Report</h1></header>\n");
    out.push_str("<main>\n");

    // -- metadata -----------------------------------------------------------
    out.push_str("<section><h2>Scan Metadata</h2>\n<ul class=\"meta\">\n");
    let path = report.meta.scanned_path.display().to_string();
    let _ = writeln!(out, "<li><strong>Scanned path:</strong> <code>{}</code></li>", esc(&path));
    let _ = writeln!(
        out,
        "<li><strong>Tool version:</strong> {}</li>",
        esc(&report.meta.tool_version)
    );
    if let Some(ts) = &report.meta.timestamp {
        let _ = writeln!(out, "<li><strong>Timestamp:</strong> {}</li>", esc(ts));
    }
    if let Some(fw) = &report.meta.framework {
        let _ = writeln!(
            out,
            "<li><strong>Forced framework:</strong> {}</li>",
            esc(fw.display_name())
        );
    }
    if !report.meta.frameworks_detected.is_empty() {
        let fws: Vec<String> = report
            .meta
            .frameworks_detected
            .iter()
            .map(|f| esc(f.display_name()))
            .collect();
        let _ = writeln!(
            out,
            "<li><strong>Frameworks detected:</strong> {}</li>",
            fws.join(", ")
        );
    }
    let _ = writeln!(out, "<li><strong>Dynamic:</strong> {}</li>", report.meta.dynamic);
    let _ = writeln!(out, "<li><strong>Hardened:</strong> {}</li>", report.meta.hardened);
    out.push_str("</ul></section>\n");

    // -- severity summary ---------------------------------------------------
    out.push_str("<section><h2>Severity Summary</h2>\n");
    let counts = report.severity_counts();
    out.push_str("<table>\n<thead><tr><th>Severity</th><th>Count</th></tr></thead>\n<tbody>\n");
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let c = counts.get(&sev).copied().unwrap_or(0);
        let _ = writeln!(
            out,
            "<tr><td>{}</td><td>{}</td></tr>",
            severity_badge(sev),
            c
        );
    }
    out.push_str("</tbody></table>\n</section>\n");

    // -- graph --------------------------------------------------------------
    out.push_str("<section><h2>Workflow Graph</h2>\n");
    let st = &report.stats;
    let _ = writeln!(
        out,
        "<p class=\"stats\">{} agents · {} tools · {} memory · {} RAG · {} edges · {} unresolved</p>",
        st.agents, st.tools, st.memory_stores, st.rag_sources, st.edges, st.unknown_nodes
    );
    // The mermaid source is itself untrusted text; escape it before placing it
    // in the <pre> so it cannot inject markup. mermaid.js reads textContent.
    out.push_str("<pre class=\"mermaid\">\n");
    out.push_str(&esc(&crate::mermaid(&report.graph)));
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("</pre>\n</section>\n");

    // -- findings -----------------------------------------------------------
    out.push_str("<section><h2>Findings</h2>\n");
    let by_cat = report.findings_by_category();
    if by_cat.is_empty() {
        out.push_str("<p class=\"empty\">No active findings.</p>\n");
    } else {
        for (cat, findings) in &by_cat {
            let _ = writeln!(
                out,
                "<h3>{} <span class=\"count\">({})</span></h3>",
                esc(cat.title()),
                findings.len()
            );
            for &f in findings {
                out.push_str("<article class=\"finding\">\n");
                let _ = writeln!(
                    out,
                    "<h4>{} {}</h4>",
                    severity_badge(f.severity),
                    esc(&f.title)
                );
                let _ = writeln!(
                    out,
                    "<p class=\"detector\"><code>{}</code> · confidence {}</p>",
                    esc(&f.detector_id),
                    esc(&format!("{:?}", f.confidence).to_lowercase())
                );
                let loc = f.location.display_path();
                if !loc.is_empty() {
                    let _ = writeln!(out, "<p class=\"loc\">📍 <code>{}</code></p>", esc(&loc));
                }
                let _ = writeln!(out, "<p>{}</p>", esc(&f.description));
                if let Some(ev) = &f.evidence {
                    let _ = writeln!(
                        out,
                        "<details><summary>Evidence</summary><pre>{}</pre></details>",
                        esc(ev)
                    );
                }
                if let Some(fix) = &f.fix_suggestion {
                    let _ = writeln!(out, "<p class=\"fix\"><strong>Fix:</strong> {}</p>", esc(fix));
                }
                if let Some(patch) = &f.remediation_patch {
                    let _ = writeln!(
                        out,
                        "<details><summary>Suggested patch</summary><pre>{}</pre></details>",
                        esc(patch)
                    );
                }
                let chips = compliance_chips(f);
                if !chips.is_empty() {
                    let _ = writeln!(out, "<p class=\"compliance\">{chips}</p>");
                }
                out.push_str("</article>\n");
            }
        }
    }
    out.push_str("</section>\n");

    // -- compliance ---------------------------------------------------------
    out.push_str("<section><h2>Compliance Coverage</h2>\n");
    compliance_section(&mut out, "OWASP Agentic 2026", &report.compliance_summary.owasp_agentic_2026);
    compliance_section(&mut out, "OWASP LLM 2025", &report.compliance_summary.owasp_llm_2025);
    compliance_section(&mut out, "EU AI Act", &report.compliance_summary.eu_ai_act);
    compliance_section(&mut out, "NIST AI RMF", &report.compliance_summary.nist_ai_rmf);
    compliance_section(&mut out, "CSA AICM", &report.compliance_summary.csa_aicm);
    compliance_section(&mut out, "MITRE ATLAS", &report.compliance_summary.mitre_atlas);
    out.push_str("</section>\n");

    out.push_str("</main>\n");

    // -- mermaid bootstrap --------------------------------------------------
    let _ = writeln!(
        out,
        "<script type=\"module\">\nimport mermaid from '{}';\nmermaid.initialize({{ startOnLoad: true, theme: 'dark' }});\n</script>",
        MERMAID_CDN
    );

    out.push_str("</body>\n</html>\n");
    out
}

/// Render one compliance sub-section (heading + chip list of code→count).
fn compliance_section(out: &mut String, title: &str, map: &BTreeMap<String, usize>) {
    let _ = writeln!(out, "<h3>{}</h3>", esc(title));
    let non_zero: Vec<(&String, &usize)> = map.iter().filter(|(_, &c)| c > 0).collect();
    if non_zero.is_empty() {
        out.push_str("<p class=\"empty\">No findings mapped.</p>\n");
        return;
    }
    out.push_str("<p class=\"chips\">");
    for (code, count) in non_zero {
        let _ = write!(
            out,
            "<code class=\"chip\">{} <span class=\"count\">{}</span></code> ",
            esc(code),
            count
        );
    }
    out.push_str("</p>\n");
}

/// The inline dark-mode stylesheet.
fn style_block() -> String {
    "<style>\n\
:root { color-scheme: dark; }\n\
* { box-sizing: border-box; }\n\
body { margin: 0; font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; \
background: #0b1020; color: #e2e8f0; line-height: 1.5; }\n\
header { padding: 1.5rem 2rem; background: #111827; border-bottom: 1px solid #1f2937; }\n\
h1 { margin: 0; font-size: 1.5rem; color: #f8fafc; }\n\
main { max-width: 1100px; margin: 0 auto; padding: 1.5rem 2rem 4rem; }\n\
section { margin-bottom: 2.5rem; }\n\
h2 { border-bottom: 1px solid #1f2937; padding-bottom: .4rem; color: #f1f5f9; }\n\
h3 { color: #cbd5e1; margin-top: 1.5rem; }\n\
h4 { margin: .3rem 0; color: #f8fafc; }\n\
ul.meta { list-style: none; padding: 0; }\n\
ul.meta li { padding: .15rem 0; }\n\
table { border-collapse: collapse; width: 100%; }\n\
th, td { text-align: left; padding: .4rem .8rem; border-bottom: 1px solid #1f2937; }\n\
th { color: #94a3b8; font-weight: 600; }\n\
code { background: #1e293b; padding: .1rem .35rem; border-radius: 4px; font-size: .85em; }\n\
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 999px; color: #fff; \
font-size: .75rem; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; }\n\
.finding { background: #111827; border: 1px solid #1f2937; border-left: 3px solid #334155; \
border-radius: 8px; padding: 1rem 1.2rem; margin: 1rem 0; }\n\
.finding p { margin: .4rem 0; }\n\
.detector { color: #94a3b8; font-size: .85rem; }\n\
.loc { color: #94a3b8; font-size: .85rem; }\n\
.fix { color: #86efac; }\n\
details { margin: .5rem 0; }\n\
summary { cursor: pointer; color: #93c5fd; }\n\
pre { background: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: .8rem; \
overflow-x: auto; white-space: pre-wrap; word-break: break-word; }\n\
pre.mermaid { background: #0f172a; }\n\
.chip { display: inline-block; margin: .15rem; background: #1e293b; }\n\
.count { color: #64748b; font-weight: 400; }\n\
.stats { color: #94a3b8; }\n\
.empty { color: #64748b; font-style: italic; }\n\
</style>\n"
        .to_string()
}
