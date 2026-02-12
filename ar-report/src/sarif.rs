//! Hand-rolled SARIF 2.1.0 emitter for GitHub code-scanning upload.
//!
//! We do not depend on a SARIF crate; the document is assembled with
//! `serde_json::json!` and serialized with `serde_json::to_string_pretty`. One
//! `rules[]` entry is produced per distinct `detector_id`, and one `results[]`
//! entry per active finding, carrying the finding fingerprint as a partial
//! fingerprint and the compliance codes as result properties.

use ar_core::{Finding, Report};
use serde_json::{json, Value};
use std::collections::BTreeSet;

const INFORMATION_URI: &str = "https://github.com/lancer/lancer-agentic-radar";

/// Collect the compliance codes attached to a finding into a flat list of
/// strings, suitable for SARIF tags and result properties.
fn compliance_codes(f: &Finding) -> Vec<String> {
    let mut codes = Vec::new();
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
    if let Some(c) = &f.compliance.cvss {
        codes.push(c.clone());
    }
    codes
}

/// Build the `tool.driver.rules` array: one rule per distinct detector id. The
/// representative finding (first seen, after the report's severity sort) sets
/// the rule's title, category tags and default level.
fn build_rules(findings: &[&Finding]) -> Vec<Value> {
    // Preserve first-seen order while de-duplicating by detector id. The
    // representative rule is built from the first finding seen for each id.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut rules: Vec<Value> = Vec::new();
    for &f in findings {
        if !seen.insert(f.detector_id.clone()) {
            continue;
        }
        let mut tags = vec![f.category.id().to_string()];
        tags.extend(compliance_codes(f));
        rules.push(json!({
            "id": f.detector_id,
            "name": f.detector_id,
            "shortDescription": { "text": f.title },
            "fullDescription": { "text": f.description },
            "defaultConfiguration": { "level": f.severity.sarif_level() },
            "properties": {
                "category": f.category.id(),
                "tags": tags,
                "security-severity": format!("{:.1}", f.severity.numeric()),
            }
        }));
    }
    rules
}

/// Build the `results` array from the active findings.
fn build_results(findings: &[&Finding]) -> Vec<Value> {
    let mut results = Vec::with_capacity(findings.len());
    for &f in findings {
        let uri = f.location.file.display().to_string();
        let uri = if uri.is_empty() {
            "unknown".to_string()
        } else {
            uri.replace('\\', "/")
        };
        let start_line = f.location.line.unwrap_or(1).max(1);

        let mut region = json!({ "startLine": start_line });
        if let Some(col) = f.location.column {
            region["startColumn"] = json!(col.max(1));
        }
        if let Some(snippet) = &f.location.snippet {
            region["snippet"] = json!({ "text": snippet });
        }

        let mut properties = json!({
            "severity": f.severity.as_str(),
            "category": f.category.id(),
            "confidence": format!("{:?}", f.confidence).to_lowercase(),
            "compliance": compliance_codes(f),
            "dynamicallyConfirmed": f.dynamically_confirmed,
        });
        if let Some(agent) = &f.agent {
            properties["agent"] = json!(agent.as_str());
        }
        if let Some(tool) = &f.tool {
            properties["tool"] = json!(tool.as_str());
        }
        if let Some(fix) = &f.fix_suggestion {
            properties["fix"] = json!(fix);
        }

        results.push(json!({
            "ruleId": f.detector_id,
            "level": f.severity.sarif_level(),
            "message": { "text": f.description },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": uri },
                    "region": region
                }
            }],
            "partialFingerprints": { "primary": f.fingerprint() },
            "properties": properties
        }));
    }
    results
}

/// Render the report as a SARIF 2.1.0 document (pretty-printed).
pub fn render(report: &Report) -> String {
    let findings: Vec<&Finding> = report.active_findings().collect();
    let rules = build_rules(&findings);
    let results = build_results(&findings);

    let doc = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "lancer-agentic-radar",
                    "version": report.meta.tool_version,
                    "informationUri": INFORMATION_URI,
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| {
        "{\n  \"version\": \"2.1.0\",\n  \"runs\": []\n}".to_string()
    })
}
