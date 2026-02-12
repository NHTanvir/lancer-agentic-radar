//! Runtime-governance integration exports.
//!
//! Each export turns the static [`ar_core::Report`] into a deterministic policy
//! document for a runtime guardrail framework, so the enforcement layer can
//! block / require-approval / inline-filter the issues found statically:
//!
//! * [`ms_agt`] — Microsoft Agent Governance Toolkit policy set.
//! * [`defenseclaw`] — Cisco DefenseClaw secure-agent-framework controls.
//! * [`llamafirewall`] — Meta LlamaFirewall inline-filter config.
//!
//! All three iterate findings in the report's stable (severity-sorted) order
//! and emit pretty-printed JSON.

use ar_core::{DetectorCategory, Finding, Report, Severity};
use serde_json::{json, Value};

/// OWASP Agentic 2026 codes attached to a finding, joined for policy metadata.
fn owasp_codes(f: &Finding) -> Vec<String> {
    f.compliance
        .owasp_agentic_2026
        .iter()
        .map(|c| c.code().to_string())
        .collect()
}

/// Whether a finding should drive a runtime policy rule (Critical/High only,
/// per the plan — those are the issues worth blocking at agent-call time).
fn is_enforceable(f: &Finding) -> bool {
    matches!(f.severity, Severity::Critical | Severity::High)
}

/// Microsoft Agent Governance Toolkit policy export (JSON string).
///
/// Emits one rule per Critical/High finding: Critical findings `deny`, High
/// findings `require_approval`. The `match` object scopes the rule to the
/// finding's agent and tool when known.
pub fn ms_agt(report: &Report) -> String {
    let mut rules: Vec<Value> = Vec::new();
    for f in report.active_findings() {
        if !is_enforceable(f) {
            continue;
        }
        let action = match f.severity {
            Severity::Critical => "deny",
            _ => "require_approval",
        };
        rules.push(json!({
            "id": f.detector_id,
            "action": action,
            "match": {
                "agent": f.agent.as_ref().map(|a| a.as_str()),
                "tool": f.tool.as_ref().map(|t| t.as_str()),
            },
            "severity": f.severity.as_str(),
            "category": f.category.id(),
            "owasp": owasp_codes(f),
            "fingerprint": f.fingerprint(),
        }));
    }

    let doc = json!({
        "policy_set": "lancer-agentic-radar",
        "version": report.meta.tool_version,
        "rules": rules,
    });
    to_pretty(&doc)
}

/// Map a detector category to a DefenseClaw control type.
fn defenseclaw_control_type(cat: DetectorCategory) -> &'static str {
    match cat {
        DetectorCategory::PromptInjection
        | DetectorCategory::IndirectInjection
        | DetectorCategory::JailbreakPathway => "input-guard",
        DetectorCategory::MissingOutputFilter | DetectorCategory::SecretLeakage => "output-guard",
        DetectorCategory::ToolPoisoning
        | DetectorCategory::ExcessiveAuthority
        | DetectorCategory::TrustBoundary => "tool-policy",
        DetectorCategory::MemoryPoisoning | DetectorCategory::RagPoisoning => "data-policy",
        DetectorCategory::HandoffAbuse => "handoff-policy",
        DetectorCategory::RecursionBomb
        | DetectorCategory::InfiniteLoop
        | DetectorCategory::ResourceExhaustion => "rate-limit",
        _ => "audit",
    }
}

/// Cisco DefenseClaw secure-agent-framework export (JSON string).
///
/// Emits one control per Critical/High finding, classified by the finding's
/// detector category, with `block` enforcement for Critical and `monitor` for
/// High.
pub fn defenseclaw(report: &Report) -> String {
    let mut controls: Vec<Value> = Vec::new();
    for f in report.active_findings() {
        if !is_enforceable(f) {
            continue;
        }
        let enforcement = match f.severity {
            Severity::Critical => "block",
            _ => "monitor",
        };
        controls.push(json!({
            "id": f.detector_id,
            "control_type": defenseclaw_control_type(f.category),
            "enforcement": enforcement,
            "target": {
                "agent": f.agent.as_ref().map(|a| a.as_str()),
                "tool": f.tool.as_ref().map(|t| t.as_str()),
            },
            "severity": f.severity.as_str(),
            "category": f.category.id(),
            "owasp": owasp_codes(f),
            "fingerprint": f.fingerprint(),
        }));
    }

    let doc = json!({
        "framework": "defenseclaw",
        "policy_set": "lancer-agentic-radar",
        "version": report.meta.tool_version,
        "audit_log": true,
        "controls": controls,
    });
    to_pretty(&doc)
}

/// Map a detector category to a LlamaFirewall (filter type, pattern class).
fn llamafirewall_filter(cat: DetectorCategory) -> (&'static str, &'static str) {
    match cat {
        DetectorCategory::PromptInjection => ("input", "prompt_injection"),
        DetectorCategory::IndirectInjection => ("input", "indirect_injection"),
        DetectorCategory::JailbreakPathway => ("input", "jailbreak"),
        DetectorCategory::MissingInputValidation => ("input", "schema_validation"),
        DetectorCategory::SecretLeakage => ("output", "secret_redaction"),
        DetectorCategory::MissingOutputFilter => ("output", "output_scan"),
        DetectorCategory::ToolPoisoning => ("input", "tool_description_scan"),
        DetectorCategory::RagPoisoning => ("input", "retrieval_scan"),
        DetectorCategory::MemoryPoisoning => ("input", "memory_scan"),
        DetectorCategory::TrustBoundary | DetectorCategory::ExcessiveAuthority => {
            ("input", "tool_call_guard")
        }
        DetectorCategory::HandoffAbuse => ("input", "handoff_guard"),
        DetectorCategory::RecursionBomb
        | DetectorCategory::InfiniteLoop
        | DetectorCategory::ResourceExhaustion => ("output", "loop_guard"),
        _ => ("input", "generic_scan"),
    }
}

/// Meta LlamaFirewall inline-filter config export (JSON string).
///
/// Emits one filter per active finding (de-duplicated by name), classifying the
/// filter as input/output and assigning a `pattern_class` derived from the
/// finding category. Every filter blocks on match.
pub fn llamafirewall(report: &Report) -> String {
    let mut filters: Vec<Value> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for f in report.active_findings() {
        let (ftype, pattern_class) = llamafirewall_filter(f.category);
        let name = format!("{}::{}", f.category.id(), f.detector_id);
        if !seen.insert(name.clone()) {
            continue;
        }
        filters.push(json!({
            "name": name,
            "type": ftype,
            "pattern_class": pattern_class,
            "on_match": "block",
            "severity": f.severity.as_str(),
            "detector": f.detector_id,
        }));
    }

    let doc = json!({
        "engine": "llamafirewall",
        "version": report.meta.tool_version,
        "filters": filters,
    });
    to_pretty(&doc)
}

/// Serialize a value to pretty JSON, never panicking.
fn to_pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".to_string())
}
