//! The OWASP Agentic 2026 meta-detector (plan §"Detector catalog" item 15).
//!
//! This is not a finding source of its own. It is a post-process that ensures
//! every finding carries at least one OWASP Top 10 for Agentic Applications
//! 2026 tag, derived from the finding's detector category. The mapping is the
//! authoritative category -> OWASP-Agentic table from the plan.
//!
//! [`tag_compliance`] is idempotent: running it twice does not duplicate tags.

use crate::detector::Detector;
use ar_core::{DetectorCategory, Finding, OwaspAgentic2026, Severity};

/// The default OWASP Agentic 2026 categories for a detector category.
///
/// Mirrors the plan's mapping table (trust-boundary -> ToolMisuse; excessive-
/// authority -> ToolMisuse + UnsafeAutonomyEscalation; memory-poisoning ->
/// MemoryPoisoning; handoff-abuse -> UnauthorizedHandoff; recursion / infinite
/// / resource -> CascadingFailure; secret-leakage / missing-output-filter ->
/// DataExfiltrationViaAgent; prompt-injection / jailbreak / indirect ->
/// GoalHijacking; tool-poisoning -> ToolMisuse; resolution -> TraceabilityGap).
pub fn default_agentic_for(category: DetectorCategory) -> &'static [OwaspAgentic2026] {
    // Use fully-qualified paths throughout: the `OwaspAgentic2026` name is both
    // a `DetectorCategory` variant and the compliance enum, so globbing either
    // would be ambiguous.
    use OwaspAgentic2026 as A;
    match category {
        DetectorCategory::PromptInjection => &[A::GoalHijacking],
        DetectorCategory::ToolPoisoning => &[A::ToolMisuse],
        DetectorCategory::RagPoisoning => &[A::MemoryPoisoning],
        DetectorCategory::MemoryPoisoning => &[A::MemoryPoisoning],
        DetectorCategory::TrustBoundary => &[A::ToolMisuse],
        DetectorCategory::ExcessiveAuthority => &[A::ToolMisuse, A::UnsafeAutonomyEscalation],
        DetectorCategory::MissingInputValidation => &[A::ToolMisuse],
        DetectorCategory::MissingOutputFilter => &[A::DataExfiltrationViaAgent],
        DetectorCategory::SecretLeakage => &[A::DataExfiltrationViaAgent],
        DetectorCategory::JailbreakPathway => &[A::GoalHijacking],
        DetectorCategory::IndirectInjection => &[A::GoalHijacking],
        DetectorCategory::RecursionBomb => &[A::CascadingFailure],
        DetectorCategory::InfiniteLoop => &[A::CascadingFailure],
        DetectorCategory::ResourceExhaustion => &[A::CascadingFailure],
        DetectorCategory::OwaspAgentic2026 => &[A::RogueAgent],
        DetectorCategory::N8nWorkflowRisks => &[A::ToolMisuse],
        DetectorCategory::HandoffAbuse => &[A::UnauthorizedHandoff],
        DetectorCategory::PromptHardeningNeeded => &[A::GoalHijacking],
        DetectorCategory::Resolution => &[A::TraceabilityGap],
    }
}

/// Ensure every finding carries at least one OWASP Agentic 2026 tag derived
/// from its category. Idempotent — existing tags are preserved and not
/// duplicated.
pub fn tag_compliance(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        for &cat in default_agentic_for(f.category) {
            if !f.compliance.owasp_agentic_2026.contains(&cat) {
                f.compliance.owasp_agentic_2026.push(cat);
            }
        }
    }
}

/// The meta-detector itself. It emits no findings (its job is the post-process
/// [`tag_compliance`]) but is registered so it appears in the detector catalog
/// and `--self-test`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OwaspAgenticMeta;

impl Detector for OwaspAgenticMeta {
    fn id(&self) -> &'static str {
        "owasp-agentic-2026-mapping"
    }
    fn category(&self) -> DetectorCategory {
        DetectorCategory::OwaspAgentic2026
    }
    fn default_severity(&self) -> Severity {
        Severity::Info
    }
    fn title(&self) -> &'static str {
        "OWASP Agentic 2026 compliance mapping (meta-detector)"
    }
    fn detect(&self, _g: &ar_core::AgentGraph) -> Vec<Finding> {
        // The mapping is applied as a post-process in `run_all`; this detector
        // intentionally emits nothing.
        Vec::new()
    }
}
