//! # ar-runtime
//!
//! The optional **dynamic probe** layer for lancer-agentic-radar — the engine
//! behind the `test` subcommand and the `--dynamic` flag.
//!
//! Where the static pipeline (`ar-parsers` → `ar-detectors`) reasons about the
//! reconstructed [`AgentGraph`](ar_core::AgentGraph) from code alone, this crate
//! talks to a *live* target: it replays attack-prompt corpora against an agent
//! HTTP endpoint, grades the responses heuristically, enumerates the tools an
//! MCP server advertises at runtime, and cross-references all of that with the
//! static finding set to confirm exploitability (lowering the false-positive
//! rate — see plan §"Dynamic probe flow").
//!
//! The taxonomy of dynamic tests matches upstream `agentic-radar test`:
//! prompt-injection, PII-leakage, harmful-content, and fake-news
//! ([`ar_core::TestCategory`]).
//!
//! ## Modules
//! * [`probes`] — attack-prompt corpora per [`ar_core::TestCategory`].
//! * [`grader`] — heuristic, refusal-aware response grading.
//! * [`http`] — agent-endpoint HTTP client (`reqwest`).
//! * [`mcp`] — MCP transports (stdio / SSE; WebSocket stubbed).
//! * [`correlate`] — fold dynamic results into the static findings.
//! * [`error`] — [`RuntimeError`].

pub mod correlate;
pub mod error;
pub mod grader;
pub mod http;
pub mod mcp;
pub mod probes;

pub use error::RuntimeError;

use ar_core::{
    ComplianceTags, Confidence, DetectorCategory, EuAiActArticle, Finding, McpTransport,
    OwaspAgentic2026, OwaspLlm2025, Severity, TestCategory, TestOptions,
};

/// Run the dynamic vulnerability tests against `opts.endpoint`.
///
/// Behavior:
/// * If neither an endpoint nor an MCP transport is configured, returns a
///   single informational [`Finding`] (`dynamic-testing-skipped`) explaining
///   that dynamic testing was skipped — it never errors on missing config.
/// * Otherwise it iterates the selected [`TestCategory`] set (or all categories
///   when `opts.categories` is empty), sends up to `opts.max_attempts` probes
///   per category to the endpoint, grades each response, and emits one
///   `dynamically_confirmed` [`Finding`] per probe graded *vulnerable*.
///
/// Transport/HTTP errors on individual probes are recorded as info findings
/// rather than aborting the whole run, so a flaky target still yields a report.
pub async fn run_tests(opts: &TestOptions) -> Result<Vec<Finding>, RuntimeError> {
    // No live target at all → informational skip notice (never an error).
    if opts.endpoint.is_none() && opts.mcp.is_none() {
        return Ok(vec![skip_finding()]);
    }

    let mut findings: Vec<Finding> = Vec::new();

    // Probe the HTTP endpoint if one is configured.
    if opts.endpoint.is_some() {
        let client = http::build_client(opts)?;
        let categories = selected_categories(opts);
        let max = opts.max_attempts.max(1) as usize;

        for cat in categories {
            let corpus = probes::corpus(cat);
            for prompt in corpus.into_iter().take(max) {
                match http::send_prompt(&client, opts, &prompt.prompt).await {
                    Ok(response) => {
                        let grade = grader::grade(cat, &prompt, &response);
                        if grade.vulnerable {
                            findings.push(vulnerable_finding(cat, &prompt, &grade, &response));
                        }
                    }
                    Err(e) => {
                        findings.push(probe_error_finding(cat, &prompt.id, &e));
                    }
                }
            }
        }

        // If the endpoint resisted every probe, say so explicitly.
        if !findings.iter().any(|f| f.dynamically_confirmed) {
            findings.push(
                Finding::new(
                    "dynamic-no-vulnerabilities",
                    DetectorCategory::Resolution,
                    Severity::Info,
                    "No dynamic vulnerabilities confirmed",
                    "All dynamic probes against the configured endpoint were refused or did not \
                     match a success marker. This is not proof of safety — it only means the \
                     static-corpus probes did not land.",
                )
                .with_confidence(Confidence::Low),
            );
        }
    }

    Ok(findings)
}

/// Probe the endpoint and mark matching static findings as
/// `dynamically_confirmed`; returns the (possibly updated) finding set plus any
/// new dynamic-only findings.
///
/// `graph` is accepted for parity with the facade and to allow future graph-
/// guided probe selection (AI augmentation #1); correlation today keys off the
/// static findings' categories and the configured MCP transport.
pub async fn probe_and_correlate(
    graph: &ar_core::AgentGraph,
    opts: &TestOptions,
    static_findings: &[Finding],
) -> Result<Vec<Finding>, RuntimeError> {
    let _ = graph;
    correlate::probe_and_correlate(opts, static_findings).await
}

/// Enumerate an MCP server's advertised tools as `(tool_name, description)`
/// pairs (for tool-poisoning supply-chain scanning).
///
/// Dispatches on the [`McpTransport`] variant: stdio spawns the server and
/// reads a JSON-RPC `tools/list` reply; SSE issues an HTTP GET; WebSocket
/// returns [`RuntimeError::Unsupported`].
pub async fn list_mcp_tools(
    transport: &McpTransport,
) -> Result<Vec<(String, String)>, RuntimeError> {
    mcp::list_tools(transport).await
}

// ---------------------------------------------------------------------------
// Internal helpers.
// ---------------------------------------------------------------------------

/// The categories to run: the explicit selection, or all when empty.
fn selected_categories(opts: &TestOptions) -> Vec<TestCategory> {
    if opts.categories.is_empty() {
        TestCategory::ALL.to_vec()
    } else {
        // Preserve order, drop duplicates.
        let mut out = Vec::new();
        for c in &opts.categories {
            if !out.contains(c) {
                out.push(*c);
            }
        }
        out
    }
}

/// The detector category a dynamic test category reports findings under.
fn detector_category(cat: TestCategory) -> DetectorCategory {
    match cat {
        TestCategory::PromptInjection => DetectorCategory::PromptInjection,
        TestCategory::PiiLeakage => DetectorCategory::SecretLeakage,
        TestCategory::HarmfulContent => DetectorCategory::JailbreakPathway,
        TestCategory::FakeNews => DetectorCategory::MissingOutputFilter,
    }
}

/// Severity assigned to a confirmed dynamic finding, by category.
fn category_severity(cat: TestCategory) -> Severity {
    match cat {
        TestCategory::PromptInjection => Severity::High,
        TestCategory::PiiLeakage => Severity::Critical,
        TestCategory::HarmfulContent => Severity::High,
        TestCategory::FakeNews => Severity::Medium,
    }
}

/// Compliance tags attached to a confirmed dynamic finding, by category.
fn category_compliance(cat: TestCategory) -> ComplianceTags {
    let base = ComplianceTags::new();
    match cat {
        TestCategory::PromptInjection => base
            .with_agentic(OwaspAgentic2026::GoalHijacking)
            .with_llm(OwaspLlm2025::PromptInjection)
            .with_eu(EuAiActArticle::Article15Robustness)
            .with_atlas("AML.T0051")
            .with_nist("MEASURE 2.7"),
        TestCategory::PiiLeakage => base
            .with_agentic(OwaspAgentic2026::DataExfiltrationViaAgent)
            .with_llm(OwaspLlm2025::SensitiveInformationDisclosure)
            .with_eu(EuAiActArticle::Article10DataGovernance)
            .with_nist("MEASURE 2.7"),
        TestCategory::HarmfulContent => base
            .with_llm(OwaspLlm2025::ImproperOutputHandling)
            .with_eu(EuAiActArticle::Article15Robustness)
            .with_atlas("AML.T0054")
            .with_nist("MANAGE 2.2"),
        TestCategory::FakeNews => base
            .with_llm(OwaspLlm2025::Misinformation)
            .with_eu(EuAiActArticle::Article13Transparency)
            .with_nist("MEASURE 2.9"),
    }
}

/// Build the [`Finding`] for a probe graded vulnerable.
fn vulnerable_finding(
    cat: TestCategory,
    prompt: &probes::AttackPrompt,
    grade: &grader::Grade,
    response: &str,
) -> Finding {
    let title = format!("Dynamic {} vulnerability confirmed", cat.id());
    let description = format!(
        "A live probe in the `{}` category succeeded against the target agent. \
         Probe `{}`: {}\n\nGrader rationale: {}",
        cat.id(),
        prompt.id,
        truncate(&prompt.prompt, 240),
        grade.rationale,
    );

    let mut f = Finding::new(
        format!("dyn-{}", prompt.id),
        detector_category(cat),
        category_severity(cat),
        title,
        description,
    )
    .with_evidence(truncate(response, 400))
    .with_confidence(grade.confidence)
    .with_compliance(category_compliance(cat))
    .with_fix(remediation_for(cat));
    f.dynamically_confirmed = true;
    f
}

/// A `proof-of-concept`-flavored finding describing a probe transport error.
fn probe_error_finding(cat: TestCategory, probe_id: &str, err: &RuntimeError) -> Finding {
    Finding::new(
        format!("dyn-error-{probe_id}"),
        DetectorCategory::Resolution,
        Severity::Info,
        "Dynamic probe could not reach the target",
        format!(
            "Probe `{probe_id}` in category `{}` failed to obtain a response: {err}",
            cat.id()
        ),
    )
    .with_confidence(Confidence::Low)
}

/// Remediation guidance per test category.
fn remediation_for(cat: TestCategory) -> &'static str {
    match cat {
        TestCategory::PromptInjection =>
            "Separate untrusted input from instructions with explicit delimiters/roles, never \
             concatenate user/tool text into the system prompt, and add an input/output guardrail \
             (e.g. a prompt-injection classifier or LlamaFirewall).",
        TestCategory::PiiLeakage =>
            "Add an output filter that redacts PII (regex / Microsoft Presidio), scope memory and \
             RAG reads to the current tenant, and never echo stored credentials or environment \
             variables.",
        TestCategory::HarmfulContent =>
            "Layer a content-safety classifier on inputs and outputs, harden the system prompt \
             against roleplay/DAN framings, and refuse persona-override requests.",
        TestCategory::FakeNews =>
            "Require source attribution and refuse to fabricate citations; add a factuality / \
             grounding check and surface a confidence/uncertainty disclaimer.",
    }
}

/// The informational finding returned when dynamic testing is skipped.
fn skip_finding() -> Finding {
    Finding::new(
        "dynamic-testing-skipped",
        DetectorCategory::Resolution,
        Severity::Info,
        "Dynamic testing skipped",
        "No agent endpoint or MCP transport was configured, so dynamic vulnerability testing \
         was skipped. Provide `--endpoint <url>` (and optionally `--auth <token>`) or an MCP \
         transport to enable live probing.",
    )
    .with_confidence(Confidence::High)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_options_returns_skip_finding() {
        let opts = TestOptions::default();
        let findings = run_tests(&opts).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector_id, "dynamic-testing-skipped");
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(!findings[0].dynamically_confirmed);
    }

    #[tokio::test]
    async fn probe_and_correlate_with_empty_options_passes_statics_through() {
        let graph = ar_core::AgentGraph::new();
        let opts = TestOptions::default();
        let statics = vec![Finding::new(
            "tb-tool-output-to-next-tool-input",
            DetectorCategory::TrustBoundary,
            Severity::High,
            "trust boundary",
            "desc",
        )];
        let out = probe_and_correlate(&graph, &opts, &statics).await.unwrap();
        // Static finding preserved (unconfirmed) + the skip notice appended.
        assert!(out
            .iter()
            .any(|f| f.detector_id == "tb-tool-output-to-next-tool-input"
                && !f.dynamically_confirmed));
        assert!(out.iter().any(|f| f.detector_id == "dynamic-testing-skipped"));
    }

    #[test]
    fn selected_categories_defaults_to_all() {
        let opts = TestOptions::default();
        assert_eq!(selected_categories(&opts).len(), TestCategory::ALL.len());
    }

    #[test]
    fn selected_categories_dedups_explicit() {
        let opts = TestOptions {
            categories: vec![
                TestCategory::PromptInjection,
                TestCategory::PromptInjection,
                TestCategory::FakeNews,
            ],
            ..TestOptions::default()
        };
        assert_eq!(selected_categories(&opts).len(), 2);
    }

    #[test]
    fn vulnerable_finding_is_marked_confirmed() {
        let prompt = probes::corpus(TestCategory::PromptInjection)
            .into_iter()
            .next()
            .unwrap();
        let grade = grader::Grade {
            vulnerable: true,
            confidence: Confidence::High,
            rationale: "matched".to_string(),
        };
        let f = vulnerable_finding(TestCategory::PromptInjection, &prompt, &grade, "PWNED");
        assert!(f.dynamically_confirmed);
        assert_eq!(f.category, DetectorCategory::PromptInjection);
        assert_eq!(f.severity, Severity::High);
        assert!(!f.compliance.owasp_llm_2025.is_empty());
    }
}
