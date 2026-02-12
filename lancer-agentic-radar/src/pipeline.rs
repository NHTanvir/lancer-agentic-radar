//! Shared scan / test / harden orchestration used by both the CLI and the GUI.
//!
//! This is the one place that wires the library crates together:
//! `ar_parsers` → `ar_detectors` → (`ar_hardening`) → (`ar_runtime`) →
//! `ar_report`. Keeping it framework-agnostic means the GUI is a true alternate
//! frontend over the same code path as the CLI.

use std::path::{Path, PathBuf};

use ar_core::{
    AgentGraph, Config, Framework, HardenOptions, ParseOptions, Report, ScanMeta, TestOptions,
};

/// A fully-resolved request to perform a static scan (optionally augmented with
/// hardening and a dynamic probe).
#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub input: PathBuf,
    pub framework: Option<Framework>,
    pub config: Config,
    pub parse_opts: ParseOptions,
    pub dynamic: bool,
    pub harden: bool,
    pub test_opts: TestOptions,
    pub harden_opts: HardenOptions,
}

impl ScanRequest {
    /// A plain static scan of `input` with default everything.
    pub fn new(input: impl Into<PathBuf>) -> Self {
        ScanRequest {
            input: input.into(),
            framework: None,
            config: Config::default(),
            parse_opts: ParseOptions::default(),
            dynamic: false,
            harden: false,
            test_opts: TestOptions::default(),
            harden_opts: HardenOptions::default(),
        }
    }
}

/// Current UTC timestamp as an RFC-3339 string (ar-core stays clock-free, so the
/// frontend stamps the time).
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Run the full static (and optional dynamic/hardening) pipeline.
pub fn run_scan(req: &ScanRequest) -> anyhow::Result<Report> {
    // 1. Parse → uniform AgentGraph.
    let mut parse_opts = req.parse_opts.clone();
    parse_opts.framework = req.framework;
    parse_opts.trust = req.config.trust.clone();
    let mut graph: AgentGraph = ar_parsers::scan_path(&req.input, &parse_opts)
        .map_err(|e| anyhow::anyhow!("parse failed: {e}"))?;

    // 2. Trust-label propagation across edges.
    graph.propagate_trust();

    // 3. Static detectors.
    let mut findings = ar_detectors::run_all(&graph, &req.config);

    // 4. Optional prompt hardening — attach candidate rewrites to the relevant
    //    findings as remediation patches.
    let mut hardened = Vec::new();
    if req.harden {
        hardened = ar_hardening::harden_graph(&graph, &req.harden_opts);
        attach_hardening(&mut findings, &hardened);
    }

    // 5. Optional dynamic probe + cross-correlation.
    if req.dynamic {
        let rt = tokio::runtime::Runtime::new()?;
        findings = rt.block_on(async {
            ar_runtime::probe_and_correlate(&graph, &req.test_opts, &findings).await
        })
        .map_err(|e| anyhow::anyhow!("dynamic probe failed: {e}"))?;
    }

    // 6. Assemble the report.
    let detected = ar_parsers::detect_frameworks(&req.input);
    let meta = ScanMeta {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        scanned_path: req.input.clone(),
        framework: req.framework,
        frameworks_detected: detected,
        timestamp: Some(now_rfc3339()),
        dynamic: req.dynamic,
        hardened: req.harden,
        compliance_modes: req.config.compliance_modes.clone(),
    };

    let report = Report::new(meta, graph, findings);
    Ok(report)
}

/// Run a dynamic-only test (the `test` subcommand). If `input` exists, a static
/// graph is built first so dynamic results can be cross-correlated.
pub fn run_test(input: Option<&Path>, opts: &TestOptions, config: &Config) -> anyhow::Result<Report> {
    let rt = tokio::runtime::Runtime::new()?;
    let (graph, findings) = if let Some(p) = input.filter(|p| p.exists()) {
        let parse_opts = ParseOptions {
            trust: config.trust.clone(),
            ..ParseOptions::default()
        };
        let mut g = ar_parsers::scan_path(p, &parse_opts)
            .map_err(|e| anyhow::anyhow!("parse failed: {e}"))?;
        g.propagate_trust();
        let statics = ar_detectors::run_all(&g, config);
        let dynamic = rt
            .block_on(async { ar_runtime::probe_and_correlate(&g, opts, &statics).await })
            .map_err(|e| anyhow::anyhow!("dynamic probe failed: {e}"))?;
        (g, dynamic)
    } else {
        let dynamic = rt
            .block_on(async { ar_runtime::run_tests(opts).await })
            .map_err(|e| anyhow::anyhow!("dynamic test failed: {e}"))?;
        (AgentGraph::new(), dynamic)
    };

    let meta = ScanMeta {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        scanned_path: input.map(|p| p.to_path_buf()).unwrap_or_default(),
        framework: None,
        frameworks_detected: Vec::new(),
        timestamp: Some(now_rfc3339()),
        dynamic: true,
        hardened: false,
        compliance_modes: config.compliance_modes.clone(),
    };
    Ok(Report::new(meta, graph, findings))
}

/// Attach hardened-prompt rewrites to `prompt-hardening-needed` findings on the
/// matching agent (and as a general fallback, any finding referencing that
/// agent that lacks a remediation patch).
fn attach_hardening(findings: &mut [ar_core::Finding], hardened: &[ar_hardening::HardenedPrompt]) {
    for h in hardened {
        for f in findings.iter_mut() {
            if f.agent.as_ref() == Some(&h.agent)
                && f.category == ar_core::DetectorCategory::PromptHardeningNeeded
                && f.remediation_patch.is_none()
            {
                f.remediation_patch = Some(h.hardened.clone());
            }
        }
    }
}

/// Filter a report's findings down to those NOT present in a baseline file
/// (matched by fingerprint), for `--baseline` diff mode. Returns how many were
/// suppressed as "already known".
pub fn apply_baseline(report: &mut Report, baseline_path: &Path) -> anyhow::Result<usize> {
    let text = std::fs::read_to_string(baseline_path)?;
    let known = extract_fingerprints(&text);
    let before = report.findings.len();
    for f in report.findings.iter_mut() {
        if known.contains(&f.fingerprint()) {
            f.suppressed = true;
        }
    }
    let suppressed = report.findings.iter().filter(|f| f.suppressed).count();
    let _ = before;
    Ok(suppressed)
}

/// Best-effort extraction of finding fingerprints from a prior JSON or SARIF
/// baseline.
fn extract_fingerprints(text: &str) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        collect_fingerprints(&v, &mut set);
    }
    set
}

fn collect_fingerprints(v: &serde_json::Value, set: &mut std::collections::HashSet<String>) {
    match v {
        serde_json::Value::Object(map) => {
            // SARIF: results[].partialFingerprints.primary
            if let Some(pf) = map.get("partialFingerprints").and_then(|p| p.get("primary")) {
                if let Some(s) = pf.as_str() {
                    set.insert(s.to_string());
                }
            }
            for (_, child) in map {
                collect_fingerprints(child, set);
            }
        }
        serde_json::Value::Array(arr) => {
            for child in arr {
                collect_fingerprints(child, set);
            }
        }
        _ => {}
    }
}
