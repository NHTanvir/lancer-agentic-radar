//! Upstream-parity tests: scan every bundled reference target, run the full
//! detector suite, and confirm every report format renders. Pins the public
//! facades the workspace exposes.

use std::path::PathBuf;

use ar_core::{Config, ParseOptions, Report, ReportFormat, ScanMeta};

fn targets_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("tests")
        .join("upstream_parity")
        .join("targets")
}

fn target_subdirs() -> Vec<PathBuf> {
    let dir = targets_dir();
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            if e.path().is_dir() {
                out.push(e.path());
            }
        }
    }
    out.sort();
    out
}

#[test]
fn reference_targets_present() {
    let subdirs = target_subdirs();
    assert!(
        subdirs.len() >= 10,
        "expected ≥10 framework reference targets, found {} in {}",
        subdirs.len(),
        targets_dir().display()
    );
}

#[test]
fn every_target_scans_without_panic() {
    let opts = ParseOptions::default();
    for dir in target_subdirs() {
        let graph = ar_parsers::scan_path(&dir, &opts)
            .unwrap_or_else(|e| panic!("scan_path failed for {}: {e}", dir.display()));
        // Each target should reconstruct at least one node.
        assert!(
            graph.node_count() > 0,
            "no nodes reconstructed for {}",
            dir.display()
        );
    }
}

#[test]
fn detectors_run_and_all_formats_render() {
    let opts = ParseOptions::default();
    let cfg = Config::default();
    for dir in target_subdirs() {
        let mut graph = ar_parsers::scan_path(&dir, &opts).expect("scan");
        graph.propagate_trust();
        let findings = ar_detectors::run_all(&graph, &cfg);

        let report = Report::new(
            ScanMeta {
                tool_version: "test".into(),
                scanned_path: dir.clone(),
                ..Default::default()
            },
            graph,
            findings,
        );

        for fmt in ReportFormat::ALL {
            let out = ar_report::render(&report, fmt);
            assert!(
                !out.is_empty(),
                "{} render empty for {}",
                fmt.id(),
                dir.display()
            );
        }
        // Mermaid + DOT emit.
        assert!(ar_report::mermaid(&report.graph).contains("flowchart"));
        assert!(ar_report::dot(&report.graph).contains("digraph"));
    }
}

#[test]
fn self_test_matrix_passes() {
    // The bundled parity matrix should be green.
    let code = lancer_agentic_radar::selftest::run().expect("self-test run");
    assert_eq!(code, 0, "self-test reported failures");
}
