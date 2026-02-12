//! Command-line surface (clap). Mirrors upstream `agentic-radar`'s `scan` /
//! `test` subcommands and `--harden-prompts`, plus Lancer extras
//! (`list-detectors`, `self-test`, `gui`).

use std::path::PathBuf;

use anyhow::Context;
use ar_core::{
    Config, Framework, HardenOptions, McpTransport, ParseOptions, ReportFormat, Report,
    TestCategory, TestOptions,
};
use clap::{ArgAction, Args, Parser, Subcommand};

use crate::config_load::{load_config, merge_cli};
use crate::pipeline::{self, ScanRequest};

#[derive(Parser, Debug)]
#[command(
    name = "lancer-agentic-radar",
    version,
    about = "Security scanner for agentic AI workflows (Rust clone of agentic-radar + native GUI)",
    long_about = "Reconstructs the tool graph of an agentic AI workflow (LangChain, LangGraph, \
                  CrewAI, AutoGen, Semantic Kernel, Vercel AI SDK, Pydantic AI, OpenAI \
                  Assistants, OpenAI Agents SDK, Anthropic Computer Use, MCP, n8n), runs static \
                  + optional dynamic security checks, and emits JSON/SARIF/Markdown/HTML reports \
                  with a Mermaid/DOT graph.\n\nRun with no subcommand to open the native GUI; pass \
                  --cli or a subcommand for the command-line surface."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub global: GlobalArgs,
}

#[derive(Args, Debug, Default)]
pub struct GlobalArgs {
    /// Force the CLI surface (do not open the GUI) even with no subcommand.
    #[arg(long, global = true)]
    pub cli: bool,

    /// Increase logging verbosity (-v info, -vv debug, -vvv trace).
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Path to a config file (ar.toml or *.yaml).
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Run the upstream-parity self-test matrix and exit.
    #[arg(long = "self-test", global = true)]
    pub self_test: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Static analysis of an agent workflow (reconstruct graph + run detectors).
    Scan(ScanArgs),
    /// Dynamic vulnerability testing against a live agent / MCP endpoint.
    Test(TestArgs),
    /// Rewrite weak system prompts into a defensive, hardened form.
    HardenPrompts(HardenArgs),
    /// List every detector sub-check and exit.
    ListDetectors,
    /// Run the upstream-parity self-test matrix.
    SelfTest,
    /// Launch the native GUI.
    Gui,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Path to the agent project / file to scan (positional; defaults to ".").
    pub path: Option<PathBuf>,

    /// Input directory/file (alias for the positional path).
    #[arg(short = 'i', long)]
    pub input: Option<PathBuf>,

    /// Write the report to this file (extension picked from --report-format).
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Force a specific framework (skip auto-detection).
    #[arg(long)]
    pub framework: Option<String>,

    /// Report format(s): json, sarif, md, html (comma-separated / repeatable).
    #[arg(long = "report-format", value_delimiter = ',', default_value = "json")]
    pub report_format: Vec<String>,

    /// Compliance mapping(s) to include: owasp-agentic-top10-2026,
    /// owasp-llm-top10-2025, owasp-aivss, eu-ai-act, nist-ai-rmf, csa-aicm,
    /// mitre-atlas.
    #[arg(long = "compliance-mode", value_delimiter = ',')]
    pub compliance_mode: Vec<String>,

    /// Exit non-zero if findings of these severities exist (e.g. critical,high).
    #[arg(long = "fail-on", value_delimiter = ',')]
    pub fail_on: Vec<String>,

    /// Exclude detector ids/categories (comma-separated / repeatable).
    #[arg(long = "exclude", value_delimiter = ',')]
    pub exclude: Vec<String>,

    /// Only report findings NOT present in this baseline (json/sarif).
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// Only parse MCP manifests.
    #[arg(long = "mcp-only")]
    pub mcp_only: bool,

    /// Also run the dynamic probe and cross-correlate (needs --endpoint).
    #[arg(long)]
    pub dynamic: bool,

    /// Generate hardened-prompt rewrites for eligible findings.
    #[arg(long = "harden-prompts")]
    pub harden_prompts: bool,

    /// Live agent endpoint URL (for --dynamic).
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Bearer/auth token for the endpoint.
    #[arg(long)]
    pub auth: Option<String>,

    /// MCP endpoint (stdio:///path, sse://url, ws://url) for --dynamic.
    #[arg(long = "mcp-endpoint")]
    pub mcp_endpoint: Option<String>,

    /// Also write Mermaid (.mmd) and DOT (.dot) graph files next to --output.
    #[arg(long = "emit-graph")]
    pub emit_graph: bool,

    /// Print the Mermaid graph to stdout instead of a report.
    #[arg(long = "graph-only")]
    pub graph_only: bool,
}

#[derive(Args, Debug)]
pub struct TestArgs {
    /// Optional path to also build a static graph for cross-correlation.
    pub path: Option<PathBuf>,

    /// Live agent endpoint URL.
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Bearer/auth token.
    #[arg(long)]
    pub auth: Option<String>,

    /// MCP endpoint (stdio:///path, sse://url, ws://url).
    #[arg(long = "mcp-endpoint")]
    pub mcp_endpoint: Option<String>,

    /// Test categories: prompt-injection, pii-leakage, harmful-content,
    /// fake-news (default: all).
    #[arg(long = "test-categories", value_delimiter = ',')]
    pub test_categories: Vec<String>,

    /// Max attack prompts per category.
    #[arg(long = "max-attempts", default_value_t = 8)]
    pub max_attempts: u32,

    /// OTEL trace collector endpoint to consume tool-call telemetry.
    #[arg(long = "otel-endpoint")]
    pub otel_endpoint: Option<String>,

    /// Report format(s).
    #[arg(long = "report-format", value_delimiter = ',', default_value = "json")]
    pub report_format: Vec<String>,

    /// Write the report to this file.
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct HardenArgs {
    /// Path to the agent project / file.
    pub path: Option<PathBuf>,

    /// LLM model id for online hardening.
    #[arg(long, default_value = "claude-opus-4-8")]
    pub model: String,

    /// OpenAI-compatible API base URL for online hardening.
    #[arg(long = "api-base")]
    pub api_base: Option<String>,

    /// Use the online LLM rewriter (default is the offline rule-based engine).
    #[arg(long)]
    pub online: bool,

    /// Write the hardened prompts to this file (json/markdown by extension).
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}

/// Entry point shared by both binaries.
pub fn run(cli: Cli) -> anyhow::Result<i32> {
    match cli.command {
        Some(Command::Scan(a)) => cmd_scan(a, &cli.global),
        Some(Command::Test(a)) => cmd_test(a, &cli.global),
        Some(Command::HardenPrompts(a)) => cmd_harden(a, &cli.global),
        Some(Command::ListDetectors) => {
            cmd_list_detectors();
            Ok(0)
        }
        Some(Command::SelfTest) => crate::selftest::run(),
        Some(Command::Gui) => {
            crate::gui::launch()?;
            Ok(0)
        }
        None => {
            print_help();
            Ok(2)
        }
    }
}

pub fn print_help() {
    use clap::CommandFactory;
    let _ = Cli::command().print_help();
    println!();
}

fn resolve_input(path: Option<PathBuf>, input: Option<PathBuf>) -> PathBuf {
    path.or(input).unwrap_or_else(|| PathBuf::from("."))
}

fn parse_formats(formats: &[String]) -> anyhow::Result<Vec<ReportFormat>> {
    let mut out = Vec::new();
    for f in formats {
        for part in f.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let rf: ReportFormat = part
                .parse()
                .map_err(|e| anyhow::anyhow!("--report-format: {e}"))?;
            if !out.contains(&rf) {
                out.push(rf);
            }
        }
    }
    if out.is_empty() {
        out.push(ReportFormat::Json);
    }
    Ok(out)
}

/// Parse an MCP endpoint string into a transport.
pub fn parse_mcp_endpoint(s: &str) -> anyhow::Result<McpTransport> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("stdio://") {
        Ok(McpTransport::Stdio(rest.to_string()))
    } else if let Some(rest) = s.strip_prefix("stdio:") {
        Ok(McpTransport::Stdio(rest.to_string()))
    } else if s.starts_with("sse://") || s.starts_with("http://") || s.starts_with("https://") {
        Ok(McpTransport::Sse(s.to_string()))
    } else if s.starts_with("ws://") || s.starts_with("wss://") {
        Ok(McpTransport::WebSocket(s.to_string()))
    } else {
        // Bare path → stdio subprocess.
        Ok(McpTransport::Stdio(s.to_string()))
    }
}

fn parse_test_categories(items: &[String]) -> anyhow::Result<Vec<TestCategory>> {
    let mut out = Vec::new();
    for s in items {
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let c: TestCategory = part
                .parse()
                .map_err(|e| anyhow::anyhow!("--test-categories: {e}"))?;
            out.push(c);
        }
    }
    Ok(out)
}

fn cmd_scan(a: ScanArgs, g: &GlobalArgs) -> anyhow::Result<i32> {
    let input = resolve_input(a.path.clone(), a.input.clone());
    let mut config: Config = load_config(g.config.as_deref(), &input)?;
    config = merge_cli(config, &a.fail_on, &a.compliance_mode, &a.exclude)?;

    let framework = match &a.framework {
        Some(s) => Some(s.parse::<Framework>().map_err(|e| anyhow::anyhow!(e))?),
        None => None,
    };

    let mut test_opts = TestOptions {
        endpoint: a.endpoint.clone(),
        auth: a.auth.clone(),
        ..TestOptions::default()
    };
    if let Some(m) = &a.mcp_endpoint {
        test_opts.mcp = Some(parse_mcp_endpoint(m)?);
    }

    let parse_opts = ParseOptions {
        framework,
        mcp_only: a.mcp_only,
        trust: config.trust.clone(),
        ..ParseOptions::default()
    };

    let req = ScanRequest {
        input: input.clone(),
        framework,
        config: config.clone(),
        parse_opts,
        dynamic: a.dynamic,
        harden: a.harden_prompts,
        test_opts,
        harden_opts: HardenOptions::default(),
    };

    let mut report = pipeline::run_scan(&req).context("scan failed")?;

    if let Some(baseline) = &a.baseline {
        let n = pipeline::apply_baseline(&mut report, baseline)?;
        eprintln!("baseline: suppressed {n} already-known finding(s)");
    }

    if a.graph_only {
        println!("{}", ar_report::mermaid(&report.graph));
        return Ok(0);
    }

    let formats = parse_formats(&a.report_format)?;
    emit_report(&report, &formats, a.output.as_deref(), a.emit_graph)?;

    print_summary(&report);

    // Exit code for CI.
    if config.should_fail(report.present_severities()) {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn cmd_test(a: TestArgs, g: &GlobalArgs) -> anyhow::Result<i32> {
    let input = a.path.clone();
    let root = input.clone().unwrap_or_else(|| PathBuf::from("."));
    let config = load_config(g.config.as_deref(), &root)?;

    let mut opts = TestOptions {
        endpoint: a.endpoint.clone(),
        auth: a.auth.clone(),
        categories: parse_test_categories(&a.test_categories)?,
        max_attempts: a.max_attempts,
        otel_endpoint: a.otel_endpoint.clone(),
        ..TestOptions::default()
    };
    if let Some(m) = &a.mcp_endpoint {
        opts.mcp = Some(parse_mcp_endpoint(m)?);
    }

    let report = pipeline::run_test(input.as_deref(), &opts, &config)?;
    let formats = parse_formats(&a.report_format)?;
    emit_report(&report, &formats, a.output.as_deref(), false)?;
    print_summary(&report);
    Ok(0)
}

fn cmd_harden(a: HardenArgs, g: &GlobalArgs) -> anyhow::Result<i32> {
    let input = a.path.clone().unwrap_or_else(|| PathBuf::from("."));
    let config = load_config(g.config.as_deref(), &input)?;
    let parse_opts = ParseOptions {
        trust: config.trust.clone(),
        ..ParseOptions::default()
    };
    let mut graph =
        ar_parsers::scan_path(&input, &parse_opts).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    graph.propagate_trust();

    let opts = HardenOptions {
        model: a.model.clone(),
        api_base: a.api_base.clone(),
        offline: !a.online,
    };

    let hardened = if a.online {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async { ar_hardening::harden_graph_llm(&graph, &opts).await })
            .map_err(|e| anyhow::anyhow!("hardening: {e}"))?
    } else {
        ar_hardening::harden_graph(&graph, &opts)
    };

    let rendered = render_hardened(&hardened, a.output.as_deref());
    match &a.output {
        Some(path) => {
            std::fs::write(path, &rendered)?;
            eprintln!("wrote {} hardened prompt(s) → {}", hardened.len(), path.display());
        }
        None => println!("{rendered}"),
    }
    Ok(0)
}

fn render_hardened(
    hardened: &[ar_hardening::HardenedPrompt],
    output: Option<&std::path::Path>,
) -> String {
    let as_md = output
        .and_then(|p| p.extension())
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("md"))
        .unwrap_or(false);
    if as_md {
        let mut s = String::from("# Hardened Prompts\n\n");
        for h in hardened {
            s.push_str(&format!(
                "## {} ({})\n\n**Before** (score {}/4):\n\n```\n{}\n```\n\n**After** (score {}/4):\n\n```\n{}\n```\n\n",
                h.agent_name,
                h.framework.display_name(),
                h.rubric_before.score(),
                h.original,
                h.rubric_after.score(),
                h.hardened
            ));
        }
        s
    } else {
        // JSON view
        let arr: Vec<serde_json::Value> = hardened
            .iter()
            .map(|h| {
                serde_json::json!({
                    "agent": h.agent.as_str(),
                    "agent_name": h.agent_name,
                    "framework": h.framework.id(),
                    "score_before": h.rubric_before.score(),
                    "score_after": h.rubric_after.score(),
                    "original": h.original,
                    "hardened": h.hardened,
                })
            })
            .collect();
        serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".into())
    }
}

fn cmd_list_detectors() {
    let reg = ar_detectors::registry();
    println!("{} detector sub-checks registered:\n", reg.len());
    println!("{:<40} {:<24} {}", "ID", "CATEGORY", "SEVERITY");
    println!("{}", "-".repeat(80));
    for d in &reg {
        println!(
            "{:<40} {:<24} {}",
            d.id,
            d.category.id(),
            d.default_severity.as_str()
        );
    }
}

/// Render each requested format and write to disk (or stdout if no --output).
fn emit_report(
    report: &Report,
    formats: &[ReportFormat],
    output: Option<&std::path::Path>,
    emit_graph: bool,
) -> anyhow::Result<()> {
    match output {
        None => {
            // Print the first (primary) format to stdout.
            let primary = formats[0];
            println!("{}", ar_report::render(report, primary));
        }
        Some(path) => {
            for (i, fmt) in formats.iter().enumerate() {
                let target = if formats.len() == 1 {
                    path.to_path_buf()
                } else {
                    path.with_extension(fmt.extension())
                };
                let rendered = ar_report::render(report, *fmt);
                std::fs::write(&target, rendered)
                    .with_context(|| format!("writing {}", target.display()))?;
                eprintln!("wrote {} report → {}", fmt.id(), target.display());
                let _ = i;
            }
            if emit_graph {
                let mmd = path.with_extension("mmd");
                let dot = path.with_extension("dot");
                std::fs::write(&mmd, ar_report::mermaid(&report.graph))?;
                std::fs::write(&dot, ar_report::dot(&report.graph))?;
                eprintln!("wrote graph → {} / {}", mmd.display(), dot.display());
            }
        }
    }
    Ok(())
}

fn print_summary(report: &Report) {
    let counts = report.severity_counts();
    let total: usize = counts.values().sum();
    eprintln!(
        "\nScanned {} — {} agent(s), {} tool(s), {} finding(s).",
        report.meta.scanned_path.display(),
        report.stats.agents,
        report.stats.tools,
        total
    );
    for sev in ar_core::Severity::ALL.iter().rev() {
        if let Some(n) = counts.get(sev) {
            if *n > 0 {
                eprintln!("  {:<9} {}", format!("{}:", sev.as_str()), n);
            }
        }
    }
}
