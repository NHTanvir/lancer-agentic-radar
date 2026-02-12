//! Excessive-authority sub-checks (plan §"Detector catalog" item 6).
//!
//! These flag tools whose effects grant dangerous authority without scoping:
//! shell exec without an allowlist, payment without 2FA, broadcast email,
//! unbounded network egress, write-anywhere filesystem, destructive DB deletes,
//! over-scoped cloud IAM, and computer-use without confirmation.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{
    DetectorCategory, EuAiActArticle, Finding, OwaspAgentic2026, OwaspLlm2025, Severity, ToolSource,
};

/// Does the tool's signature/description mention a scoping control?
fn mentions(t: &ar_core::ToolNode, needles: &[&str]) -> bool {
    let hay = format!(
        "{} {} {}",
        t.name,
        t.signature.as_deref().unwrap_or(""),
        t.description.as_deref().unwrap_or("")
    );
    contains_any(&hay, needles)
}

define_detectors! {
    /// Shell-exec tool with no command allowlist.
    EaShellToolWithoutAllowlist {
        id: "ea-shell-tool-without-allowlist",
        category: DetectorCategory::ExcessiveAuthority,
        severity: Severity::High,
        title: "Shell tool without command allowlist",
        detect: |g| {
            let mut out = Vec::new();
            for t in g.tools.iter().filter(|t| t.effects.shell_exec) {
                if mentions(t, &["allowlist", "whitelist", "allowed_commands", "shell=false", "shlex", "subprocess.run(["]) {
                    continue;
                }
                let f = Finding::new(
                    "ea-shell-tool-without-allowlist",
                    DetectorCategory::ExcessiveAuthority,
                    Severity::High,
                    "Shell tool without command allowlist",
                    format!(
                        "Tool `{}` executes shell commands with no detectable allowlist or \
                         non-shell execution. The agent can run arbitrary commands.",
                        t.name
                    ),
                )
                .with_tool(t.id.clone())
                .with_evidence(format!("effects=[{}] {}", t.effects.badges().join(","), tool_evidence(t)))
                .with_location(loc(&t.location))
                .with_fix(
                    "Replace shell execution with an allowlisted set of commands run via \
                     subprocess with shell=False and explicit, validated arguments.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_agentic(OwaspAgentic2026::UnsafeAutonomyEscalation)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                        .with_atlas("AML.T0050")
                }));
            }
            out
        }
    }

    /// Payment tool with no second-factor / confirmation gate.
    EaPaymentToolWithout2fa {
        id: "ea-payment-tool-without-2fa",
        category: DetectorCategory::ExcessiveAuthority,
        severity: Severity::Critical,
        title: "Payment tool without confirmation / 2FA",
        detect: |g| {
            let mut out = Vec::new();
            for t in g.tools.iter().filter(|t| t.effects.payment) {
                if mentions(t, &["2fa", "confirm", "approval", "otp", "mfa", "verify", "human"]) { continue; }
                let f = Finding::new(
                    "ea-payment-tool-without-2fa",
                    DetectorCategory::ExcessiveAuthority,
                    Severity::Critical,
                    "Payment tool without confirmation / 2FA",
                    format!(
                        "Tool `{}` can move money with no confirmation / second factor. An injected \
                         instruction could trigger an unauthorized payment autonomously.",
                        t.name
                    ),
                )
                .with_tool(t.id.clone())
                .with_evidence(tool_evidence(t))
                .with_location(loc(&t.location))
                .with_fix(
                    "Require an out-of-band human confirmation / 2FA before any payment, and cap \
                     per-transaction and per-day amounts.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::UnsafeAutonomyEscalation)
                        .with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                        .with_eu(EuAiActArticle::Article14HumanOversight)
                }));
            }
            out
        }
    }

    /// Email tool capable of broadcast without recipient scoping.
    EaEmailToolBroadcast {
        id: "ea-email-tool-broadcast",
        category: DetectorCategory::ExcessiveAuthority,
        severity: Severity::High,
        title: "Email tool without recipient allowlist",
        detect: |g| {
            let mut out = Vec::new();
            for t in g.tools.iter().filter(|t| t.effects.email) {
                if mentions(t, &["allowlist", "allowed_domains", "internal only", "recipient_allowlist", "confirm"]) { continue; }
                let f = Finding::new(
                    "ea-email-tool-broadcast",
                    DetectorCategory::ExcessiveAuthority,
                    Severity::High,
                    "Email tool without recipient allowlist",
                    format!(
                        "Tool `{}` can send email to arbitrary recipients with no domain/recipient \
                         allowlist. The agent could be steered into phishing or data exfiltration \
                         via email.",
                        t.name
                    ),
                )
                .with_tool(t.id.clone())
                .with_evidence(tool_evidence(t))
                .with_location(loc(&t.location))
                .with_fix(
                    "Restrict recipients to an allowlisted set of internal domains and require \
                     confirmation for external sends; rate-limit outbound mail.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::DataExfiltrationViaAgent)
                        .with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                        .with_llm(OwaspLlm2025::SensitiveInformationDisclosure)
                }));
            }
            out
        }
    }

    /// Network egress with no destination allowlist.
    EaNetworkEgressUnbounded {
        id: "ea-network-egress-unbounded",
        category: DetectorCategory::ExcessiveAuthority,
        severity: Severity::Medium,
        title: "Network egress without destination allowlist",
        detect: |g| {
            let mut out = Vec::new();
            for t in g.tools.iter().filter(|t| t.effects.net_egress) {
                if mentions(t, &["allowlist", "allowed_hosts", "allowed_domains", "ssrf", "block_private", "internal only"]) { continue; }
                let f = Finding::new(
                    "ea-network-egress-unbounded",
                    DetectorCategory::ExcessiveAuthority,
                    Severity::Medium,
                    "Network egress without destination allowlist",
                    format!(
                        "Tool `{}` makes outbound network requests with no destination allowlist. \
                         This is an SSRF / data-exfiltration channel under the agent's control.",
                        t.name
                    ),
                )
                .with_tool(t.id.clone())
                .with_evidence(tool_evidence(t))
                .with_location(loc(&t.location))
                .with_fix(
                    "Allowlist outbound destinations, block private/link-local ranges (SSRF), and \
                     log/limit egress volume.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::DataExfiltrationViaAgent)
                        .with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                }));
            }
            out
        }
    }

    /// Filesystem write with no path scoping.
    EaFsWriteAnywhere {
        id: "ea-fs-write-anywhere",
        category: DetectorCategory::ExcessiveAuthority,
        severity: Severity::High,
        title: "Filesystem write without path scoping",
        detect: |g| {
            let mut out = Vec::new();
            for t in g.tools.iter().filter(|t| t.effects.writes_fs) {
                if mentions(t, &["allowlist", "base_dir", "sandbox", "chroot", "jail", "safe_join", "resolve()", "within"]) { continue; }
                let f = Finding::new(
                    "ea-fs-write-anywhere",
                    DetectorCategory::ExcessiveAuthority,
                    Severity::High,
                    "Filesystem write without path scoping",
                    format!(
                        "Tool `{}` writes to the filesystem with no base-directory scoping or path \
                         traversal protection, so it can overwrite arbitrary files.",
                        t.name
                    ),
                )
                .with_tool(t.id.clone())
                .with_evidence(tool_evidence(t))
                .with_location(loc(&t.location))
                .with_fix(
                    "Confine writes to a sandboxed base directory, canonicalize paths, and reject \
                     traversal sequences (`..`, absolute paths, symlinks).",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                }));
            }
            out
        }
    }

    /// DB delete/update without a WHERE clause guard.
    EaDbDeleteWithoutWhere {
        id: "ea-db-delete-without-where",
        category: DetectorCategory::ExcessiveAuthority,
        severity: Severity::High,
        title: "Destructive DB operation without WHERE guard",
        detect: |g| {
            let mut out = Vec::new();
            for t in g.tools.iter().filter(|t| t.effects.db_write) {
                let hay = format!("{} {}", t.signature.as_deref().unwrap_or(""), t.description.as_deref().unwrap_or("")).to_ascii_lowercase();
                let destructive = contains_any(&hay, &["delete", "drop", "truncate", "update"]) || mentions(t, &["delete", "drop", "truncate"]);
                let guarded = contains_any(&hay, &["where", "parameterized", "prepared", "allowlist", "confirm"]);
                if destructive && !guarded {
                    let f = Finding::new(
                        "ea-db-delete-without-where",
                        DetectorCategory::ExcessiveAuthority,
                        Severity::High,
                        "Destructive DB operation without WHERE guard",
                        format!(
                            "Tool `{}` performs destructive database writes (delete/update/drop) with \
                             no detectable WHERE-clause guard or parameterization. The agent can wipe \
                             rows or tables.",
                            t.name
                        ),
                    )
                    .with_tool(t.id.clone())
                    .with_evidence(tool_evidence(t))
                    .with_location(loc(&t.location))
                    .with_fix(
                        "Require a bounded WHERE clause on destructive statements, use parameterized \
                         queries, and gate DROP/TRUNCATE behind explicit human approval.",
                    );
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::ToolMisuse)
                            .with_agentic(OwaspAgentic2026::UnsafeAutonomyEscalation)
                            .with_llm(OwaspLlm2025::ExcessiveAgency)
                    }));
                }
            }
            out
        }
    }

    /// Cloud IAM over-scope (broad cloud credentials / wildcard actions).
    EaCloudIamOverscope {
        id: "ea-cloud-iam-overscope",
        category: DetectorCategory::ExcessiveAuthority,
        severity: Severity::High,
        title: "Cloud IAM over-scoped for tool",
        detect: |g| {
            let mut out = Vec::new();
            for t in &g.tools {
                let hay = format!(
                    "{} {} {}",
                    t.name,
                    t.signature.as_deref().unwrap_or(""),
                    t.description.as_deref().unwrap_or("")
                );
                let cloudy = contains_any(&hay, &["iam", "aws", "gcp", "azure", "s3", "boto3", "ec2", "admin", "role", "policy"]);
                let wildcard = contains_any(&hay, &["*:*", "\"*\"", "'*'", "fulladmin", "administratoraccess", "wildcard", "all permissions"]);
                if cloudy && (wildcard || (t.effects.net_egress && contains_any(&hay, &["admin", "administratoraccess"]))) {
                    let f = Finding::new(
                        "ea-cloud-iam-overscope",
                        DetectorCategory::ExcessiveAuthority,
                        Severity::High,
                        "Cloud IAM over-scoped for tool",
                        format!(
                            "Tool `{}` references broad / wildcard cloud IAM permissions. Over-scoped \
                             credentials let a hijacked agent escalate across the cloud account.",
                            t.name
                        ),
                    )
                    .with_tool(t.id.clone())
                    .with_evidence(tool_evidence(t))
                    .with_location(loc(&t.location))
                    .with_fix(
                        "Scope the tool's cloud credentials to least privilege: specific actions, \
                         resources and conditions; never use wildcard `*:*` policies.",
                    );
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::IdentityAbuse)
                            .with_agentic(OwaspAgentic2026::UnsafeAutonomyEscalation)
                            .with_llm(OwaspLlm2025::ExcessiveAgency)
                            .with_aicm("AICM-IAM-02")
                    }));
                }
            }
            out
        }
    }

    /// Computer-use / GUI-control tool without a human confirmation step.
    EaComputerUseWithoutConfirm {
        id: "ea-computer-use-without-confirm",
        category: DetectorCategory::ExcessiveAuthority,
        severity: Severity::High,
        title: "Computer-use tool without confirmation",
        detect: |g| {
            let mut out = Vec::new();
            for t in &g.tools {
                let is_cu = matches!(&t.source, ToolSource::Builtin(b) if {
                    let b = b.to_ascii_lowercase();
                    b.contains("computer") || b.contains("bash") || b.contains("text_editor")
                }) || {
                    let n = t.name.to_ascii_lowercase();
                    n.contains("computer") || n.starts_with("computer_") || n == "bash" || n.contains("text_editor")
                };
                if !is_cu { continue; }
                if mentions(t, &["confirm", "approval", "human", "review", "dry_run", "dry-run"]) { continue; }
                let f = Finding::new(
                    "ea-computer-use-without-confirm",
                    DetectorCategory::ExcessiveAuthority,
                    Severity::High,
                    "Computer-use tool without confirmation",
                    format!(
                        "Tool `{}` grants Computer Use / direct machine control with no confirmation \
                         step. Autonomous GUI/shell control without a human gate is high-risk.",
                        t.name
                    ),
                )
                .with_tool(t.id.clone())
                .with_evidence(tool_evidence(t))
                .with_location(loc(&t.location))
                .with_fix(
                    "Require human confirmation before each privileged computer-use action (clicks, \
                     typing, command execution) and run inside an isolated, monitored VM.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::UnsafeAutonomyEscalation)
                        .with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                        .with_eu(EuAiActArticle::Article14HumanOversight)
                }));
            }
            out
        }
    }
}
