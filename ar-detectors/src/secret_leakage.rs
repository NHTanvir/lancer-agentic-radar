//! Secret-leakage sub-checks (plan §"Detector catalog" item 9).
//!
//! Uses the secret-pattern library in [`crate::detector::helpers`] to find
//! hard-coded credentials in agent source / prompts / tool descriptions, and
//! environment-variable interpolation that feeds secrets into the LLM context.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{DetectorCategory, Finding, OwaspAgentic2026, OwaspLlm2025, Severity};

define_detectors! {
    /// Hard-coded API key anywhere in agent source (prompt, signature, snippet).
    SlHardcodedApiKey {
        id: "sl-hardcoded-api-key",
        category: DetectorCategory::SecretLeakage,
        severity: Severity::High,
        title: "Hard-coded API key / secret in agent source",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                let mut hay = String::new();
                if let Some(p) = &a.system_prompt { hay.push_str(p); hay.push('\n'); }
                if let Some(s) = &a.location.snippet { hay.push_str(s); hay.push('\n'); }
                if has_secret(&hay) {
                    let f = Finding::new(
                        "sl-hardcoded-api-key",
                        DetectorCategory::SecretLeakage,
                        Severity::High,
                        "Hard-coded API key / secret in agent source",
                        format!(
                            "Agent `{}` source contains what looks like a hard-coded secret/API key. \
                             Hard-coded credentials leak via the repo and can be exfiltrated through \
                             the agent.",
                            a.name
                        ),
                    )
                    .with_agent(a.id.clone())
                    .with_evidence(first_secret(&hay).unwrap_or_else(|| "<redacted secret>".into()))
                    .with_location(loc(&a.location))
                    .with_fix("Move secrets to a secrets manager / environment and reference them at runtime; rotate the exposed key.");
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::DataExfiltrationViaAgent)
                            .with_llm(OwaspLlm2025::SensitiveInformationDisclosure)
                            .with_aicm("AICM-IAM-04")
                    }));
                }
            }
            // Tool source snippets too.
            for t in &g.tools {
                let mut hay = String::new();
                if let Some(s) = &t.location.snippet { hay.push_str(s); hay.push('\n'); }
                if let Some(sig) = &t.signature { hay.push_str(sig); hay.push('\n'); }
                if has_secret(&hay) {
                    let f = Finding::new(
                        "sl-hardcoded-api-key",
                        DetectorCategory::SecretLeakage,
                        Severity::High,
                        "Hard-coded API key / secret in tool source",
                        format!("Tool `{}` source contains what looks like a hard-coded secret/API key.", t.name),
                    )
                    .with_tool(t.id.clone())
                    .with_evidence(first_secret(&hay).unwrap_or_else(|| "<redacted secret>".into()))
                    .with_location(loc(&t.location))
                    .with_fix("Move secrets to a secrets manager / environment and rotate the exposed key.");
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::DataExfiltrationViaAgent)
                            .with_llm(OwaspLlm2025::SensitiveInformationDisclosure)
                            .with_aicm("AICM-IAM-04")
                    }));
                }
            }
            out
        }
    }

    /// Environment variables interpolated into the LLM context.
    SlEnvVarToLlmContext {
        id: "sl-env-var-to-llm-context",
        category: DetectorCategory::SecretLeakage,
        severity: Severity::Medium,
        title: "Environment variable interpolated into LLM context",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                let prompt = match &a.system_prompt { Some(p) => p, None => continue };
                let envy = rx_match(prompt, r"(?i)os\.environ|getenv|process\.env|\$\{?[A-Z_]+\}?|env\[")
                    && contains_any(prompt, &["key", "token", "secret", "password", "credential", "api"]);
                if envy {
                    let f = Finding::new(
                        "sl-env-var-to-llm-context",
                        DetectorCategory::SecretLeakage,
                        Severity::Medium,
                        "Environment variable interpolated into LLM context",
                        format!(
                            "Agent `{}` interpolates a secret-bearing environment variable into its \
                             prompt/context. Secrets placed in the model context can be echoed back \
                             or exfiltrated.",
                            a.name
                        ),
                    )
                    .with_agent(a.id.clone())
                    .with_evidence(prompt_evidence(a))
                    .with_location(loc(&a.location))
                    .with_fix("Never place secrets in the prompt/context; inject them only into the tool layer that needs them.");
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::DataExfiltrationViaAgent)
                            .with_llm(OwaspLlm2025::SensitiveInformationDisclosure)
                    }));
                }
            }
            out
        }
    }

    /// Secret pattern present directly in the system prompt text.
    SlSecretInSystemPrompt {
        id: "sl-secret-in-system-prompt",
        category: DetectorCategory::SecretLeakage,
        severity: Severity::High,
        title: "Secret embedded in system prompt",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                let prompt = match &a.system_prompt { Some(p) => p, None => continue };
                if has_secret(prompt) {
                    let f = Finding::new(
                        "sl-secret-in-system-prompt",
                        DetectorCategory::SecretLeakage,
                        Severity::High,
                        "Secret embedded in system prompt",
                        format!(
                            "Agent `{}` embeds a secret/credential directly in its system prompt. \
                             Prompt-leak attacks will exfiltrate it.",
                            a.name
                        ),
                    )
                    .with_agent(a.id.clone())
                    .with_evidence(first_secret(prompt).unwrap_or_else(|| "<redacted secret>".into()))
                    .with_location(loc(&a.location))
                    .with_fix("Remove the secret from the prompt; pass credentials through the tool layer, not the model.");
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::DataExfiltrationViaAgent)
                            .with_llm(OwaspLlm2025::SensitiveInformationDisclosure)
                            .with_llm(OwaspLlm2025::SystemPromptLeakage)
                    }));
                }
            }
            out
        }
    }

    /// Secret pattern present in a tool description.
    SlSecretInToolDescription {
        id: "sl-secret-in-tool-description",
        category: DetectorCategory::SecretLeakage,
        severity: Severity::Medium,
        title: "Secret embedded in tool description",
        detect: |g| {
            let mut out = Vec::new();
            for t in &g.tools {
                let desc = match &t.description { Some(d) => d, None => continue };
                if has_secret(desc) {
                    let f = Finding::new(
                        "sl-secret-in-tool-description",
                        DetectorCategory::SecretLeakage,
                        Severity::Medium,
                        "Secret embedded in tool description",
                        format!(
                            "Tool `{}` embeds a secret/credential in its description, which is fed to \
                             the model and can be leaked.",
                            t.name
                        ),
                    )
                    .with_tool(t.id.clone())
                    .with_evidence(first_secret(desc).unwrap_or_else(|| "<redacted secret>".into()))
                    .with_location(loc(&t.location))
                    .with_fix("Remove credentials from tool descriptions; keep them in the tool's secured config.");
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::DataExfiltrationViaAgent)
                            .with_llm(OwaspLlm2025::SensitiveInformationDisclosure)
                    }));
                }
            }
            out
        }
    }
}
