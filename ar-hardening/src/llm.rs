//! LLM-driven prompt hardening over an OpenAI-compatible chat-completions API.
//!
//! [`harden_graph_llm`] is the public entry point. It is deliberately
//! resilient:
//!
//! * if `opts.offline` is set, or no API key is present in the environment, it
//!   delegates entirely to the deterministic offline rewriter
//!   ([`crate::harden_graph`]) and returns `Ok`;
//! * otherwise it POSTs one chat-completion request per eligible agent prompt;
//! * on *any* transport / parse failure for a given prompt it silently falls
//!   back to the offline rewrite for that prompt, so a flaky network never
//!   hard-fails the whole run.

use crate::rewrite;
use crate::{HardenError, HardenedPrompt};
use ar_core::{AgentGraph, Framework, HardenOptions};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Default OpenAI-compatible chat-completions base URL.
const DEFAULT_API_BASE: &str = "https://api.openai.com/v1";

/// Read the first available API key from the environment.
///
/// Checks `OPENAI_API_KEY` first, then `ANTHROPIC_API_KEY`. Returns `None` if
/// neither is set (or both are empty), which forces the offline path.
fn api_key() -> Option<String> {
    for var in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"] {
        if let Ok(k) = std::env::var(var) {
            let k = k.trim().to_string();
            if !k.is_empty() {
                return Some(k);
            }
        }
    }
    None
}

// --- OpenAI-compatible chat-completions wire types --------------------------

#[derive(Debug, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage>,
    temperature: f32,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    #[serde(default)]
    message: Option<ChatMessage>,
}

/// Build the instruction sent to the model asking it to defensively rewrite a
/// single system prompt.
fn build_messages(prompt: &str, framework: Framework) -> Vec<ChatMessage> {
    let system = format!(
        "You are a prompt-security engineer. Rewrite the given {} agent system prompt so that it \
is defensively hardened. The rewrite MUST contain all four components: (1) an anti-jailbreak \
preamble that makes the instructions non-overridable, (2) a role-separator / system-prompt \
confidentiality clause, (3) an explicit refusal policy for out-of-scope or malicious requests, \
and (4) an output-format constraint. Preserve the original task intent. Respond with ONLY the \
rewritten system prompt text — no commentary, no code fences.",
        framework.display_name()
    );
    vec![
        ChatMessage {
            role: "system".into(),
            content: system,
        },
        ChatMessage {
            role: "user".into(),
            content: format!("Original system prompt:\n\n{prompt}"),
        },
    ]
}

/// Attempt one LLM rewrite of a single prompt. Returns `Err` on any HTTP /
/// parse failure so the caller can fall back to the offline rewrite.
async fn rewrite_one_llm(
    client: &reqwest::Client,
    api_base: &str,
    api_key: &str,
    model: &str,
    prompt: &str,
    framework: Framework,
) -> Result<String, HardenError> {
    let url = format!("{}/chat/completions", api_base.trim_end_matches('/'));
    let body = ChatRequest {
        model,
        messages: build_messages(prompt, framework),
        temperature: 0.0,
    };

    let resp = client
        .post(&url)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| HardenError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(HardenError::Http(format!(
            "chat-completions returned status {}",
            resp.status()
        )));
    }

    let parsed: ChatResponse = resp
        .json()
        .await
        .map_err(|e| HardenError::Other(format!("malformed chat-completions response: {e}")))?;

    let content = parsed
        .choices
        .into_iter()
        .next()
        .and_then(|c| c.message)
        .map(|m| m.content)
        .ok_or_else(|| HardenError::Other("chat-completions response had no choices".into()))?;

    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(HardenError::Other(
            "chat-completions returned empty content".into(),
        ));
    }
    Ok(trimmed.to_string())
}

/// LLM-driven hardening of every eligible agent prompt in `graph`.
///
/// See the module docs for the fallback semantics. This never returns an `Err`
/// for transient per-prompt failures; it only propagates `Err` if the HTTP
/// client itself cannot be constructed.
pub async fn harden_graph_llm(
    graph: &AgentGraph,
    opts: &HardenOptions,
) -> Result<Vec<HardenedPrompt>, HardenError> {
    // Offline mode (or no key available): use the deterministic rewriter.
    let key = match api_key() {
        Some(k) if !opts.offline => k,
        _ => return Ok(crate::harden_graph(graph, opts)),
    };

    let api_base = opts
        .api_base
        .clone()
        .unwrap_or_else(|| DEFAULT_API_BASE.to_string());

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Err(HardenError::Http(e.to_string())),
    };

    let mut out = Vec::new();
    for agent in &graph.agents {
        if !agent.framework.supports_hardening() {
            continue;
        }
        let original = match &agent.system_prompt {
            Some(p) if !p.trim().is_empty() => p.clone(),
            _ => continue,
        };

        let rubric_before = rewrite::score(&original);

        // Try the LLM; on any failure fall back to the offline rewrite.
        let hardened = match rewrite_one_llm(
            &client,
            &api_base,
            &key,
            &opts.model,
            &original,
            agent.framework,
        )
        .await
        {
            Ok(text) => text,
            Err(err) => {
                tracing::warn!(
                    agent = %agent.id,
                    error = %err,
                    "LLM hardening failed; falling back to offline rewrite"
                );
                rewrite::harden(&original, agent.framework)
            }
        };

        let rubric_after = rewrite::score(&hardened);

        out.push(HardenedPrompt {
            agent: agent.id.clone(),
            agent_name: agent.name.clone(),
            framework: agent.framework,
            original,
            hardened,
            rubric_before,
            rubric_after,
        });
    }

    Ok(out)
}
