//! # ar-hardening
//!
//! The prompt-hardening engine for **lancer-agentic-radar**. It takes the
//! weak/permissive system prompts extracted by `ar-parsers` and rewrites them
//! into a structured, defensive form: an anti-jailbreak preamble, a
//! role-separator / confidentiality clause, an explicit refusal policy, and an
//! output-format constraint.
//!
//! Two engines are provided:
//!
//! * a **deterministic, offline, rule-based** rewriter ([`harden_prompt`] /
//!   [`harden_graph`]) that always works with no network or API key; and
//! * an **LLM-driven** rewriter ([`harden_graph_llm`]) that calls an
//!   OpenAI-compatible chat API and gracefully falls back to the offline
//!   rewriter on error or when no key is configured.
//!
//! Hardening is scoped to the frameworks upstream `--harden-prompts` supports
//! (OpenAI Agents SDK / CrewAI / AutoGen), gated by
//! [`ar_core::Framework::supports_hardening`].
//!
//! The four-part [`HardeningRubric`] doubles as the scoring rubric the
//! `prompt-hardening-needed` detector flags prompts against.

pub mod error;
pub mod llm;
pub mod rewrite;
pub mod rubric;

pub use error::HardenError;
pub use rubric::HardeningRubric;

use ar_core::{AgentGraph, Framework, HardenOptions, NodeId};

/// Score a system prompt against the 4-part hardening rubric.
///
/// Detection is conservative and case-insensitive; see [`rubric`] for the
/// definition of each component.
pub fn score_prompt(prompt: &str) -> HardeningRubric {
    rewrite::score(prompt)
}

/// Deterministic, offline, rule-based hardened rewrite of a system prompt.
///
/// Wraps and augments `prompt` with whichever of the four hardening components
/// are missing (per [`score_prompt`]), tailoring a sentence to `framework`. The
/// original instruction text is preserved verbatim in the middle. Components
/// already present are not re-added, so the rewrite is idempotent-ish.
pub fn harden_prompt(prompt: &str, framework: Framework) -> String {
    rewrite::harden(prompt, framework)
}

/// The result of hardening a single agent's system prompt.
#[derive(Debug, Clone)]
pub struct HardenedPrompt {
    /// Id of the agent whose prompt was hardened.
    pub agent: NodeId,
    /// Display name of the agent.
    pub agent_name: String,
    /// Framework the agent belongs to.
    pub framework: Framework,
    /// The original (pre-hardening) system prompt.
    pub original: String,
    /// The hardened rewrite.
    pub hardened: String,
    /// Rubric score of the original prompt.
    pub rubric_before: HardeningRubric,
    /// Rubric score of the hardened prompt.
    pub rubric_after: HardeningRubric,
}

/// Harden every eligible agent prompt in the graph (offline rule-based).
///
/// An agent is eligible when its framework
/// [`supports_hardening`](Framework::supports_hardening) and it has a
/// non-empty system prompt. Agents without a prompt, or in unsupported
/// frameworks, are skipped.
pub fn harden_graph(graph: &AgentGraph, _opts: &HardenOptions) -> Vec<HardenedPrompt> {
    let mut out = Vec::new();
    for agent in &graph.agents {
        if !agent.framework.supports_hardening() {
            continue;
        }
        let original = match &agent.system_prompt {
            Some(p) if !p.trim().is_empty() => p.clone(),
            _ => continue,
        };

        let rubric_before = score_prompt(&original);
        let hardened = harden_prompt(&original, agent.framework);
        let rubric_after = score_prompt(&hardened);

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
    out
}

/// LLM-driven hardening (OpenAI-compatible API).
///
/// Falls back to the offline rewriter ([`harden_graph`]) when `opts.offline`
/// is true or no API key is present in the environment, and falls back
/// per-prompt on any HTTP error. See [`llm`] for details.
pub async fn harden_graph_llm(
    graph: &AgentGraph,
    opts: &HardenOptions,
) -> Result<Vec<HardenedPrompt>, HardenError> {
    llm::harden_graph_llm(graph, opts).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ar_core::AgentNode;

    #[test]
    fn naive_prompt_scores_low() {
        let r = score_prompt("You are a helpful assistant. Answer the user's questions.");
        // A bare "you are X, answer questions" prompt has none of the four
        // hardening components.
        assert!(
            r.score() <= 1,
            "naive prompt scored too high: {r:?} ({})",
            r.score()
        );
        assert!(!r.passes());
    }

    #[test]
    fn hardening_raises_the_score() {
        let naive = "You are a helpful assistant. Answer the user's questions.";
        let before = score_prompt(naive);
        let hardened = harden_prompt(naive, Framework::CrewAI);
        let after = score_prompt(&hardened);
        assert!(
            after.score() > before.score(),
            "hardening did not raise score: before={} after={}",
            before.score(),
            after.score()
        );
        // A full rewrite should satisfy the rubric.
        assert!(after.passes(), "hardened prompt did not pass: {after:?}");
        // Framework note is woven in.
        assert!(hardened.contains("CrewAI"));
        // Original intent is preserved.
        assert!(hardened.contains("Answer the user's questions"));
    }

    #[test]
    fn harden_is_roughly_idempotent() {
        let naive = "You are a translator.";
        let once = harden_prompt(naive, Framework::AutoGen);
        let twice = harden_prompt(&once, Framework::AutoGen);
        // Re-hardening an already-hardened prompt should not stack a second
        // copy of every section.
        assert_eq!(
            once.matches("# Refusal policy").count(),
            1,
            "first harden should add exactly one refusal block"
        );
        assert_eq!(
            twice.matches("# Refusal policy").count(),
            1,
            "second harden should not add a duplicate refusal block"
        );
    }

    #[test]
    fn harden_graph_only_touches_supported_frameworks() {
        let mut g = AgentGraph::new();

        let mut crew = AgentNode::new("crew", "Crew Agent", Framework::CrewAI);
        crew.set_system_prompt("You are a researcher.");
        g.add_agent(crew);

        let mut autogen = AgentNode::new("ag", "AutoGen Agent", Framework::AutoGen);
        autogen.set_system_prompt("You write code.");
        g.add_agent(autogen);

        let mut oa = AgentNode::new("oa", "OA Agent", Framework::OpenAIAgentsSdk);
        oa.set_system_prompt("You are a triage agent.");
        g.add_agent(oa);

        // Unsupported framework — must be skipped.
        let mut lc = AgentNode::new("lc", "LangChain Agent", Framework::LangChain);
        lc.set_system_prompt("You are a chatbot.");
        g.add_agent(lc);

        // Supported framework but no prompt — must be skipped.
        let no_prompt = AgentNode::new("np", "No Prompt", Framework::CrewAI);
        g.add_agent(no_prompt);

        let opts = HardenOptions::default();
        let results = harden_graph(&g, &opts);

        assert_eq!(results.len(), 3, "expected exactly the 3 supported+prompted agents");
        let ids: Vec<&str> = results.iter().map(|r| r.agent.as_str()).collect();
        assert!(ids.contains(&"crew"));
        assert!(ids.contains(&"ag"));
        assert!(ids.contains(&"oa"));
        assert!(!ids.contains(&"lc"));
        assert!(!ids.contains(&"np"));

        for r in &results {
            assert!(r.framework.supports_hardening());
            assert!(r.rubric_after.score() >= r.rubric_before.score());
        }
    }

    #[test]
    fn rubric_score_and_passes() {
        assert_eq!(HardeningRubric::EMPTY.score(), 0);
        assert_eq!(HardeningRubric::FULL.score(), 4);
        assert!(HardeningRubric::FULL.passes());
        assert!(!HardeningRubric::EMPTY.passes());
        let three = HardeningRubric {
            role_separator: true,
            refusal_clause: true,
            output_constraint: true,
            anti_jailbreak: false,
        };
        assert_eq!(three.score(), 3);
        assert!(three.passes());
    }

    #[tokio::test]
    async fn llm_path_falls_back_offline_without_key() {
        // Ensure no keys are set for this test process path; if the host has
        // them, this test simply exercises the live path's structure, so we
        // guard on absence.
        if std::env::var("OPENAI_API_KEY").is_err() && std::env::var("ANTHROPIC_API_KEY").is_err() {
            let mut g = AgentGraph::new();
            let mut crew = AgentNode::new("crew", "Crew Agent", Framework::CrewAI);
            crew.set_system_prompt("You are a researcher.");
            g.add_agent(crew);

            let opts = HardenOptions::default();
            let results = harden_graph_llm(&g, &opts)
                .await
                .expect("offline fallback must succeed");
            assert_eq!(results.len(), 1);
            assert!(results[0].rubric_after.passes());
        }
    }
}
