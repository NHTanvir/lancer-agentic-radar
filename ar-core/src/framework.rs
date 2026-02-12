//! The set of agent frameworks lancer-agentic-radar can parse.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Agentic framework targeted by a parser. Mirrors upstream `agentic-radar`'s
/// framework coverage (plus the GUI's framework picker).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Framework {
    #[serde(rename = "langchain")]
    LangChain,
    #[serde(rename = "langgraph")]
    LangGraph,
    #[serde(rename = "crewai")]
    CrewAI,
    #[serde(rename = "autogen")]
    AutoGen,
    #[serde(rename = "semantic-kernel")]
    SemanticKernel,
    #[serde(rename = "vercel-ai")]
    VercelAI,
    #[serde(rename = "pydantic-ai")]
    PydanticAI,
    #[serde(rename = "openai-assistants")]
    OpenAIAssistants,
    #[serde(rename = "openai-agents")]
    OpenAIAgentsSdk,
    #[serde(rename = "anthropic-computer-use")]
    AnthropicComputerUse,
    #[serde(rename = "mcp")]
    Mcp,
    #[serde(rename = "n8n")]
    N8n,
}

impl Framework {
    /// Every framework, in catalog order.
    pub const ALL: [Framework; 12] = [
        Framework::LangChain,
        Framework::LangGraph,
        Framework::CrewAI,
        Framework::AutoGen,
        Framework::SemanticKernel,
        Framework::VercelAI,
        Framework::PydanticAI,
        Framework::OpenAIAssistants,
        Framework::OpenAIAgentsSdk,
        Framework::AnthropicComputerUse,
        Framework::Mcp,
        Framework::N8n,
    ];

    /// Canonical kebab-case id (matches the `--framework` CLI flag + serde).
    pub fn id(self) -> &'static str {
        match self {
            Framework::LangChain => "langchain",
            Framework::LangGraph => "langgraph",
            Framework::CrewAI => "crewai",
            Framework::AutoGen => "autogen",
            Framework::SemanticKernel => "semantic-kernel",
            Framework::VercelAI => "vercel-ai",
            Framework::PydanticAI => "pydantic-ai",
            Framework::OpenAIAssistants => "openai-assistants",
            Framework::OpenAIAgentsSdk => "openai-agents",
            Framework::AnthropicComputerUse => "anthropic-computer-use",
            Framework::Mcp => "mcp",
            Framework::N8n => "n8n",
        }
    }

    /// Human-friendly display name.
    pub fn display_name(self) -> &'static str {
        match self {
            Framework::LangChain => "LangChain",
            Framework::LangGraph => "LangGraph",
            Framework::CrewAI => "CrewAI",
            Framework::AutoGen => "AutoGen",
            Framework::SemanticKernel => "Semantic Kernel",
            Framework::VercelAI => "Vercel AI SDK",
            Framework::PydanticAI => "Pydantic AI",
            Framework::OpenAIAssistants => "OpenAI Assistants",
            Framework::OpenAIAgentsSdk => "OpenAI Agents SDK",
            Framework::AnthropicComputerUse => "Anthropic Computer Use",
            Framework::Mcp => "MCP",
            Framework::N8n => "n8n",
        }
    }

    /// Whether this framework's prompts are eligible for `--harden-prompts`
    /// (upstream scopes hardening to OpenAI Agents SDK / CrewAI / AutoGen).
    pub fn supports_hardening(self) -> bool {
        matches!(
            self,
            Framework::OpenAIAgentsSdk | Framework::CrewAI | Framework::AutoGen
        )
    }
}

impl fmt::Display for Framework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

impl FromStr for Framework {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n = s.trim().to_ascii_lowercase().replace(['_', ' '], "-");
        let f = match n.as_str() {
            "langchain" => Framework::LangChain,
            "langgraph" => Framework::LangGraph,
            "crewai" | "crew-ai" => Framework::CrewAI,
            "autogen" | "autogen-agentchat" => Framework::AutoGen,
            "semantic-kernel" | "sk" => Framework::SemanticKernel,
            "vercel-ai" | "vercel" | "ai-sdk" => Framework::VercelAI,
            "pydantic-ai" | "pydantic" => Framework::PydanticAI,
            "openai-assistants" | "assistants" => Framework::OpenAIAssistants,
            "openai-agents" | "openai-agents-sdk" | "agents-sdk" => Framework::OpenAIAgentsSdk,
            "anthropic-computer-use" | "computer-use" | "anthropic-cu" => {
                Framework::AnthropicComputerUse
            }
            "mcp" | "model-context-protocol" => Framework::Mcp,
            "n8n" => Framework::N8n,
            other => return Err(format!("unknown framework: {other}")),
        };
        Ok(f)
    }
}
