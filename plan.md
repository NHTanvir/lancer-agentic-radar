# RESEARCH DOSSIER: Agentic Radar

> Part of the Lancer ecosystem. A Rust clone of Agentic Radar — security scanner for agentic AI workflows. Build with Claude Code.
> Upstream: github.com/splx-ai/agentic-radar (Python, Apache-2.0, currently v0.14.1 as of May 2026). Focused on LangChain / LangGraph / CrewAI / AutoGen / Semantic Kernel / Vercel AI SDK / Pydantic AI / OpenAI Assistants / OpenAI Agents SDK / Anthropic Computer Use / MCP-based agents / **n8n workflow automation**.

## Feature Parity Mandate

**`lancer-agentic-radar` MUST ship with 100% feature parity to the upstream `agentic-radar` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `agentic-radar --help` (and the long-form man page / docs) must work in `lancer-agentic-radar --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-agentic-radar` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-agentic-radar --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

Agentic Radar (SplxAI, Apache-2.0) is a security scanner purpose-built for **agentic AI workflows** — the new class of apps where an LLM is wired to a graph of tools, memory stores, and RAG sources and is allowed to autonomously decide what to call. It targets the dominant agent frameworks of 2024-2026:

- **LangChain** (agents/chains/tools — Python)
- **LangGraph** (state-machine agents — Python)
- **CrewAI** (multi-agent crews/tasks — Python/YAML)
- **Microsoft AutoGen** (multi-agent conversation — Python, including `autogen-agentchat`)
- **Semantic Kernel** (skills/planners — C#/Python)
- **Vercel AI SDK** (TS/JS tool-calling agents)
- **Pydantic AI** (typed Python agents)
- **OpenAI Assistants** (threads/runs/tools API — v1 + V2 with `file_search`)
- **OpenAI Agents SDK** (the dedicated `openai-agents` SDK — distinct from Assistants; first-class upstream support, including testing mode)
- **Anthropic Computer Use** (tool definitions + computer-control)
- **MCP-based agents** (Model Context Protocol servers/clients — stdio / SSE / WebSocket transports)
- **n8n** (low-code workflow automation — JSON workflow definitions with AI Agent nodes; upstream-supported since v0.13 / fully-stable in v0.14)

For each, Agentic Radar **parses the workflow definition file** (Python AST walking for LangChain/CrewAI; YAML reader for CrewAI/Semantic Kernel configs; JSON schema for OpenAI Assistants & MCP), **reconstructs the tool graph** (which tools each agent node is allowed to call, what RAG sources it queries, what memory stores it reads/writes), then runs **static + optional dynamic checks** across categories:

- **Tool poisoning** — untrusted tool descriptions / parameter injection (MCP supply-chain risk)
- **Prompt injection escape paths** — where user input lands inside an LLM system prompt
- **RAG poisoning surface** — which docs feed the retriever, are they trusted
- **Memory poisoning surface** — vector store contents that persist across runs
- **Trust-boundary violations** — untrusted tool output flowing into next tool's input
- **Excessive tool authority** — agent has tool-call rights to dangerous operations (shell, file write, network egress) without scoping
- **Missing input validation** — no schema/regex/allowlist on tool args
- **Missing output filtering** — tool output piped to user without PII/secret redaction

Output: JSON / SARIF / Markdown / HTML report plus a **Mermaid/DOT graph** of the tool topology that auditors can diff against the system design doc. The killer demo is "feed it your LangChain agent file → get a diagram of the call graph with red edges where trust boundaries break."

## Internal architecture

**Workspace** (`Cargo.toml`):
```
[workspace]
members = ["lancer-agentic-radar", "ar-core", "ar-parsers", "ar-detectors", "ar-runtime", "ar-report"]
```

- **`lancer-agentic-radar`** — CLI binary (clap 4.x). Subcommands: `scan <path>` (static analysis), `test <path>` (dynamic vulnerability testing — runs prompt-injection / PII-leakage / harmful-content / fake-news probes against a configured agent endpoint, matching upstream `agentic-radar test`), `harden-prompts` (LLM-driven prompt rewriting for OpenAI Agents SDK / CrewAI / AutoGen targets). Flags include `--framework <name>`, `--dynamic`, `--harden-prompts`, `--config <yaml>`, `-i/--input <dir>`, `-o/--output <file>`, `--report-format sarif|json|md|html`, `--compliance-mode owasp-agentic-top10-2026|owasp-llm-top10-2025|eu-ai-act|nist-ai-rmf`.
- **`ar-core`** — Shared types: `AgentGraph`, `AgentNode`, `ToolNode`, `MemoryStore`, `RAGSource`, `Edge`, `TrustLabel { Trusted, Untrusted, Mixed }`, `Finding`, `Severity { Critical, High, Medium, Low, Info }`.
- **`ar-parsers`** — One sub-module per framework. Parses source/config into a uniform `AgentGraph`.
- **`ar-detectors`** — One detector per security check. All operate on `AgentGraph` from `ar-core`.
- **`ar-runtime`** — Optional dynamic probe: invokes the live agent endpoint, replays attack prompts, observes tool selection. Houses the `test` subcommand's vulnerability test runner (prompt-injection, PII leakage, harmful content, fake news) — matching upstream `agentic-radar test`'s test-categories taxonomy aligned with OWASP LLM Top 10 v2025 and OWASP Top 10 for Agentic Applications 2026.
- **`ar-hardening`** — Prompt-hardening engine. Takes weak/permissive system prompts extracted by `ar-parsers`, sends them through Claude / GPT-4 / local model to rewrite them in a structured, defensive style (role-separator clause, refusal patterns, output-format constraints, anti-jailbreak preamble). Currently scoped to OpenAI Agents SDK / CrewAI / AutoGen targets, mirroring upstream `--harden-prompts`.
- **`ar-report`** — Markdown/SARIF/JSON/HTML emitters; Mermaid+DOT graph generators; OWASP-Agentic-Top-10-2026 + OWASP-LLM-Top-10-2025 vulnerability-mapping tables tying each finding to the framework category.

**Key modules in `ar-core/src/`:**
- `graph.rs` — `AgentGraph { nodes: Vec<AgentNode>, tools: Vec<ToolNode>, edges: Vec<Edge>, memory: Vec<MemoryStore>, rag: Vec<RAGSource> }` backed by `petgraph::DiGraph<NodeKind, EdgeKind>`.
- `node.rs` — `AgentNode { id, name, system_prompt, model, framework, file_loc }`, `ToolNode { id, name, signature, side_effects: ToolEffects, source: ToolSource }`, where `ToolEffects = { reads_fs, writes_fs, shell_exec, net_egress, db_write, payment, email }`.
- `trust.rs` — Trust labels propagating across edges (user input = Untrusted; vetted internal RAG = Trusted; LLM output = Mixed-tending-Untrusted; tool result = depends on tool).
- `framework.rs` — Enum `Framework { LangChain, LangGraph, CrewAI, AutoGen, SemanticKernel, VercelAI, PydanticAI, OpenAIAssistants, OpenAIAgentsSdk, AnthropicComputerUse, MCP, N8n }`.
- `finding.rs` — `Finding { detector_id, severity, title, description, agent, tool?, evidence, fix_suggestion }`.

**Key modules in `ar-parsers/src/`:**
- `langchain/` — Walks Python AST via `rustpython-parser`. Recognizes `AgentExecutor`, `initialize_agent`, `Tool`, `@tool` decorator, `create_react_agent`, `create_openai_functions_agent`. Resolves tool list passed to agent constructor.
- `langgraph/` — Specialized walker for `StateGraph`, `add_node`, `add_edge`, `add_conditional_edges`. Reconstructs state-machine.
- `crewai/` — Dual mode: Python AST for `Agent(...)/Task(...)/Crew(...)`; YAML reader for `agents.yaml`/`tasks.yaml` config files.
- `autogen/` — Walks `ConversableAgent`, `UserProxyAgent`, `AssistantAgent` constructors and `register_tool` calls.
- `semantic_kernel/` — Reads C# attributes (`[KernelFunction]`) or Python `kernel.add_plugin()` calls plus `planners/` config.
- `vercel_ai/` — TypeScript via tree-sitter (`tree-sitter-typescript`); recognizes `generateText({ tools: ... })`, `streamText`, `experimental_*`.
- `pydantic_ai/` — Python AST: `Agent(...)`, `@agent.tool` decorator.
- `openai_assistants/` — JSON from OpenAI API or YAML config: parses `tools: [{ type: "function" | "code_interpreter" | "file_search" }]`, threads, runs.
- `anthropic_cu/` — Tool definitions (`{ name, description, input_schema }`) plus `computer_20241022` / `computer_20250124` builtin tool detection.
- `mcp/` — Parses MCP server manifests (`mcp.json`), client config, tool advertisements; cross-references with declared trust level.
- `openai_agents_sdk/` — Dedicated parser for the `openai-agents` Python SDK (distinct from Assistants API): `Agent(...)`, `Runner.run(...)`, `function_tool` decorator, `handoff` between agents, `WebSearchTool` / `FileSearchTool` / `ComputerTool` builtins, guardrails, tracing, `as_tool()` agent-as-tool patterns.
- `n8n/` — Parses n8n workflow JSON exports (`.json` files from n8n's export endpoint). Recognizes `@n8n/n8n-nodes-langchain.agent` nodes, tool sub-nodes, MCP nodes, chat trigger nodes, RAG/vector store nodes (Pinecone/Qdrant/Supabase/PGVector). Builds the node-connection graph from `connections` field and maps each node type to a `ToolNode` / `RAGSource` / `MemoryStore` accordingly.

**Key modules in `ar-detectors/src/`:**
- `detector.rs` — `Detector` trait + `DetectorId` enum + `define_detectors!` macro (mirrors aderyn's pattern).
- `prompt_injection/`, `tool_poisoning/`, `rag_poisoning/`, `memory_poisoning/`, `trust_boundary/`, `excessive_authority/`, `missing_validation/`, `missing_output_filter/`, `secret_leakage/`, `jailbreak_pathway/`, `indirect_injection/`, `recursion_bomb/`, `infinite_loop/`, `resource_exhaustion/` — one directory per detector category.

**Static analysis flow:**
1. `ar-parsers` detect framework (file extension + structural fingerprints).
2. Build `AgentGraph` (nodes = agents, edges = agent→tool, agent→memory, agent→rag, tool→agent).
3. Run trust-label propagation (BFS from Untrusted sources).
4. Each detector in `ar-detectors` queries graph predicates (`find_agents_calling_tool_with_effect`, `edges_crossing_trust_boundary`, etc.) and emits `Finding`s.
5. `ar-report` renders Mermaid/DOT graphs + JSON/SARIF/Markdown/HTML.

**Dynamic probe flow** (optional, `--dynamic` flag):
1. CLI provided endpoint URL + auth.
2. `ar-runtime` sends crafted attack prompts (indirect injection, tool-selection abuse, RAG poisoning markers).
3. Observe response + tool-call telemetry (if endpoint emits OTEL traces).
4. Cross-reference with static findings to **confirm exploitability** (lowers FP rate).

## Granular feature catalog

**Framework support matrix:**

| Framework | Parse | Tool extract | RAG detect | Memory detect | Multi-agent | Dynamic probe |
|---|---|---|---|---|---|---|
| LangChain | Python AST | yes | yes (Chroma/FAISS/Pinecone/Weaviate) | yes (ConversationBufferMemory, RedisChatMessageHistory) | partial | yes |
| LangGraph | Python AST | yes | yes | yes (state.MessagesState) | yes | yes |
| CrewAI | Python + YAML | yes | yes | yes (mem0) | yes | yes |
| AutoGen | Python AST | yes | partial | yes | yes | yes |
| Semantic Kernel | C#/Python | yes | yes | yes | partial | partial |
| Vercel AI SDK | TS via tree-sitter | yes | partial | n/a (stateless) | n/a | yes |
| Pydantic AI | Python AST | yes | yes | yes | yes | yes |
| OpenAI Assistants | JSON/YAML | yes | yes (file_search) | yes (threads) | yes | yes |
| OpenAI Agents SDK | Python AST | yes (`function_tool`, builtins) | yes (`FileSearchTool`) | yes (sessions) | yes (handoffs) | yes (testing mode) |
| Anthropic Computer Use | JSON | yes (computer/bash/text_editor) | n/a | n/a | n/a | yes |
| MCP | mcp.json | yes (server advertisements) | yes (resources) | yes (prompts) | n/a | yes |
| n8n | workflow JSON | yes (tool sub-nodes + MCP nodes) | yes (vector store nodes) | yes (memory nodes) | partial (multi-agent via sub-workflows) | partial (webhook trigger replay) |

**Detector catalog (one per category, ~50 sub-checks total):**

1. **prompt-injection** — `pi-user-in-system-prompt`, `pi-untrusted-rag-in-system-prompt`, `pi-tool-result-concatenated-without-delim`, `pi-system-prompt-leak-via-echo`, `pi-no-role-separator`, `pi-template-variable-unescaped`.
2. **tool-poisoning** — `tp-mcp-untrusted-server`, `tp-tool-description-from-untrusted-source`, `tp-parameter-schema-permissive`, `tp-runtime-tool-registration` (any-tool-added-at-runtime), `tp-mcp-server-no-signature-check`, `tp-tool-name-collision`.
3. **rag-poisoning** — `rp-untrusted-document-source`, `rp-no-content-validation`, `rp-vector-store-user-writable`, `rp-retriever-no-source-attribution`, `rp-no-chunk-size-limit`, `rp-embedding-injection-vector`.
4. **memory-poisoning** — `mp-cross-session-memory-shared`, `mp-untrusted-input-written-to-memory`, `mp-no-memory-eviction-policy`, `mp-memory-stored-verbatim`, `mp-memory-no-tenant-isolation`.
5. **trust-boundary** — `tb-tool-output-to-next-tool-input`, `tb-rag-doc-to-shell-tool`, `tb-user-input-to-eval`, `tb-llm-output-to-fs-write`, `tb-llm-output-to-sql-query`, `tb-mcp-result-to-shell`.
6. **excessive-authority** — `ea-shell-tool-without-allowlist`, `ea-payment-tool-without-2fa`, `ea-email-tool-broadcast`, `ea-network-egress-unbounded`, `ea-fs-write-anywhere`, `ea-db-delete-without-where`, `ea-cloud-iam-overscope`, `ea-computer-use-without-confirm`.
7. **missing-input-validation** — `miv-no-schema-on-tool-args`, `miv-no-length-limit`, `miv-no-allowlist-on-url`, `miv-no-path-traversal-check`, `miv-no-content-type-check`.
8. **missing-output-filter** — `mof-no-pii-redaction`, `mof-no-secret-pattern-filter`, `mof-raw-stack-trace`, `mof-no-content-policy`, `mof-no-jailbreak-output-detector`.
9. **secret-leakage** — hardcoded API keys in agent source, env var leakage to LLM context, secret pattern in system prompt, secret in tool description.
10. **jailbreak-pathway** — system-prompt overridable by user (no role-separator), DAN/Skeleton-Key vulnerability pattern matches, missing system-prompt-confidentiality clause.
11. **indirect-injection** — RAG/email/webpage tool output reaches LLM context without sanitization markers, MCP server output without trust label.
12. **recursion-bomb** — agent can call itself (or sub-agent that calls back) without depth cap, mutual recursion in graph of agents.
13. **infinite-loop** — `while True:` style loops without timeout / step budget, LangGraph cycle without exit condition.
14. **resource-exhaustion** — token budget unbounded, no max-steps, no rate-limit on tool calls, no cost cap.
15. **owasp-agentic-2026** — meta-detector that **tags every other finding** with the matching OWASP Top 10 for Agentic Applications 2026 category. Categories include: `goal-hijacking`, `tool-misuse`, `identity-abuse`, `memory-poisoning`, `cascading-failure`, `rogue-agent`, `unauthorized-handoff`, `unsafe-autonomy-escalation`, `data-exfiltration-via-agent`, `traceability-gap`. Provides a top-level "OWASP Agentic 2026 coverage" pie chart in the report.
16. **n8n-workflow-risks** — n8n-specific: `n8n-webhook-trigger-public-without-auth`, `n8n-credential-shared-across-workflows`, `n8n-code-node-no-sandbox`, `n8n-http-request-egress-unbounded`, `n8n-ai-agent-tool-fan-out`, `n8n-mcp-node-untrusted-server`.
17. **handoff-abuse (OpenAI Agents SDK)** — `oa-handoff-without-input-filter`, `oa-handoff-loop-no-cap`, `oa-agent-as-tool-no-scoping`, `oa-guardrail-disabled`, `oa-tracing-disabled-in-prod`.
18. **prompt-hardening-needed** — flags system prompts that score below the prompt-hardening rubric (no role separator, no refusal clause, no output-format constraint, no anti-jailbreak preamble). Each finding emits a candidate hardened rewrite via `ar-hardening` when `--harden-prompts` is set.

**Graph visualization:**
- Mermaid `flowchart TB` output with edge colors: green = Trusted→Trusted; orange = Mixed; red = Untrusted→privileged-tool.
- DOT/Graphviz output for higher-fidelity rendering.
- Nodes labeled with agent name, model, system-prompt SHA-256 (for diffing).
- Tools labeled with effect badges (`SHELL`, `NET`, `FS-W`, `DB-W`, `$`).

**Report formats:**
- **JSON** — machine-readable list of findings + graph.
- **SARIF 2.1.0** — GitHub code-scanning upload.
- **Markdown** — auditor-friendly with TOC, severity table, embedded Mermaid diagram.
- **HTML** — askama/tera-rendered standalone page, dark-mode, collapsible per-finding evidence.

**CI integration:**
- `lancer-agentic-radar scan . --fail-on critical,high` exit code for GitHub Actions / GitLab CI.
- SARIF upload action.
- Baseline diff: `--baseline base.sarif` to only report new findings vs main branch.

**Dependency upgrade alerts:**
- Embedded table of known-vulnerable agent-framework versions (LangChain pre-0.1.0 SSRF in `requests` tool, CrewAI pre-0.30 unsanitized RAG, MCP servers with reported tool-poisoning CVEs).
- Reports outdated framework usage with linked CVE.

**Compliance & framework mapping:**
- **OWASP Top 10 for Agentic Applications 2026** — full mapping table tying each detector to one or more of the 10 categories (goal hijacking, tool misuse, identity abuse, memory poisoning, cascading failures, rogue agents, etc.).
- **OWASP LLM Top 10 v2025** — mapping retained for model-level findings (prompt injection, sensitive info disclosure, insecure output handling, etc.).
- **OWASP AIVSS** (AI Vulnerability Scoring System) — each finding emits an AIVSS vector string alongside CVSS for cross-tool interop.
- **NIST AI RMF (AI 600-1)** — mapping retained.
- **EU AI Act** — Article 13 / 14 / 15 mapping retained.
- **CSA AICM** (Cloud Security Alliance AI Controls Matrix) — control-IDs cited per finding.
- **MITRE ATLAS** — adversarial-ML tactic IDs cited where applicable (e.g. `AML.T0051` prompt injection, `AML.T0017` model theft).

**Runtime-governance integration:**
- Optional **Microsoft Agent Governance Toolkit** policy export — emit deterministic sub-millisecond policy rules covering each Critical/High finding so the AGT runtime can enforce them at agent-call time.
- Optional **Cisco DefenseClaw** secure-agent-framework export — same idea, different runtime.
- Hook for **LlamaFirewall** (Meta) inline-filter config generation per finding.

## Engineering hard parts

1. **Robust Python AST walking for LangChain.** LangChain is a TypeScript-of-Python: deep dynamic dispatch, decorator chains (`@tool`, `@chain`, `RunnableLambda`), runtime tool registration (`agent.tools.append(...)` in another module), and constant API churn. The walker must:
   - Resolve cross-module imports (`from langchain.tools import Tool` → fully qualified).
   - Follow variable reassignment (`tools = [...]; tools.append(extra_tool); agent = create_react_agent(llm, tools)`).
   - Handle decorator chains and recognize `@tool`-decorated functions as tool nodes.
   - Treat unresolved dynamic constructs as `Unknown` nodes with a finding (`unable-to-statically-resolve` = audit needed).

2. **YAML schema heterogeneity.** CrewAI's `agents.yaml` vs Semantic Kernel's planner config vs OpenAI Assistants' JSON each have their own shape. The parser layer must do **structural** detection (look at top-level keys) rather than relying on filename, since users rename.

3. **Capturing data-flow through LLM calls.** The LLM is a **black box** — we can't statically know what it'll output. But its output feeds downstream tools. The model: treat every LLM call as an **opaque untrusted source** for the purposes of trust-label propagation. This is conservative but sound; refinement comes from `--dynamic` probe results that confirm/deny.

4. **Distinguishing trusted vs untrusted RAG sources.** Heuristics:
   - Internal-prefixed paths (`./docs/`, `s3://internal-bucket/`) → Trusted by default.
   - Public-prefixed (`https://*`, `wikipedia`, `arxiv`) → Untrusted.
   - User-uploaded (`s3://user-uploads/`, `db.user_files`) → Untrusted.
   - Override-able via config (`ar.toml [trust] trusted_sources = [...]`).

5. **Modeling the memory layer.** Vector stores persist contents across runs — anything written by prior (potentially malicious) inputs is "in" the store. Detectors flag any memory store whose write path is reachable from an Untrusted source.

6. **Framework version churn.** Each major version of LangChain/LangGraph/CrewAI reorganizes APIs. The parsers need versioned strategies:
   - Detect framework version from `requirements.txt`/`pyproject.toml`/`package.json`.
   - Apply the right AST signature set.
   - When parsing fails: emit `unsupported-version` info and degrade gracefully.

7. **MCP tool advertisement parsing.** MCP servers advertise tools at runtime via JSON-RPC. Static parsing can only read declared `mcp.json` manifests; runtime advertisements require **dynamic probe** (connect to the MCP server, list tools, capture descriptions, scan descriptions for prompt-injection patterns).

8. **False-positive suppression via suppression hints.** Per-finding suppression via `# ar-ignore: detector-id` comments adjacent to declaration. Per-project suppression via `ar.toml [detectors] exclude = [...]`.

9. **Tool-effect inference.** For each declared tool we must guess what it actually does. Heuristics:
   - Pattern-match function body for `subprocess.`/`os.system`/`shell=True` → `shell_exec`.
   - Pattern-match for `open(..., 'w')`/`pathlib.Path(...).write_text` → `writes_fs`.
   - Pattern-match for `requests.`/`httpx.`/`urllib.` → `net_egress`.
   - Pattern-match for `sqlalchemy`/`psycopg`/`pymongo` → `db_write` (if INSERT/UPDATE/DELETE found).
   - Override-able via decorator metadata: `@tool(effects=["net", "db"])`.
   - When inference fails → emit `unknown-tool-effects` info finding with the auditor responsible for tagging.

10. **System-prompt extraction.** The system prompt may be a string literal, an f-string, a Jinja template, or loaded from disk. The parser walks back to the literal source (or `Path.read_text(...)` call) and records the SHA-256 of the final concatenated prompt so two scans can diff prompt evolution.

11. **MCP transport diversity.** MCP supports stdio, SSE, and WebSocket transports. The dynamic probe must speak all three; each has its own quirks (stdio: spawn server subprocess and pipe JSON-RPC; SSE: hold long-lived connection; WS: stateful messages). `ar-runtime` abstracts via a `McpTransport` trait.

12. **Multi-tenant memory store detection.** A vector store may be partitioned by tenant ID via metadata filter. The detector must walk back from the query call to confirm the filter is being applied — failing to apply tenant isolation when the store contains mixed-tenant data is a critical finding.

## Rust library mapping

| Need | Crate | Version |
|---|---|---|
| Python AST parsing | `rustpython-parser` | 0.3+ |
| Python parsing fallback / TS / multilang | `tree-sitter`, `tree-sitter-python`, `tree-sitter-typescript`, `tree-sitter-javascript` | 0.20+ |
| YAML config | `serde_yaml` | 0.9 |
| JSON (OpenAI Assistants / MCP) | `serde_json` | 1.0 |
| Graph algorithms | `petgraph` | 0.6+ |
| Async runtime (dynamic probe) | `tokio` | 1.40 |
| HTTP client (dynamic probe + MCP) | `reqwest` | 0.12 |
| CLI | `clap` | 4.x |
| SARIF output | `serde_sarif` | 0.4 |
| HTML/Markdown templating | `askama` or `tera` | 0.12 / 1.x |
| Mermaid/DOT generation | hand-rolled emitter | n/a |
| Parallelism (per-detector) | `rayon` | 1.11 |
| Errors | `eyre` / `thiserror` | 0.6 / 1.0 |
| Logging | `tracing`, `tracing-subscriber` | 0.1.x |
| TOML config | `toml` | 0.8 |
| OpenTelemetry consumer (dynamic) | `opentelemetry`, `opentelemetry_sdk` | 0.24+ |
| Regex (PII/secret patterns) | `regex` | 1.10 |
| Hashing (system prompt SHA-256) | `sha2` | 0.10 |

(Upstream is Python — for the Rust clone, `rustpython-parser` is the load-bearing dependency; `tree-sitter-python` is the fallback when `rustpython-parser` chokes on bleeding-edge syntax.)

## Bug bounty workflows

The 2026 bug-bounty thesis for AI: **the LLM-backed feature is the new SQL injection.** Whenever a target ships a chatbot, coding assistant, customer-support agent, or workflow automator, the agent definition + tool graph is the high-value attack surface. Agentic Radar fits in:

**Workflow A — open-source target:**
1. Find vulnerable agent definitions in the target's public repos (LangChain `*.py`, CrewAI `crews/*.py`, MCP `mcp.json`).
2. Run `lancer-agentic-radar scan <repo>`.
3. Read the Mermaid graph; identify the highest-severity trust-boundary violation (typically `tb-tool-output-to-next-tool-input` between a fetch-URL tool and an exec tool, or excessive-authority `ea-shell-tool-without-allowlist`).
4. Validate by hand using §42 LLM Vuln Scanner (Lancer's promptfoo wrapper) or §43 Red-Team Orchestrator (Strix-driven autonomous tester).
5. Submit finding with the Mermaid graph as evidence of impact.

**Workflow B — live endpoint, closed-source:**
1. Point Agentic Radar at the agent endpoint with `--dynamic`.
2. Tool fires baseline probes (indirect injection markers, tool-discovery prompts) → builds best-effort tool graph from observed behavior.
3. Combines with §42's promptfoo plugin matrix for full attack coverage.
4. Findings cross-correlated, report exported.

**Programs that explicitly ask for agentic-AI testing (2026):**
- Anthropic — Claude API + Computer Use; tools-as-attack-surface category.
- OpenAI — Assistants API + Operator agent.
- Microsoft — Copilot Studio, Semantic Kernel deployments.
- Google — Gemini agents in Vertex AI.
- Cursor / Codeium / GitHub Copilot Workspace — coding-agent sandbox escape categories.
- HackerOne AI / Bugcrowd AI — generic agentic categories.
- Vertical: bank/fintech chatbots (Klarna, Plaid, Revolut had bounty programs covering LLM features in 2025-2026).

**Workflow C — supply-chain (MCP servers):**
1. Discover MCP servers in target's deployment (`mcp.json` in repos, advertised in container manifests).
2. Run `lancer-agentic-radar scan --mcp-only <path>` and `--dynamic --mcp-endpoint stdio:///path/to/server`.
3. Inspect tool advertisements; tool-poisoning detectors flag suspicious description patterns (instructions hidden in description text, Unicode tag-character payloads).
4. For each suspicious tool, attempt the canonical "tool description as prompt injection" probe — does the agent obey instructions written into the tool description?
5. File against the MCP server author (potentially CVE-worthy) and the integrating product.

**Workflow D — agentic compliance gap audit:**
1. For a target subject to EU AI Act (high-risk AI systems) or NIST AI RMF assessments.
2. Run with `--compliance-mode eu-ai-act,nist-ai-rmf,owasp-llm-2025`.
3. Report sections include gap analysis: which articles/categories are violated by findings.
4. Useful for governance-team-driven bounties and for paid AI security audits ($).

## 2024-2026 state

- **2024 H2 — first stable release.** Initial 0.x with LangChain + LangGraph + CrewAI parsers, ~10 detectors. Mermaid output. SARIF.
- **2025 H1 — framework expansion.** AutoGen, Semantic Kernel, Vercel AI SDK parsers added. Detector count doubles. CI GitHub Action shipped.
- **2025 H2 — LangChain v0.3 migration.** Massive parser rewrite to track LangChain's `langchain-core` extraction. LangGraph v0.2 with new `StateGraph` API supported.
- **2025 H2 — OpenAI Assistants V2 API support.** New thread/run model parsed; vector store / file_search attachments mapped to RAG detector category.
- **2025 H2 — Anthropic Computer Use beta support.** `computer_20241022` / `computer_20250124` builtin tools recognized; trust-boundary detector specifically flags Computer Use → shell pipeline.
- **2025 H2 — MCP spec stabilization.** Full MCP server/client parsing; tool-poisoning detector category added.
- **2026 H1 — Pydantic AI + agentic compliance.** Pydantic AI parser. **NIST AI RMF mapping** + **OWASP LLM Top 10 v2025 mapping** + **EU AI Act compliance checks** (Article 13 transparency, Article 14 human oversight, Article 15 robustness) — each finding tagged with framework citations.
- **2026 H1 — dynamic probe maturity.** Production-grade `--dynamic` mode with OTEL trace consumption, integration with LLM-as-judge graders, replay/reproduction harness.
- **2026 mid (latest):** versioned framework detection, refined trust labels, dependency-upgrade-alert table fed by NVD + curated agent-CVE list. LangGraph v0.2 conditional-edge analysis improved; Vercel AI SDK v4 tool-call tracking; OpenAI Assistants V2 file_search RAG mapped to detector graph.

> **Deep-research update — 2026-05-30:** confirmed upstream `splx-ai/agentic-radar` is at **v0.14.1** (902 stars, 113 forks, Apache-2.0). Verified upstream framework support now spans **OpenAI Agents SDK** (full: scan + MCP + prompt-hardening + testing), **CrewAI** (scan + MCP + prompt-hardening), **LangGraph** (scan + MCP), **n8n** (scan + MCP — added v0.13, stabilized v0.14), and **AutoGen** (scan + MCP + prompt-hardening, including `autogen-agentchat`). Confirmed upstream CLI surface = `scan` + `test` subcommands plus `--harden-prompts` flag (LLM-driven system-prompt rewriting). Testing subcommand runs prompt-injection / PII-leakage / harmful-content / fake-news probes against running agents. v0.14.0 release notes specifically called out **MCP-detection coverage expansion** across autogen / crewai / n8n / openai-agents and **duplicate-tool-node de-duplication** in graph output. New external standards landed in 2026 that must be mapped: **OWASP Top 10 for Agentic Applications 2026** (10 categories including goal hijacking, tool misuse, identity abuse, memory poisoning, cascading failures, rogue agents), **OWASP AIVSS** (AI Vulnerability Scoring System), **CSA AICM** (AI Controls Matrix), **MITRE ATLAS** adversarial-ML tactics, **Microsoft Agent Governance Toolkit** (sub-ms runtime policy enforcement covering all 10 OWASP Agentic Top 10 risks, OSS-launched March 2026), and **Cisco DefenseClaw** (RSAC 2026 OSS secure-agent framework). Plan sections updated to include: (a) n8n + OpenAI Agents SDK parsers and framework-enum entries, (b) `test` subcommand + `--harden-prompts` flag + `ar-hardening` crate, (c) new detector categories `owasp-agentic-2026`, `n8n-workflow-risks`, `handoff-abuse`, `prompt-hardening-needed`, (d) compliance mappings for OWASP Agentic Top 10 2026 / AIVSS / CSA AICM / MITRE ATLAS, (e) runtime-governance export hooks for MS AGT / Cisco DefenseClaw / LlamaFirewall, (f) updated comparison-to-neighbors table.

**Comparison to neighbors (2026 verdict):**

| Tool | Focus | Frameworks | Static / Dynamic | Output |
|---|---|---|---|---|
| **Agentic Radar (SplxAI)** | Agent topology + trust-boundary analysis + prompt-hardening + dynamic testing | 11+ frameworks incl. n8n + OpenAI Agents SDK | Static (scan) + Dynamic (test) + Hardening (harden-prompts) | SARIF/JSON/MD/HTML + Mermaid graph |
| Promptfoo Redteam | Attack-prompt generation + grading | provider-agnostic | Dynamic only | HTML dashboard |
| Garak (NVIDIA) | Probe-based testing | model-level | Dynamic only | Markdown/JSON |
| PyRIT (Microsoft) | Multi-turn red-team orchestration | model-level | Dynamic only | JSON |
| LlamaFirewall (Meta) | Runtime guardrails | model-level | Runtime | Inline filter |
| MS Agent Governance Toolkit | Runtime policy covering OWASP Agentic Top 10 2026 | runtime-agnostic | Runtime only | Sub-ms policy enforcement + telemetry |
| Cisco DefenseClaw | Secure agent framework + inventory automation | runtime-agnostic | Runtime only | Inline filter + audit log |

Agentic Radar's niche is the only one of these that **understands the agent's tool graph as a graph** and reasons about edges. The others test the model in isolation. They're complementary — Agentic Radar tells you where to attack; Promptfoo / Garak provide the payloads.

## AI augmentation ideas

1. **LLM-generated test inputs targeting specific tool-graph weaknesses.** Given a `Finding` of `tb-tool-output-to-next-tool-input` between a `fetch_url` tool and an `exec_shell` tool, ask Claude to generate 20 attack URLs whose returned content would trigger shell-injectable strings in the exec tool. Feed those into `--dynamic` to validate.

2. **LLM-summarized "what could go wrong" per agent.** Plain-English risk narrative for each `AgentNode` derived from its system prompt + tool list + RAG source list. Auditor reads this before scanning the findings.

3. **Auto-generate mitigation patches.** Per finding, propose a code patch:
   - `miv-no-schema-on-tool-args` → suggest Pydantic schema for tool args.
   - `ea-shell-tool-without-allowlist` → suggest allowlist + `subprocess.run([...], shell=False)`.
   - `mof-no-pii-redaction` → suggest pre-output regex filter or microsoft-presidio integration snippet.
   - `tb-tool-output-to-next-tool-input` → suggest delimiter-based separation + `<tool_output>` tag stripping.

4. **Explain a complex agent graph in plain English.** Given the reconstructed `AgentGraph`, generate a 2-paragraph executive summary: "This system is a 3-agent CrewAI deployment. The Researcher agent has unrestricted web access. Its output feeds the Writer agent which has email-send capability. Risk: a malicious webpage could cause the Writer to send a phishing email…"

5. **Detector authoring assist.** "Write me a detector that flags any LangGraph state-machine with an unconditional edge from a user-input node to a shell-exec tool." LLM emits Rust code using the `Detector` trait + `AgentGraph` query API.

6. **False-positive triage via LLM.** Each medium-severity finding goes to Claude with surrounding context for a confidence rating; below threshold → demoted to info-level in the report.

7. **Severity uplift via target context.** LLM reads README + deployment context (is this a banking chatbot? a public free service?) and proposes severity adjustments — e.g. an `ea-payment-tool-without-2fa` finding in a real payments product is Critical, in a sandbox demo is Low.

8. **Generated proof-of-concept attack scenarios.** Given a graph + finding, LLM emits a sequence of HTTP requests / chat turns that demonstrate exploitation — feed this into Lancer's request engine for replay validation.

9. **Diff-summarizer between scans.** When scanning HEAD vs main, LLM summarizes: "this PR adds 3 new tools to the agent. Tool `delete_user` lacks a confirmation step. Tool `send_email` was previously allowlisted to internal domains; that allowlist was removed in this PR." Surface as a CI comment.

## Implementation phases — 12-week roadmap

| Week | Deliverable |
|---|---|
| 1 | Cargo workspace (`lancer-agentic-radar`, `ar-core`, `ar-parsers`, `ar-detectors`, `ar-runtime`, `ar-report`). `AgentGraph` types + petgraph wrapper. Trust-label propagation skeleton. |
| 2 | LangChain Python AST parser via `rustpython-parser`. Recognize `Tool`, `@tool`, `initialize_agent`, `create_react_agent`, `AgentExecutor`. Resolve tool lists across module boundaries. |
| 3 | First 5 detectors: `tb-tool-output-to-next-tool-input`, `ea-shell-tool-without-allowlist`, `pi-user-in-system-prompt`, `miv-no-schema-on-tool-args`, `mof-no-pii-redaction`. Unit tests against LangChain reference agents. |
| 4 | LangGraph parser (`StateGraph`, `add_node`, `add_edge`, `add_conditional_edges`). 5 more detectors targeting state-machine patterns (`infinite-loop`, `recursion-bomb`). |
| 5 | CrewAI parser (Python + YAML dual mode). MCP parser (`mcp.json` + runtime server advertisement parse). Tool-poisoning detector category. |
| 6 | Report layer: Markdown + JSON + SARIF + Mermaid emitter. HTML via askama. CLI flags wired (`--report-format`, `--fail-on`, `--baseline`). |
| 7 | AutoGen + Semantic Kernel + Pydantic AI parsers. Remaining detector categories filled out to ~30 sub-checks. |
| 8 | Vercel AI SDK parser via `tree-sitter-typescript`. OpenAI Assistants JSON parser. Anthropic Computer Use parser. |
| 9 | Dynamic probe layer (`ar-runtime`). `reqwest` + OTEL trace consumer. Cross-correlate dynamic observations with static graph; mark findings as "confirmed" / "static-only". |
| 10 | OWASP LLM Top 10 v2025 + NIST AI RMF + EU AI Act mapping. Each detector tagged with framework citations; report includes compliance section. Dependency-CVE table. |
| 11 | CI integration: GitHub Action wrapping the binary, SARIF upload, baseline-diff mode. Validation against open-source agent repos (LangChain examples, CrewAI demos, MCP reference servers). |
| 12 | AI augmentation: detector-authoring LLM helper, "explain this graph" mode, auto-mitigation patches. Docs, examples, blog post: "Static + dynamic scanning for agentic AI." |

---

## GUI (Lancer-standard pattern)

`lancer-agentic-radar` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-agentic-radar-cli` companion binary), but the **plain `lancer-agentic-radar` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-agentic-radar/`, `%APPDATA%\lancer-agentic-radar\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-agentic-radar-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-agentic-radar.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-agentic-radar.exe` (double-click opens the GUI window).
- Linux: `build/lancer-agentic-radar` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-agentic-radar` (bundled into `lancer-agentic-radar.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-agentic-radar/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-agentic-radar.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-agentic-radar-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-agentic-radar
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-agentic-radar.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-agentic-radar-windows-x86_64\bin\lancer-agentic-radar.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-agentic-radar`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
