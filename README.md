# lancer-agentic-radar

A security scanner for **agentic AI workflows** — a Rust reimplementation of
[`splx-ai/agentic-radar`](https://github.com/splx-ai/agentic-radar) (Apache-2.0)
with full feature parity **plus a native desktop GUI**. Part of the Lancer
ecosystem.

It parses an agent workflow definition, **reconstructs the tool graph** (which
tools each agent may call, which RAG sources it queries, which memory stores it
reads/writes), propagates **trust labels** across the edges, and runs static +
optional dynamic security checks. Output is a JSON / SARIF / Markdown / HTML
report plus a **Mermaid/DOT diagram** of the topology with red edges where trust
boundaries break.

> 🚧 Active development. Run the build yourself (see below) — see `plan.md`
> (local, gitignored) for the full design.

## Frameworks

LangChain · LangGraph · CrewAI · AutoGen · Semantic Kernel · Vercel AI SDK ·
Pydantic AI · OpenAI Assistants · OpenAI Agents SDK · Anthropic Computer Use ·
MCP · n8n.

## What it checks

18 detector categories (~60 sub-checks): prompt injection, tool poisoning, RAG
poisoning, memory poisoning, trust-boundary violations, excessive tool
authority, missing input validation, missing output filtering, secret leakage,
jailbreak pathways, indirect injection, recursion bombs, infinite loops,
resource exhaustion, n8n-specific risks, OpenAI Agents SDK handoff abuse, and
prompt-hardening gaps — each mapped to **OWASP Top 10 for Agentic Applications
2026**, **OWASP LLM Top 10 2025**, **OWASP AIVSS**, **EU AI Act**,
**NIST AI RMF**, **CSA AICM**, and **MITRE ATLAS**.

## Usage

The plain invocation opens the **native GUI**:

```
lancer-agentic-radar
```

Pass a subcommand (or `--cli`) for the command-line surface:

```bash
# Static scan → JSON on stdout
lancer-agentic-radar scan ./my-agent

# SARIF for GitHub code scanning, fail CI on high+ findings
lancer-agentic-radar scan . --report-format sarif -o radar.sarif --fail-on critical,high

# Markdown + HTML + graph files, with compliance mapping
lancer-agentic-radar scan . --report-format md,html --emit-graph \
  --compliance-mode owasp-agentic-top10-2026,eu-ai-act -o report

# Force a framework, MCP-only, baseline diff
lancer-agentic-radar scan . --framework crewai --baseline main.sarif

# Dynamic testing against a live agent endpoint
lancer-agentic-radar test ./my-agent --endpoint https://agent.example/api \
  --test-categories prompt-injection,pii-leakage

# Probe an MCP server for tool-poisoning
lancer-agentic-radar test --mcp-endpoint stdio:///path/to/server

# Rewrite weak system prompts (offline rule-based by default)
lancer-agentic-radar harden-prompts ./my-agent -o hardened.md

# List detectors / run the parity matrix
lancer-agentic-radar list-detectors
lancer-agentic-radar --self-test
```

The headless companion binary `lancer-agentic-radar-cli` always runs the CLI.

### Configuration

Drop an `ar.toml` in your scan root (see `ar.toml.example`) to set trusted /
untrusted RAG sources, detector exclusions, `fail_on` severities, and compliance
modes. `--config <file.yaml>` is also accepted.

## GUI

A three-pane desktop app (inputs · results · detail) built with `egui`:

- pick a target folder, framework, and options; **Scan** runs on a background
  worker so the UI never blocks;
- sortable findings table with severity badges and a severity bar chart;
- per-finding detail with evidence, fix, compliance codes, and hardened-prompt
  rewrites;
- Mermaid graph source export; report export to JSON/SARIF/MD/HTML;
- a local integration HTTP server (`127.0.0.1:<port>`, written to
  `%TEMP%/lancer-agentic-radar.port`) so other Lancer tools can `Send to…`
  (`GET /v1/state`, `POST /v1/import`, `GET /v1/export?format=…`).

## Build

### Windows
```
build.bat
```
Output: `build\lancer-agentic-radar.exe` (double-click to open the GUI). For a
packaged dist build: `build-windows.bat` → `dist\lancer-agentic-radar-windows-x86_64\`.

### Linux / macOS
```bash
./build-linux.sh          # → build/lancer-agentic-radar  (--install adds a .desktop entry)
./build-mac.sh            # → build/lancer-agentic-radar  (+ .app via cargo-bundle if present)
```

Or directly with Cargo:
```bash
cargo build --release --workspace
```

### Requirements
- [Rust / Cargo](https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022
- Linux GUI: GTK/X11/Wayland dev libs (for `egui`/`rfd` native dialogs)

## Workspace layout

| Crate | Role |
|-------|------|
| `lancer-agentic-radar` | CLI + GUI binary (this is what you run) |
| `ar-core` | shared types: `AgentGraph`, trust labels, findings, compliance mappings |
| `ar-parsers` | one parser per framework → uniform `AgentGraph` |
| `ar-detectors` | security detectors over the graph |
| `ar-runtime` | dynamic probe / `test` runner (HTTP + MCP transports) |
| `ar-hardening` | system-prompt hardening engine |
| `ar-report` | JSON/SARIF/Markdown/HTML + Mermaid/DOT emitters + governance exports |

## License

MIT — see [LICENSE](LICENSE).
