# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-agentic-radar` — A security scanner for agentic AI workflows, implemented in Rust as a feature-complete reimplementation of [`splx-ai/agentic-radar`](https://github.com/splx-ai/agentic-radar) with a native desktop GUI. It parses agent workflow definitions, reconstructs the tool graph (tools, RAG sources, memory stores), propagates trust labels across edges, and runs static and optional dynamic security checks. Part of the Lancer 2026 bug-bounty ecosystem, producing JSON, SARIF, Markdown, and HTML reports plus Mermaid/DOT topology diagrams highlighting trust-boundary violations.

## Architecture

This is a Cargo workspace with seven crates:

- `lancer-agentic-radar/src/lib.rs` — top-level library entry point tying the workspace together
- `lancer-agentic-radar/src/main.rs` — binary entry point; dispatches to GUI or CLI
- `lancer-agentic-radar/src/cli.rs` — CLI surface (subcommands: `scan`, `test`, `harden-prompts`, `list-detectors`, `--self-test`)
- `lancer-agentic-radar/src/gui.rs` — native desktop GUI (egui), gated behind the `gui` feature
- `lancer-agentic-radar/src/pipeline.rs` — orchestrates parse → detect → report pipeline
- `lancer-agentic-radar/src/server.rs` — optional local server mode
- `lancer-agentic-radar/src/selftest.rs` — `--self-test` parity-matrix runner
- `lancer-agentic-radar/src/config_load.rs` — loads `ar.toml` / `--config <file.yaml>`
- `ar-core/` — shared types: `Finding`, `Severity`, `Graph`, `Node`, `Trust`, `Compliance`, `Framework`, `Config`, `Report`
- `ar-parsers/` — per-framework parsers: LangChain, LangGraph, CrewAI, AutoGen, Semantic Kernel, Vercel AI SDK, Pydantic AI, OpenAI Assistants, OpenAI Agents SDK, Anthropic Computer Use, MCP, n8n
- `ar-detectors/` — 18 detector categories (~60 sub-checks): prompt injection, tool poisoning, RAG poisoning, memory poisoning, trust-boundary, excessive authority, missing validation, missing output filter, secret leakage, jailbreak pathways, indirect injection, recursion bombs, infinite loops, resource exhaustion, n8n risks, handoff abuse, prompt hardening, OWASP Agentic mappings; `registry.rs` wires them together
- `ar-report/` — output formatters: JSON, SARIF, Markdown, HTML, Graphviz/DOT, governance/compliance mapping
- `ar-hardening/` — offline rule-based prompt rewriting (`rewrite.rs`), LLM-assisted hardening (`llm.rs`), rubric evaluation (`rubric.rs`)
- `ar-runtime/` — dynamic testing: HTTP probe runner (`http.rs`), MCP probe runner (`mcp.rs`), probe definitions (`probes.rs`), grader (`grader.rs`), correlator (`correlate.rs`)
- `tests/` — workspace-level integration tests

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- GUI is gated behind the default `gui` feature; `--no-default-features` builds a headless CLI binary.
- Library code lives in `lancer-agentic-radar/src/lib.rs`; binary entry point in `lancer-agentic-radar/src/main.rs`.
- All shared types (findings, severity, graph, trust, compliance) live in `ar-core` and are referenced via `workspace = true` dependency pins in the root `Cargo.toml`.
- Framework parsers are isolated per-file in `ar-parsers/`; adding a new framework means adding a new `<framework>.rs` and registering it in `lib.rs`.
- Detector categories are isolated per-file in `ar-detectors/`; each detector implements the `Detector` trait from `ar-core` and is registered in `ar-detectors/src/registry.rs`.
- Compliance mappings (OWASP Agentic Top 10 2026, OWASP LLM Top 10 2025, EU AI Act, NIST AI RMF, CSA AICM, MITRE ATLAS) are declared in `ar-core/src/compliance.rs` and emitted by `ar-report/src/governance.rs`.

## Build / test / run

```
build.bat                   # Windows → build\lancer-agentic-radar.exe
./build-linux.sh            # Linux
./build-mac.sh              # macOS
cargo build --release       # standard release build
cargo test                  # unit + integration tests
```

Configuration: drop an `ar.toml` in your scan root (see `ar.toml.example`) to set trusted/untrusted RAG sources, detector exclusions, `fail_on` severities, and compliance modes. `--config <file.yaml>` is also accepted.

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored; if ever tracked, run `git rm --cached plan.md`.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.
- The workspace `rust-version` is `1.75`; do not use language features introduced after that edition.
- The egui family of crates (`egui`, `eframe`, `egui_extras`) must move in lockstep; bump all together in the root `[workspace.dependencies]`.
