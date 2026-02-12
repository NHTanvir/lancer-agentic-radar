//! Memory-poisoning sub-checks (plan §"Detector catalog" item 4, and
//! §"Engineering hard parts" #12 multi-tenant memory).
//!
//! Persistent memory stores carry content across runs. Anything written by a
//! prior (possibly malicious) input is "in" the store. These checks flag stores
//! shared across sessions, stores whose write path is reachable from untrusted
//! input, missing eviction policies, verbatim storage, and the critical missing
//! tenant-isolation case for multi-tenant data.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{
    DetectorCategory, EdgeKind, Finding, NodeId, OwaspAgentic2026, OwaspLlm2025, Severity,
    TrustLabel,
};

/// Whether an untrusted source can reach (write to) the memory node `mem`.
fn untrusted_write_reaches(g: &ar_core::AgentGraph, mem: &NodeId) -> Option<NodeId> {
    let labels = g.trust_labels();
    // Any agent that *writes* to this store and is itself tainted.
    for e in g.edges.iter().filter(|e| &e.to == mem && e.kind == EdgeKind::Writes) {
        if labels.get(&e.from).map(|l| l.is_tainted()).unwrap_or(false) {
            return Some(e.from.clone());
        }
    }
    None
}

define_detectors! {
    /// Memory is shared across sessions/runs.
    MpCrossSessionMemoryShared {
        id: "mp-cross-session-memory-shared",
        category: DetectorCategory::MemoryPoisoning,
        severity: Severity::Medium,
        title: "Memory store shared across sessions",
        detect: |g| {
            let mut out = Vec::new();
            for m in &g.memory {
                if !m.cross_session { continue; }
                let f = Finding::new(
                    "mp-cross-session-memory-shared",
                    DetectorCategory::MemoryPoisoning,
                    Severity::Medium,
                    "Memory store shared across sessions",
                    format!(
                        "Memory store `{}` ({}) persists across sessions/runs. Content written in \
                         one (possibly malicious) session is read back in later sessions, enabling \
                         persistent memory poisoning.",
                        m.name, m.kind
                    ),
                )
                .with_evidence(memory_evidence(m))
                .with_location(loc(&m.location))
                .with_fix(
                    "Scope memory to a single session/user where possible; if shared memory is \
                     required, validate writes and isolate by tenant/session key.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::MemoryPoisoning)
                        .with_llm(OwaspLlm2025::DataAndModelPoisoning)
                        .with_atlas("AML.T0070")
                }));
            }
            out
        }
    }

    /// Untrusted input is written into a memory store.
    MpUntrustedInputWrittenToMemory {
        id: "mp-untrusted-input-written-to-memory",
        category: DetectorCategory::MemoryPoisoning,
        severity: Severity::High,
        title: "Untrusted input written to memory",
        detect: |g| {
            let mut out = Vec::new();
            for m in &g.memory {
                if let Some(src) = untrusted_write_reaches(g, &m.id) {
                    let f = Finding::new(
                        "mp-untrusted-input-written-to-memory",
                        DetectorCategory::MemoryPoisoning,
                        if m.cross_session { Severity::High } else { Severity::Medium },
                        "Untrusted input written to memory",
                        format!(
                            "Memory store `{}` is written by `{}`, which carries tainted (untrusted) \
                             data. Poisoned content stored here can later steer the agent's decisions.",
                            m.name,
                            g.name_of(&src)
                        ),
                    )
                    .with_evidence(memory_evidence(m))
                    .with_location(loc(&m.location))
                    .with_fix(
                        "Validate and sanitize content before persisting it; never store raw \
                         untrusted text verbatim; tag stored entries with their trust tier.",
                    );
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::MemoryPoisoning)
                            .with_llm(OwaspLlm2025::DataAndModelPoisoning)
                            .with_atlas("AML.T0070")
                    }));
                }
            }
            out
        }
    }

    /// A persistent store has no eviction / TTL policy.
    MpNoMemoryEvictionPolicy {
        id: "mp-no-memory-eviction-policy",
        category: DetectorCategory::MemoryPoisoning,
        severity: Severity::Low,
        title: "Memory store has no eviction policy",
        detect: |g| {
            let mut out = Vec::new();
            for m in &g.memory {
                if m.has_eviction_policy { continue; }
                // Only meaningful for persistent stores.
                if !m.cross_session {
                    let k = m.kind.to_ascii_lowercase();
                    let persistent = contains_any(&k, &["redis", "pinecone", "qdrant", "chroma", "weaviate", "mem0", "postgres", "pgvector", "vector", "db"]);
                    if !persistent { continue; }
                }
                let f = Finding::new(
                    "mp-no-memory-eviction-policy",
                    DetectorCategory::MemoryPoisoning,
                    Severity::Low,
                    "Memory store has no eviction policy",
                    format!(
                        "Memory store `{}` ({}) has no eviction/TTL policy, so poisoned or stale \
                         entries persist indefinitely and accumulate.",
                        m.name, m.kind
                    ),
                )
                .with_evidence(memory_evidence(m))
                .with_location(loc(&m.location))
                .with_fix(
                    "Configure a TTL / size-bounded eviction policy and periodically re-validate \
                     long-lived memory entries.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::MemoryPoisoning)
                        .with_llm(OwaspLlm2025::UnboundedConsumption)
                }));
            }
            out
        }
    }

    /// Memory stored verbatim (no summarization / sanitization on write).
    MpMemoryStoredVerbatim {
        id: "mp-memory-stored-verbatim",
        category: DetectorCategory::MemoryPoisoning,
        severity: Severity::Low,
        title: "Memory stored verbatim",
        detect: |g| {
            let mut out = Vec::new();
            for m in &g.memory {
                let k = m.kind.to_ascii_lowercase();
                // Buffer-style memories store the raw transcript verbatim.
                let verbatim = contains_any(&k, &["buffer", "conversationbuffer", "raw", "history", "chatmessagehistory"]);
                if !verbatim { continue; }
                let f = Finding::new(
                    "mp-memory-stored-verbatim",
                    DetectorCategory::MemoryPoisoning,
                    Severity::Low,
                    "Memory stored verbatim",
                    format!(
                        "Memory store `{}` ({}) keeps the raw conversation verbatim. Verbatim \
                         storage of untrusted turns means any injected instruction is replayed back \
                         into context on the next turn.",
                        m.name, m.kind
                    ),
                )
                .with_evidence(memory_evidence(m))
                .with_location(loc(&m.location))
                .with_fix(
                    "Summarize / structure memory instead of storing raw turns verbatim, and strip \
                     instruction-like content before persisting.",
                )
                .with_confidence(ar_core::Confidence::Low);
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::MemoryPoisoning)
                        .with_llm(OwaspLlm2025::DataAndModelPoisoning)
                }));
            }
            out
        }
    }

    /// Multi-tenant memory with no tenant isolation (plan hard-part #12).
    MpMemoryNoTenantIsolation {
        id: "mp-memory-no-tenant-isolation",
        category: DetectorCategory::MemoryPoisoning,
        severity: Severity::Critical,
        title: "Multi-tenant memory without tenant isolation",
        detect: |g| {
            let labels = g.trust_labels();
            let mut out = Vec::new();
            for m in &g.memory {
                if m.tenant_isolated { continue; }
                // Critical only when the store is cross-session (shared) AND a
                // tainted writer can reach it — i.e. it can hold mixed-tenant data.
                let shared = m.cross_session
                    || labels.get(&m.id).map(|l| *l == TrustLabel::Mixed || l.is_tainted()).unwrap_or(false);
                let tainted_writer = untrusted_write_reaches(g, &m.id).is_some();
                if !shared { continue; }
                let sev = if tainted_writer { Severity::Critical } else { Severity::High };
                let f = Finding::new(
                    "mp-memory-no-tenant-isolation",
                    DetectorCategory::MemoryPoisoning,
                    sev,
                    "Multi-tenant memory without tenant isolation",
                    format!(
                        "Memory store `{}` ({}) is shared/cross-session but applies no tenant \
                         isolation (metadata filter). One tenant can read or poison another \
                         tenant's memory.",
                        m.name, m.kind
                    ),
                )
                .with_evidence(memory_evidence(m))
                .with_location(loc(&m.location))
                .with_fix(
                    "Partition the store by tenant id and apply the tenant filter on every read AND \
                     write; verify the filter is bound to the authenticated principal, not the \
                     model's free choice.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::MemoryPoisoning)
                        .with_agentic(OwaspAgentic2026::IdentityAbuse)
                        .with_llm(OwaspLlm2025::DataAndModelPoisoning)
                        .with_llm(OwaspLlm2025::SensitiveInformationDisclosure)
                        .with_atlas("AML.T0070")
                }));
            }
            out
        }
    }
}
