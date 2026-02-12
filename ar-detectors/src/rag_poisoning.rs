//! RAG-poisoning sub-checks (plan §"Detector catalog" item 3).
//!
//! Retrieval-augmented generation pulls documents into the agent's context.
//! These checks look at whether the document source is trusted, whether content
//! is validated, whether the store is user-writable, whether retrieved chunks
//! carry source attribution, whether chunk sizes are bounded, and whether the
//! embedding path is an injection vector.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{
    DetectorCategory, EuAiActArticle, Finding, OwaspAgentic2026, OwaspLlm2025, Severity, TrustLabel,
};

define_detectors! {
    /// The RAG source's documents come from an untrusted origin.
    RpUntrustedDocumentSource {
        id: "rp-untrusted-document-source",
        category: DetectorCategory::RagPoisoning,
        severity: Severity::High,
        title: "RAG documents come from an untrusted source",
        detect: |g| {
            let mut out = Vec::new();
            for r in &g.rag {
                if !r.trust.is_tainted() { continue; }
                let f = Finding::new(
                    "rp-untrusted-document-source",
                    DetectorCategory::RagPoisoning,
                    if r.trust == TrustLabel::Untrusted { Severity::High } else { Severity::Medium },
                    "RAG documents come from an untrusted source",
                    format!(
                        "RAG source `{}` ({}) ingests documents from `{}`, classified {}. Untrusted \
                         documents can carry payloads that poison retrieval and inject instructions.",
                        r.name, r.kind,
                        r.document_source.as_deref().unwrap_or("?"),
                        r.trust
                    ),
                )
                .with_evidence(rag_evidence(r))
                .with_location(loc(&r.location))
                .with_fix(
                    "Restrict the retriever to vetted internal corpora, or quarantine and validate \
                     external documents before indexing; mark retrieved content as untrusted data.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::MemoryPoisoning)
                        .with_llm(OwaspLlm2025::DataAndModelPoisoning)
                        .with_llm(OwaspLlm2025::VectorAndEmbeddingWeaknesses)
                        .with_atlas("AML.T0070")
                        .with_eu(EuAiActArticle::Article10DataGovernance)
                }));
            }
            out
        }
    }

    /// No content validation on ingested documents.
    RpNoContentValidation {
        id: "rp-no-content-validation",
        category: DetectorCategory::RagPoisoning,
        severity: Severity::Medium,
        title: "RAG ingestion has no content validation",
        detect: |g| {
            let mut out = Vec::new();
            for r in &g.rag {
                // Heuristic: tainted or unknown-trust source with no attribution
                // is treated as having no validation pipeline.
                if r.trust == TrustLabel::Trusted { continue; }
                let f = Finding::new(
                    "rp-no-content-validation",
                    DetectorCategory::RagPoisoning,
                    Severity::Medium,
                    "RAG ingestion has no content validation",
                    format!(
                        "RAG source `{}` shows no evidence of content validation/sanitization on \
                         ingestion. Malicious markup, hidden instructions, or oversized payloads \
                         can enter the index unchecked.",
                        r.name
                    ),
                )
                .with_evidence(rag_evidence(r))
                .with_location(loc(&r.location))
                .with_fix(
                    "Add an ingestion validation step: strip active content, normalize Unicode, \
                     enforce size limits, and reject documents that contain instruction-like text.",
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

    /// The vector store is writable by untrusted input at runtime.
    RpVectorStoreUserWritable {
        id: "rp-vector-store-user-writable",
        category: DetectorCategory::RagPoisoning,
        severity: Severity::High,
        title: "Vector store is writable by untrusted input",
        detect: |g| {
            let mut out = Vec::new();
            for r in &g.rag {
                if !r.user_writable { continue; }
                let f = Finding::new(
                    "rp-vector-store-user-writable",
                    DetectorCategory::RagPoisoning,
                    Severity::High,
                    "Vector store is writable by untrusted input",
                    format!(
                        "RAG store `{}` ({}) is writable by untrusted input at runtime. An attacker \
                         can inject poisoned documents that later surface in retrieval for other users.",
                        r.name, r.kind
                    ),
                )
                .with_evidence(rag_evidence(r))
                .with_location(loc(&r.location))
                .with_fix(
                    "Separate the ingestion path from untrusted users, require review before \
                     indexing user-supplied content, and isolate per-tenant namespaces.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::MemoryPoisoning)
                        .with_llm(OwaspLlm2025::DataAndModelPoisoning)
                        .with_llm(OwaspLlm2025::VectorAndEmbeddingWeaknesses)
                        .with_atlas("AML.T0070")
                }));
            }
            out
        }
    }

    /// The retriever returns chunks without source attribution.
    RpRetrieverNoSourceAttribution {
        id: "rp-retriever-no-source-attribution",
        category: DetectorCategory::RagPoisoning,
        severity: Severity::Low,
        title: "Retrieved chunks carry no source attribution",
        detect: |g| {
            let mut out = Vec::new();
            for r in &g.rag {
                if r.has_source_attribution { continue; }
                let f = Finding::new(
                    "rp-retriever-no-source-attribution",
                    DetectorCategory::RagPoisoning,
                    Severity::Low,
                    "Retrieved chunks carry no source attribution",
                    format!(
                        "RAG source `{}` returns chunks without source attribution, so the model \
                         (and downstream auditors) cannot tell trusted from untrusted content, nor \
                         trace a poisoned answer back to its document.",
                        r.name
                    ),
                )
                .with_evidence(rag_evidence(r))
                .with_location(loc(&r.location))
                .with_fix(
                    "Attach provenance metadata (source URI, ingestion time, trust tier) to every \
                     retrieved chunk and surface it to the model and the audit trail.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::TraceabilityGap)
                        .with_llm(OwaspLlm2025::Misinformation)
                        .with_eu(EuAiActArticle::Article13Transparency)
                }));
            }
            out
        }
    }

    /// No chunk-size limit on the retriever (DoS / context-stuffing surface).
    RpNoChunkSizeLimit {
        id: "rp-no-chunk-size-limit",
        category: DetectorCategory::RagPoisoning,
        severity: Severity::Low,
        title: "Retriever has no chunk-size limit",
        detect: |g| {
            let mut out = Vec::new();
            for r in &g.rag {
                // Heuristic: kind/source string lacks any chunk/size hint.
                let hay = format!("{} {}", r.kind, r.document_source.as_deref().unwrap_or(""));
                if contains_any(&hay, &["chunk", "max_token", "split", "size", "limit"]) { continue; }
                let f = Finding::new(
                    "rp-no-chunk-size-limit",
                    DetectorCategory::RagPoisoning,
                    Severity::Low,
                    "Retriever has no chunk-size limit",
                    format!(
                        "RAG source `{}` shows no chunk-size / token-limit configuration. Oversized \
                         retrieved chunks can stuff the context window (resource exhaustion) and \
                         hide injected instructions deep inside a long block.",
                        r.name
                    ),
                )
                .with_evidence(rag_evidence(r))
                .with_location(loc(&r.location))
                .with_fix(
                    "Configure a bounded chunk size / overlap and cap the number of retrieved chunks \
                     per query.",
                )
                .with_confidence(ar_core::Confidence::Low);
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::CascadingFailure)
                        .with_llm(OwaspLlm2025::UnboundedConsumption)
                        .with_llm(OwaspLlm2025::VectorAndEmbeddingWeaknesses)
                }));
            }
            out
        }
    }

    /// The embedding/query path itself is an injection vector.
    RpEmbeddingInjectionVector {
        id: "rp-embedding-injection-vector",
        category: DetectorCategory::RagPoisoning,
        severity: Severity::Medium,
        title: "Embedding/query path is an injection vector",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                let rags = g.rag_of(&a.id);
                let tainted = rags.iter().any(|r| r.trust.is_tainted() || r.user_writable);
                // Untrusted query (user input) into a tainted/user-writable store
                // means an attacker can steer retrieval (embedding-space attack).
                if a.accepts_user_input && tainted {
                    let r = rags.iter().find(|r| r.trust.is_tainted() || r.user_writable).unwrap();
                    let f = Finding::new(
                        "rp-embedding-injection-vector",
                        DetectorCategory::RagPoisoning,
                        Severity::Medium,
                        "Embedding/query path is an injection vector",
                        format!(
                            "Agent `{}` embeds untrusted user queries against RAG store `{}` which is \
                             tainted or user-writable. An attacker controlling both the query and the \
                             stored documents can force adversarial retrieval (embedding inversion / \
                             nearest-neighbour steering).",
                            a.name, r.name
                        ),
                    )
                    .with_agent(a.id.clone())
                    .with_evidence(rag_evidence(r))
                    .with_location(loc(&a.location))
                    .with_fix(
                        "Validate and normalize queries, rate-limit retrieval, and prevent untrusted \
                         users from writing into a store they can also query.",
                    );
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::MemoryPoisoning)
                            .with_llm(OwaspLlm2025::VectorAndEmbeddingWeaknesses)
                            .with_llm(OwaspLlm2025::DataAndModelPoisoning)
                            .with_atlas("AML.T0070")
                    }));
                }
            }
            out
        }
    }
}
