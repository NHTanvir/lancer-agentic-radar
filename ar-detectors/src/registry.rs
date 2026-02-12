//! The detector registry: assembles one instance of every sub-check.
//!
//! [`all_detectors`] is the single source of truth; [`crate::registry`] (the
//! `DetectorMeta` list) and [`crate::run_all`] are both built on top of it.

use crate::detector::Detector;

/// Push a boxed unit-struct detector onto `v` (terse registration helper).
macro_rules! reg {
    ($v:ident, $($d:path),+ $(,)?) => {
        $( $v.push(Box::new(<$d>::default()) as Box<dyn Detector>); )+
    };
}

/// Build a fresh boxed instance of every registered detector, in catalog order.
pub fn all_detectors() -> Vec<Box<dyn Detector>> {
    let mut v: Vec<Box<dyn Detector>> = Vec::new();

    // 1. prompt-injection
    reg!(
        v,
        crate::prompt_injection::PiUserInSystemPrompt,
        crate::prompt_injection::PiUntrustedRagInSystemPrompt,
        crate::prompt_injection::PiToolResultConcatenatedWithoutDelim,
        crate::prompt_injection::PiSystemPromptLeakViaEcho,
        crate::prompt_injection::PiNoRoleSeparator,
        crate::prompt_injection::PiTemplateVariableUnescaped,
    );

    // 2. tool-poisoning
    reg!(
        v,
        crate::tool_poisoning::TpMcpUntrustedServer,
        crate::tool_poisoning::TpToolDescriptionFromUntrustedSource,
        crate::tool_poisoning::TpParameterSchemaPermissive,
        crate::tool_poisoning::TpRuntimeToolRegistration,
        crate::tool_poisoning::TpMcpServerNoSignatureCheck,
        crate::tool_poisoning::TpToolNameCollision,
    );

    // 3. rag-poisoning
    reg!(
        v,
        crate::rag_poisoning::RpUntrustedDocumentSource,
        crate::rag_poisoning::RpNoContentValidation,
        crate::rag_poisoning::RpVectorStoreUserWritable,
        crate::rag_poisoning::RpRetrieverNoSourceAttribution,
        crate::rag_poisoning::RpNoChunkSizeLimit,
        crate::rag_poisoning::RpEmbeddingInjectionVector,
    );

    // 4. memory-poisoning
    reg!(
        v,
        crate::memory_poisoning::MpCrossSessionMemoryShared,
        crate::memory_poisoning::MpUntrustedInputWrittenToMemory,
        crate::memory_poisoning::MpNoMemoryEvictionPolicy,
        crate::memory_poisoning::MpMemoryStoredVerbatim,
        crate::memory_poisoning::MpMemoryNoTenantIsolation,
    );

    // 5. trust-boundary
    reg!(
        v,
        crate::trust_boundary::TbToolOutputToNextToolInput,
        crate::trust_boundary::TbRagDocToShellTool,
        crate::trust_boundary::TbUserInputToEval,
        crate::trust_boundary::TbLlmOutputToFsWrite,
        crate::trust_boundary::TbLlmOutputToSqlQuery,
        crate::trust_boundary::TbMcpResultToShell,
    );

    // 6. excessive-authority
    reg!(
        v,
        crate::excessive_authority::EaShellToolWithoutAllowlist,
        crate::excessive_authority::EaPaymentToolWithout2fa,
        crate::excessive_authority::EaEmailToolBroadcast,
        crate::excessive_authority::EaNetworkEgressUnbounded,
        crate::excessive_authority::EaFsWriteAnywhere,
        crate::excessive_authority::EaDbDeleteWithoutWhere,
        crate::excessive_authority::EaCloudIamOverscope,
        crate::excessive_authority::EaComputerUseWithoutConfirm,
    );

    // 7. missing-input-validation
    reg!(
        v,
        crate::missing_validation::MivNoSchemaOnToolArgs,
        crate::missing_validation::MivNoLengthLimit,
        crate::missing_validation::MivNoAllowlistOnUrl,
        crate::missing_validation::MivNoPathTraversalCheck,
        crate::missing_validation::MivNoContentTypeCheck,
    );

    // 8. missing-output-filter
    reg!(
        v,
        crate::missing_output_filter::MofNoPiiRedaction,
        crate::missing_output_filter::MofNoSecretPatternFilter,
        crate::missing_output_filter::MofRawStackTrace,
        crate::missing_output_filter::MofNoContentPolicy,
        crate::missing_output_filter::MofNoJailbreakOutputDetector,
    );

    // 9. secret-leakage
    reg!(
        v,
        crate::secret_leakage::SlHardcodedApiKey,
        crate::secret_leakage::SlEnvVarToLlmContext,
        crate::secret_leakage::SlSecretInSystemPrompt,
        crate::secret_leakage::SlSecretInToolDescription,
    );

    // 10. jailbreak-pathway
    reg!(
        v,
        crate::jailbreak_pathway::JbSystemPromptOverridable,
        crate::jailbreak_pathway::JbDanSkeletonkeyPattern,
        crate::jailbreak_pathway::JbMissingConfidentialityClause,
    );

    // 11. indirect-injection
    reg!(
        v,
        crate::indirect_injection::IiRagOutputUnsanitized,
        crate::indirect_injection::IiMcpOutputNoTrustLabel,
        crate::indirect_injection::IiEmailWebpageToolToContext,
    );

    // 12. recursion-bomb
    reg!(
        v,
        crate::recursion_bomb::RbAgentSelfCallNoCap,
        crate::recursion_bomb::RbMutualRecursion,
    );

    // 13. infinite-loop
    reg!(
        v,
        crate::infinite_loop::IlWhileTrueNoTimeout,
        crate::infinite_loop::IlLanggraphCycleNoExit,
    );

    // 14. resource-exhaustion
    reg!(
        v,
        crate::resource_exhaustion::ReTokenBudgetUnbounded,
        crate::resource_exhaustion::ReNoMaxSteps,
        crate::resource_exhaustion::ReNoRateLimit,
        crate::resource_exhaustion::ReNoCostCap,
    );

    // 15. owasp-agentic-2026 meta-detector
    reg!(v, crate::owasp_agentic::OwaspAgenticMeta);

    // 16. n8n-workflow-risks
    reg!(
        v,
        crate::n8n_risks::N8nWebhookTriggerPublicWithoutAuth,
        crate::n8n_risks::N8nCredentialSharedAcrossWorkflows,
        crate::n8n_risks::N8nCodeNodeNoSandbox,
        crate::n8n_risks::N8nHttpRequestEgressUnbounded,
        crate::n8n_risks::N8nAiAgentToolFanOut,
        crate::n8n_risks::N8nMcpNodeUntrustedServer,
    );

    // 17. handoff-abuse
    reg!(
        v,
        crate::handoff_abuse::OaHandoffWithoutInputFilter,
        crate::handoff_abuse::OaHandoffLoopNoCap,
        crate::handoff_abuse::OaAgentAsToolNoScoping,
        crate::handoff_abuse::OaGuardrailDisabled,
        crate::handoff_abuse::OaTracingDisabledInProd,
    );

    // 18. prompt-hardening-needed
    reg!(
        v,
        crate::prompt_hardening::PhNoRoleSeparator,
        crate::prompt_hardening::PhNoRefusalClause,
        crate::prompt_hardening::PhNoOutputFormatConstraint,
        crate::prompt_hardening::PhNoAntiJailbreakPreamble,
    );

    v
}
