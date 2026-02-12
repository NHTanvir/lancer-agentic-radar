//! Machine-readable JSON report: the full [`ar_core::Report`] (graph + findings
//! + stats + compliance summary) serialized with `serde_json`.

use ar_core::Report;

/// Render the report as pretty-printed JSON.
///
/// [`Report`] derives `Serialize`, so this is a straight
/// `serde_json::to_string_pretty`. Serialization of a well-formed report cannot
/// realistically fail, but we never panic: on error we emit a minimal JSON
/// error object so callers always get valid JSON back.
pub fn render(report: &Report) -> String {
    match serde_json::to_string_pretty(report) {
        Ok(s) => s,
        Err(e) => format!(
            "{{\n  \"error\": \"failed to serialize report\",\n  \"detail\": {}\n}}",
            serde_json::to_string(&e.to_string())
                .unwrap_or_else(|_| "\"serialization error\"".to_string())
        ),
    }
}
