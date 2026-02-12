//! HTTP client for the live agent endpoint.
//!
//! The agent under test is assumed to expose a single chat-style HTTP endpoint
//! that accepts a JSON body `{"input": "<prompt>"}` and returns either plain
//! text or a JSON object with the answer under one of several common field
//! names. We POST the prompt, optionally with a bearer token, and extract a
//! best-effort text field from the response.

use crate::error::RuntimeError;
use ar_core::TestOptions;
use std::time::Duration;

/// Build a [`reqwest::Client`] honoring the request timeout from `opts`.
pub fn build_client(opts: &TestOptions) -> Result<reqwest::Client, RuntimeError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(opts.timeout_secs.max(1)))
        .user_agent(concat!("lancer-agentic-radar/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| RuntimeError::Http(e.to_string()))
}

/// Send a single prompt to `opts.endpoint` and return the agent's text reply.
///
/// Posts `{"input": prompt}` as JSON, adding `Authorization: Bearer <token>`
/// when `opts.auth` is set. The response is parsed best-effort: if the body is
/// JSON we look for an `output` / `response` / `content` / `message` /
/// `text` / `answer` field (top-level or nested under `data` / `choices[0]`);
/// otherwise we return the raw body text.
pub async fn send_prompt(
    client: &reqwest::Client,
    opts: &TestOptions,
    prompt: &str,
) -> Result<String, RuntimeError> {
    let endpoint = opts
        .endpoint
        .as_deref()
        .ok_or_else(|| RuntimeError::Other("no agent endpoint configured".to_string()))?;

    let body = serde_json::json!({ "input": prompt });

    let mut req = client.post(endpoint).json(&body);
    if let Some(token) = opts.auth.as_deref() {
        req = req.bearer_auth(token);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| RuntimeError::Http(e.to_string()))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| RuntimeError::Http(e.to_string()))?;

    if !status.is_success() {
        return Err(RuntimeError::Http(format!(
            "endpoint returned HTTP {}: {}",
            status.as_u16(),
            truncate(&text, 200)
        )));
    }

    Ok(extract_text(&text))
}

/// Pull a best-effort answer string out of a response body.
///
/// Public so the SSE MCP path and tests can reuse the same extraction logic.
pub fn extract_text(body: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => json_text(&v).unwrap_or_else(|| body.to_string()),
        // Not JSON — return the raw body.
        Err(_) => body.to_string(),
    }
}

/// Field names, in priority order, under which an agent answer may live.
const TEXT_FIELDS: &[&str] = &[
    "output", "response", "content", "message", "text", "answer", "result", "reply",
];

/// Recursively search a JSON value for the most likely answer text.
fn json_text(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(map) => {
            // 1. Direct, well-known string fields.
            for key in TEXT_FIELDS {
                if let Some(serde_json::Value::String(s)) = map.get(*key) {
                    if !s.trim().is_empty() {
                        return Some(s.clone());
                    }
                }
            }
            // 2. OpenAI-style: choices[0].message.content / choices[0].text.
            if let Some(serde_json::Value::Array(choices)) = map.get("choices") {
                if let Some(first) = choices.first() {
                    if let Some(t) = json_text(first) {
                        return Some(t);
                    }
                }
            }
            // 3. Nested envelopes: data / result / message objects.
            for key in ["data", "result", "message", "output", "response"] {
                if let Some(inner) = map.get(key) {
                    if !inner.is_string() {
                        if let Some(t) = json_text(inner) {
                            return Some(t);
                        }
                    }
                }
            }
            None
        }
        serde_json::Value::Array(arr) => arr.iter().find_map(json_text),
        _ => None,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_plain_text_body() {
        assert_eq!(extract_text("hello world"), "hello world");
    }

    #[test]
    fn extracts_output_field() {
        assert_eq!(extract_text(r#"{"output":"hi there"}"#), "hi there");
    }

    #[test]
    fn extracts_response_field() {
        assert_eq!(extract_text(r#"{"response":"answer"}"#), "answer");
    }

    #[test]
    fn extracts_openai_style_choices() {
        let body = r#"{"choices":[{"message":{"content":"the reply"}}]}"#;
        assert_eq!(extract_text(body), "the reply");
    }

    #[test]
    fn extracts_nested_data_envelope() {
        let body = r#"{"data":{"answer":"deep value"}}"#;
        assert_eq!(extract_text(body), "deep value");
    }

    #[test]
    fn falls_back_to_raw_for_unknown_json_shape() {
        let body = r#"{"unexpected":42}"#;
        assert_eq!(extract_text(body), body);
    }
}
