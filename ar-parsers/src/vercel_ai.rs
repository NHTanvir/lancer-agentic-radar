//! Vercel AI SDK (TypeScript/JavaScript) parser.
//!
//! Recognizes `generateText({ tools: {...} })`, `streamText`, `generateObject`,
//! and `experimental_*` calls. The keys of the `tools` object literal become
//! tool nodes; `tool({ ... })` definitions and `execute` bodies are scanned for
//! effects.

use crate::common::{balanced, extract_model, extract_system_prompt, infer_effects, locate, mint_id};
use ar_core::{
    AgentGraph, AgentNode, Edge, EdgeKind, Framework, ParseOptions, ToolNode, ToolSource,
};
use regex::Regex;
use std::path::Path;

const FW: Framework = Framework::VercelAI;

/// Detect Vercel AI SDK TS/JS source.
pub fn detect(path: &Path, content: &str) -> bool {
    if !matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("ts") | Some("tsx") | Some("js") | Some("jsx") | Some("mjs")
    ) {
        return false;
    }
    Regex::new(
        r#"(?i)from\s+['"]ai['"]|generateText|streamText|generateObject|streamObject|experimental_|@ai-sdk"#,
    )
    .unwrap()
    .is_match(content)
}

/// Parse Vercel AI SDK source into a partial [`AgentGraph`].
pub fn parse(content: &str, path: &Path, _opts: &ParseOptions) -> AgentGraph {
    let mut g = AgentGraph::new();

    let call_re = Regex::new(
        r"(?i)\b(generateText|streamText|generateObject|streamObject|experimental_generateText|experimental_streamText)\s*\(",
    )
    .unwrap();

    let mut idx = 0usize;
    for m in call_re.find_iter(content) {
        // Argument object is `({ ... })`.
        let after = m.end() - 1;
        let args = balanced(content, after, '(', ')').unwrap_or_default();
        let name = format!("vercel_agent_{idx}");
        idx += 1;
        let id = mint_id("agent", path, &name);
        let mut a = AgentNode::new(id.clone(), name, FW);
        if let Some(sp) = extract_system_prompt(&args).or_else(|| system_kw(&args)) {
            a.set_system_prompt(sp);
        }
        a.model = extract_model(&args).or_else(|| extract_model(content));
        a.accepts_user_input = true;
        a.location = locate(path, content, m.as_str());
        g.add_agent(a);

        // tools: { name: tool({...}), ... }
        if let Some(tools_obj) = object_after(&args, "tools") {
            for (tname, tbody) in object_keys(&tools_obj) {
                let tid = mint_id("tool", path, &tname);
                let mut t = ToolNode::new(tid.clone(), tname);
                t.source = ToolSource::Native;
                let (e, r) = infer_effects(&tbody);
                t.effects = e;
                t.effects_resolved = r;
                t.has_input_schema =
                    tbody.contains("parameters") || tbody.contains("inputSchema") || tbody.contains("z.object");
                if let Some(d) = crate::common::kwarg_string(&tbody, "description") {
                    t.description = Some(d);
                }
                t.location = locate(path, content, m.as_str());
                g.add_tool(t);
                g.add_edge(Edge::new(id.clone(), tid, EdgeKind::Calls));
            }
        }
    }

    g
}

/// `system: "..."` kwarg (Vercel AI uses `system` not `system_prompt`).
fn system_kw(args: &str) -> Option<String> {
    crate::common::kwarg_string(args, "system")
}

/// Return the `{...}` object literal that follows `key:` / `key=`.
fn object_after(args: &str, key: &str) -> Option<String> {
    let re = Regex::new(&format!(r"(?i)\b{}\s*[:=]\s*\{{", regex::escape(key))).unwrap();
    let m = re.find(args)?;
    let open = m.end() - 1;
    balanced(args, open, '{', '}')
}

/// Split a JS object literal body into (key, value-text) pairs at the **top
/// level only**. Nested objects/strings are skipped so inner keys (e.g. a
/// Zod schema's fields) are never mistaken for tools. A key is recognized only
/// when at brace-depth 0 and immediately followed by `:`.
fn object_keys(obj: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = obj.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;

    while i < n {
        let ch = bytes[i];
        // Inside a string: consume until the matching quote.
        if let Some(q) = in_str {
            if ch == b'\\' {
                i += 2;
                continue;
            }
            if ch == q {
                in_str = None;
            }
            i += 1;
            continue;
        }
        match ch {
            b'"' | b'\'' | b'`' => {
                in_str = Some(ch);
                i += 1;
                continue;
            }
            b'{' | b'(' | b'[' => {
                depth += 1;
                i += 1;
                continue;
            }
            b'}' | b')' | b']' => {
                depth -= 1;
                i += 1;
                continue;
            }
            _ => {}
        }
        // At top level, try to read an identifier/quoted key followed by ':'.
        if depth == 0 && (ch.is_ascii_alphabetic() || ch == b'_' || ch == b'$') {
            let kstart = i;
            while i < n && {
                let c = bytes[i];
                c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
            } {
                i += 1;
            }
            let key = &obj[kstart..i];
            // skip whitespace
            let mut j = i;
            while j < n && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\n' || bytes[j] == b'\r') {
                j += 1;
            }
            if j < n && bytes[j] == b':' {
                let val_start = j + 1;
                let (val_end, ndepth, nstr) = scan_value(bytes, val_start);
                let val = obj[val_start..val_end.min(n)].trim().to_string();
                if !matches!(
                    key,
                    "description" | "parameters" | "inputSchema" | "execute" | "type" | "model" | "system" | "prompt"
                ) {
                    out.push((key.to_string(), val));
                }
                i = val_end;
                depth = ndepth;
                in_str = nstr;
                continue;
            }
            // not a key; fall through (i already advanced past the identifier)
            continue;
        }
        i += 1;
    }
    out
}

/// From `start`, scan a value until the next top-level comma or the close of
/// the enclosing object. Returns (end_index, depth_after, in_str_after) so the
/// outer scanner can resume correctly.
fn scan_value(bytes: &[u8], start: usize) -> (usize, i32, Option<u8>) {
    let n = bytes.len();
    let mut i = start;
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    while i < n {
        let ch = bytes[i];
        if let Some(q) = in_str {
            if ch == b'\\' {
                i += 2;
                continue;
            }
            if ch == q {
                in_str = None;
            }
            i += 1;
            continue;
        }
        match ch {
            b'"' | b'\'' | b'`' => in_str = Some(ch),
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => {
                if depth == 0 {
                    // close of enclosing object reached
                    return (i, 0, None);
                }
                depth -= 1;
            }
            b',' if depth == 0 => return (i + 1, 0, None),
            _ => {}
        }
        i += 1;
    }
    (i, depth, in_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_generate_text_tools() {
        let src = r#"
import { generateText, tool } from 'ai';
const result = await generateText({
  model: openai('gpt-4o'),
  system: "You are a weather bot.",
  tools: {
    getWeather: tool({ description: "fetch weather", parameters: z.object({}), execute: async () => { await fetch('https://api') } }),
  },
});
"#;
        assert!(detect(Path::new("a.ts"), src));
        let g = parse(src, Path::new("a.ts"), &ParseOptions::default());
        assert!(!g.agents.is_empty());
        assert!(g.tools.iter().any(|t| t.name == "getWeather"));
        assert!(g.tools.iter().any(|t| t.effects.net_egress));
    }
}
