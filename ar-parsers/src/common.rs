//! Shared helpers used by every framework parser: tool-effect inference,
//! system-prompt extraction, id minting, source-location/snippet helpers, and
//! RAG trust classification.
//!
//! The heuristics here are deliberately regex/string based rather than full
//! AST analysis — this keeps them robust across the constant API churn of the
//! agent frameworks and dependency-light. Quality is best-effort and
//! conservative: a missed effect degrades to an `unknown-tool-effects` audit
//! signal downstream rather than a hard failure.

use ar_core::{ParseOptions, RAGSource, SourceLocation, ToolEffects, TrustLabel};
use regex::Regex;
use std::path::Path;

// ---------------------------------------------------------------------------
// Regex helpers — compiled per call. Building a `Regex` is cheap relative to
// the file I/O around it, and per-call construction sidesteps any `OnceLock`
// lifetime subtleties. Patterns are authored to never fail to compile.
// ---------------------------------------------------------------------------

/// Compile a regex, panicking only on a programmer error (a malformed literal
/// pattern in this file). All patterns are unit-tested indirectly.
fn rx(pattern: &str) -> Regex {
    Regex::new(pattern).expect("internal regex pattern should compile")
}

/// Case-insensitive variant.
fn rxi(pattern: &str) -> Regex {
    Regex::new(&format!("(?i){pattern}")).expect("internal regex pattern should compile")
}

// ---------------------------------------------------------------------------
// id minting
// ---------------------------------------------------------------------------

/// Sanitize an arbitrary label into an id-friendly token (alnum + `_`/`-`).
pub fn slug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            out.push(c);
        } else if c == '.' || c == '/' || c == '\\' || c == ' ' {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("anon");
    }
    out
}

/// Short, stable basename of a path for use inside ids (no extension).
pub fn file_stem(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .map(|s| slug(&s))
        .unwrap_or_else(|| "file".to_string())
}

/// Mint a node id of the form `<kind>:<file>:<name>` so ids stay unique across
/// files yet dedup cleanly when the same construct is seen twice.
pub fn mint_id(kind: &str, path: &Path, name: &str) -> String {
    format!("{}:{}:{}", kind, file_stem(path), slug(name))
}

// ---------------------------------------------------------------------------
// location / snippet helpers
// ---------------------------------------------------------------------------

/// Largest byte index `<= idx` that lies on a UTF-8 char boundary. Used to
/// keep window/snippet slicing panic-free on multi-byte input.
pub fn char_boundary_floor(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// 1-based line number of the byte offset `pos` within `content`.
pub fn line_at(content: &str, pos: usize) -> u32 {
    let upto = if pos > content.len() {
        content.len()
    } else {
        pos
    };
    (content[..upto].bytes().filter(|&b| b == b'\n').count() as u32) + 1
}

/// Find the first byte offset of `needle` in `content`, if present.
pub fn offset_of(content: &str, needle: &str) -> Option<usize> {
    content.find(needle)
}

/// A trimmed single-line snippet for the line containing byte offset `pos`.
pub fn snippet_at(content: &str, pos: usize) -> String {
    let start = content[..pos.min(content.len())]
        .rfind('\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let end = content[pos.min(content.len())..]
        .find('\n')
        .map(|i| pos + i)
        .unwrap_or(content.len());
    content[start..end].trim().to_string()
}

/// Build a [`SourceLocation`] for `path` pointing at the line containing the
/// first occurrence of `anchor` (falls back to the file with no line).
pub fn locate(path: &Path, content: &str, anchor: &str) -> SourceLocation {
    match offset_of(content, anchor) {
        Some(pos) => SourceLocation::new(path)
            .at_line(line_at(content, pos))
            .with_snippet(snippet_at(content, pos)),
        None => SourceLocation::new(path),
    }
}

// ---------------------------------------------------------------------------
// string-literal helpers
// ---------------------------------------------------------------------------

/// Strip a single layer of matching quotes from a literal token, also handling
/// Python/TS string prefixes (`r`, `f`, `b`, `u`, and combinations) and triple
/// quotes. If the token is NOT a quoted literal it is returned unchanged
/// (trimmed) — crucially, a prefix letter (`r`/`f`/…) is only dropped when it is
/// immediately followed by a quote, so a bare word like `Researcher` is never
/// mangled.
pub fn unquote(raw: &str) -> String {
    let trimmed = raw.trim();
    // Only peel a string prefix if a quote follows it. We tolerate up to two
    // prefix letters (e.g. `rb"..."`).
    let candidate = {
        let mut rest = trimmed;
        for _ in 0..2 {
            let mut chars = rest.chars();
            match chars.next() {
                Some(c) if matches!(c, 'r' | 'R' | 'f' | 'F' | 'b' | 'B' | 'u' | 'U') => {
                    let tail = chars.as_str();
                    if tail.starts_with('"') || tail.starts_with('\'') {
                        rest = tail;
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
        rest
    };

    for q in ["\"\"\"", "'''"] {
        if let Some(inner) = candidate.strip_prefix(q).and_then(|x| x.strip_suffix(q)) {
            return inner.to_string();
        }
    }
    for q in ['"', '\'', '`'] {
        if candidate.len() >= 2 && candidate.starts_with(q) && candidate.ends_with(q) {
            return candidate[1..candidate.len() - 1].to_string();
        }
    }
    // Not a quoted literal — return the original trimmed token untouched.
    trimmed.to_string()
}

/// Extract the first string literal (single, double, backtick, or triple
/// quoted) appearing at/after byte offset `from` in `content`.
pub fn first_string_literal(content: &str, from: usize) -> Option<String> {
    let hay = &content[from.min(content.len())..];
    // Skip any string prefix (f/r/b/u and combinations) and leading whitespace,
    // anchored at the start so we return the literal that *immediately* follows
    // the caller's position rather than some unrelated literal later in the file.
    // Triple-quoted first (greedy-safe via non-greedy match).
    let triple = rx(r#"(?s)^\s*[rRfFbBuU]{0,2}(?:"""(.*?)"""|'''(.*?)''')"#);
    if let Some(c) = triple.captures(hay) {
        if let Some(m) = c.get(1).or_else(|| c.get(2)) {
            return Some(m.as_str().to_string());
        }
    }
    let single = rx(r#"(?s)^\s*[rRfFbBuU]{0,2}(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|`([^`]*)`)"#);
    single.captures(hay).and_then(|c| {
        c.get(1)
            .or_else(|| c.get(2))
            .or_else(|| c.get(3))
            .map(|m| m.as_str().to_string())
    })
}

// ---------------------------------------------------------------------------
// tool-effect inference
// ---------------------------------------------------------------------------

/// Infer the side effects a tool performs by pattern-matching its body /
/// surrounding source. Returns the effects plus a flag indicating whether
/// anything resolved (mirrors [`ToolEffects::is_known`], but also accounts for
/// an explicit empty `effects=[]` override).
///
/// Recognized patterns (per plan §9):
/// - `subprocess.` / `os.system` / `shell=True` / `Popen` → `shell_exec`
/// - `open(..., 'w'|'a')` / `write_text` / `fs.writeFile` / `WriteFile` → `writes_fs`
/// - `open(..., 'r')` / `read_text` / `readFile` → `reads_fs`
/// - `requests.` / `httpx.` / `urllib` / `aiohttp` / `fetch(` / `axios.` / `http.get` → `net_egress`
/// - `sqlalchemy` / `psycopg` / `pymongo` / `INSERT|UPDATE|DELETE` → `db_write`
/// - `eval(` / `exec(` / `new Function` → `code_eval`
/// - `smtplib` / `sendmail` / `send_email` / `SMTP` → `email`
/// - `stripe` / `paypal` / `charge` / `payment` → `payment`
///
/// An explicit `@tool(effects=[...])` / `effects=[...]` annotation overrides the
/// inferred set entirely.
pub fn infer_effects(body: &str) -> (ToolEffects, bool) {
    // 1) Explicit override via effects=[...] metadata wins.
    if let Some((eff, resolved)) = parse_effects_override(body) {
        return (eff, resolved);
    }

    let mut e = ToolEffects::default();

    if rxi(r"subprocess\s*\.|os\.system|shell\s*=\s*true|\bpopen\b|child_process|exec_command")
        .is_match(body)
    {
        e.shell_exec = true;
    }
    // file writes (mode-specific open(...,'w'|'a'|'x') or explicit write APIs)
    if rxi(r#"open\s*\([^)]*['"][wax]\+?b?['"]|\.write_text\b|fs\.writefile|writefile\b|\.writefilesync"#)
        .is_match(body)
        || rxi(r#"open\s*\([^)]*,\s*['"][wax]"#).is_match(body)
    {
        e.writes_fs = true;
    }
    // file reads
    if rxi(r#"open\s*\([^)]*['"]r['"]|\.read_text\b|\.readfile\b|readfilesync|fs\.readfile"#)
        .is_match(body)
        || rxi(r#"open\s*\([^)]*,\s*['"]r"#).is_match(body)
    {
        e.reads_fs = true;
    }
    // network egress
    if rxi(r"requests\s*\.|httpx\s*\.|urllib|aiohttp|\bfetch\s*\(|axios\s*\.|http\.get|http\.request|urlopen")
        .is_match(body)
    {
        e.net_egress = true;
    }
    // db writes
    if rxi(r"sqlalchemy|psycopg|pymongo|sqlite3|\bcursor\.execute\b").is_match(body)
        || rx(r"\b(INSERT|UPDATE|DELETE)\b").is_match(body)
    {
        e.db_write = true;
    }
    // code eval
    if rxi(r"\beval\s*\(|\bexec\s*\(|new\s+function\s*\(|compile\s*\(").is_match(body) {
        e.code_eval = true;
    }
    // email
    if rxi(r"smtplib|sendmail|send_email|send_mail|\bsmtp\b|mailgun|sendgrid").is_match(body) {
        e.email = true;
    }
    // payment
    if rxi(r"stripe|paypal|\bcharge\b|payment|braintree|\bcheckout\b").is_match(body) {
        e.payment = true;
    }

    let resolved = e.is_known();
    (e, resolved)
}

/// Parse an explicit `effects=[...]` / `@tool(effects=[...])` override.
/// Returns `Some((effects, true))` when an `effects=` list is present (even if
/// empty — an empty list is a deliberate "no effects" assertion and counts as
/// resolved). Returns `None` when there is no such annotation.
fn parse_effects_override(body: &str) -> Option<(ToolEffects, bool)> {
    let re = rxi(r"(?:^|[^_\w])effects\s*=\s*\[([^\]]*)\]");
    let caps = re.captures(body)?;
    let list = caps.get(1).map(|m| m.as_str()).unwrap_or("");
    let mut e = ToolEffects::default();
    for tok_raw in list.split(',') {
        let tok = unquote(tok_raw).to_ascii_lowercase();
        let tok = tok.trim();
        match tok {
            "shell" | "shell_exec" | "subprocess" | "exec" => e.shell_exec = true,
            "fs_write" | "write_fs" | "writes_fs" | "fs-w" | "write" => e.writes_fs = true,
            "fs_read" | "read_fs" | "reads_fs" | "fs-r" | "read" => e.reads_fs = true,
            "net" | "network" | "net_egress" | "http" => e.net_egress = true,
            "db" | "db_write" | "database" | "sql" => e.db_write = true,
            "code_eval" | "eval" | "code" => e.code_eval = true,
            "email" | "mail" | "smtp" => e.email = true,
            "payment" | "pay" | "money" => e.payment = true,
            "" => {}
            _ => {}
        }
    }
    // An explicit annotation is always "resolved" (the author told us).
    Some((e, true))
}

// ---------------------------------------------------------------------------
// system-prompt extraction
// ---------------------------------------------------------------------------

/// Best-effort extraction of a system prompt from a chunk of source. Looks for
/// the common keyword-argument / role patterns and returns the first string
/// literal found for any of them:
/// `system_prompt=`, `system_message=`, `instructions=`, `backstory=`,
/// `goal=`, and a `role="system"` object's adjacent `content=`/`"content":`.
///
/// Returns the concatenated literal text (prefixes/quotes stripped) or `None`.
pub fn extract_system_prompt(content: &str) -> Option<String> {
    // Direct keyword-argument assignments.
    for kw in [
        "system_prompt",
        "system_message",
        "instructions",
        "backstory",
    ] {
        let re = rxi(&format!(r#"{kw}\s*=\s*"#));
        if let Some(m) = re.find(content) {
            if let Some(s) = first_string_literal(content, m.end()) {
                let s = decode_escapes(&s);
                if !s.trim().is_empty() {
                    return Some(s);
                }
            }
        }
        // JSON / dict style: "system_prompt": "..."
        let re2 = rxi(&format!(r#""{kw}"\s*:\s*"#));
        if let Some(m) = re2.find(content) {
            if let Some(s) = first_string_literal(content, m.end()) {
                let s = decode_escapes(&s);
                if !s.trim().is_empty() {
                    return Some(s);
                }
            }
        }
    }

    // role="system" → grab the nearest following content literal.
    let role_re = rxi(r#"(?:role\s*[=:]\s*["']system["'])"#);
    if let Some(m) = role_re.find(content) {
        let tail = &content[m.end()..];
        let content_re = rxi(r#"content\s*[=:]\s*"#);
        if let Some(cm) = content_re.find(tail) {
            if let Some(s) = first_string_literal(tail, cm.end()) {
                let s = decode_escapes(&s);
                if !s.trim().is_empty() {
                    return Some(s);
                }
            }
        }
    }

    None
}

/// Decode the most common backslash escapes so the stored prompt is readable
/// (and its SHA-256 stays stable across quote styles).
pub fn decode_escapes(s: &str) -> String {
    s.replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\\"", "\"")
        .replace("\\'", "'")
        .replace("\\\\", "\\")
}

// ---------------------------------------------------------------------------
// model-id extraction
// ---------------------------------------------------------------------------

/// Best-effort model-id extraction (`model=`, `model_name=`, `"model":`).
pub fn extract_model(content: &str) -> Option<String> {
    for kw in ["model_name", "model", "deployment_name", "modelId"] {
        let re = rxi(&format!(r#"{kw}\s*[=:]\s*"#));
        if let Some(m) = re.find(content) {
            if let Some(s) = first_string_literal(content, m.end()) {
                let s = s.trim().to_string();
                if !s.is_empty() && s.len() < 80 {
                    return Some(s);
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// RAG trust classification
// ---------------------------------------------------------------------------

/// Classify a document-source string into a trust label using the parse
/// options' [`ar_core::TrustConfig`].
pub fn classify_rag_trust(opts: &ParseOptions, source: &str) -> TrustLabel {
    opts.trust.classify(source)
}

/// Build a [`RAGSource`] node with trust classified from any document-source
/// string discovered near `anchor`, and a source location anchored to it.
pub fn make_rag(
    opts: &ParseOptions,
    path: &Path,
    content: &str,
    name: &str,
    kind: &str,
    anchor: &str,
) -> RAGSource {
    let id = mint_id("rag", path, name);
    let mut r = RAGSource::new(id, name, kind);
    r.location = locate(path, content, anchor);
    if let Some(src) = nearby_document_source(content, anchor) {
        r.trust = classify_rag_trust(opts, &src);
        r.document_source = Some(src);
    }
    r
}

/// Heuristically pull a document-source URI/path string appearing shortly after
/// the anchor (within a small window), e.g. `persist_directory="./docs"`,
/// `path="https://..."`, `index_name="user-uploads"`.
pub fn nearby_document_source(content: &str, anchor: &str) -> Option<String> {
    let start = offset_of(content, anchor)?;
    let window_end = char_boundary_floor(content, (start + 400).min(content.len()));
    let window = &content[start..window_end];
    let re = rxi(r#"(?:persist_directory|path|directory|source|url|uri|index_name|namespace|collection_name|file_path)\s*[=:]\s*"#);
    if let Some(m) = re.find(window) {
        if let Some(s) = first_string_literal(window, m.end()) {
            return Some(s);
        }
    }
    // Otherwise any URL-ish literal in the window.
    let url = rxi(r#"["'](https?://[^"'\s]+|s3://[^"'\s]+|\.{0,2}/[^"'\s]+)["']"#);
    url.captures(window)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

// ---------------------------------------------------------------------------
// misc parsing helpers shared across modules
// ---------------------------------------------------------------------------

/// Extract the bracketed argument list literal that follows the first call of
/// `func_name(` in `content` (a shallow, balanced-paren scan). Returns the text
/// between the outermost parentheses, if found.
pub fn call_args(content: &str, func_name: &str) -> Option<String> {
    let re = rxi(&format!(r"\b{}\s*\(", regex::escape(func_name)));
    let m = re.find(content)?;
    balanced(content, m.end() - 1, '(', ')')
}

/// Given the byte offset of an opening delimiter, return the inner text up to
/// its matching close (handles nesting; ignores delimiters inside strings only
/// crudely). Returns `None` if unbalanced.
pub fn balanced(content: &str, open_at: usize, open: char, close: char) -> Option<String> {
    let bytes = content.as_bytes();
    if open_at >= bytes.len() || bytes[open_at] as char != open {
        return None;
    }
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    let start = open_at + 1;
    let mut i = open_at;
    while i < bytes.len() {
        let c = bytes[i];
        match in_str {
            Some(q) => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    in_str = None;
                }
            }
            None => {
                if c == b'"' || c == b'\'' || c == b'`' {
                    in_str = Some(c);
                } else if c as char == open {
                    depth += 1;
                } else if c as char == close {
                    depth -= 1;
                    if depth == 0 {
                        return Some(content[start..i].to_string());
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Pull a list of identifier-ish tokens from a comma-separated argument string,
/// dropping keyword-argument names and string-literal noise. Used to resolve
/// `tools=[search, calculator]` style lists into tool names.
pub fn ident_list(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tok_raw in args.split(',') {
        let tok = tok_raw.trim();
        if tok.is_empty() {
            continue;
        }
        // strip trailing call parens: `Tool()` -> `Tool`
        let tok = tok.split('(').next().unwrap_or(tok).trim();
        // skip kwargs (key=value) — keep the value if it's an ident
        let candidate = if let Some((_k, v)) = tok.split_once('=') {
            v.trim()
        } else {
            tok
        };
        // a bare identifier or dotted path
        if rx(r"^[A-Za-z_][A-Za-z0-9_\.]*$").is_match(candidate) {
            out.push(candidate.to_string());
        } else {
            // string-literal tool name
            let unq = unquote(candidate);
            if !unq.is_empty() && unq != candidate && rx(r"^[A-Za-z0-9_\-\. ]+$").is_match(&unq) {
                out.push(unq);
            }
        }
    }
    out
}

/// Find the value of a kwarg/string literal: `key=...` or `"key": ...`.
pub fn kwarg_string(content: &str, key: &str) -> Option<String> {
    let re = rxi(&format!(r#"(?:\b{0}\s*=|["']{0}["']\s*:)\s*"#, regex::escape(key)));
    let m = re.find(content)?;
    first_string_literal(content, m.end())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn infer_shell_and_net() {
        let body = "def t(x):\n  import subprocess\n  subprocess.run(['ls'])\n  requests.get(x)\n";
        let (e, resolved) = infer_effects(body);
        assert!(resolved);
        assert!(e.shell_exec);
        assert!(e.net_egress);
    }

    #[test]
    fn infer_effects_override() {
        let (e, resolved) = infer_effects(r#"@tool(effects=["net", "db"])"#);
        assert!(resolved);
        assert!(e.net_egress);
        assert!(e.db_write);
        assert!(!e.shell_exec);
    }

    #[test]
    fn extract_prompt_kwarg() {
        let src = r#"agent = Agent(system_prompt="You are helpful.", model="gpt-4o")"#;
        assert_eq!(
            extract_system_prompt(src).as_deref(),
            Some("You are helpful.")
        );
        assert_eq!(extract_model(src).as_deref(), Some("gpt-4o"));
    }

    #[test]
    fn balanced_paren_scan() {
        let s = "foo(a, bar(1,2), 'x,y')";
        assert_eq!(call_args(s, "foo").as_deref(), Some("a, bar(1,2), 'x,y'"));
    }

    #[test]
    fn locate_anchors_line() {
        let s = "line1\nline2 anchor\nline3";
        let loc = locate(Path::new("f.py"), s, "anchor");
        assert_eq!(loc.line, Some(2));
    }
}
