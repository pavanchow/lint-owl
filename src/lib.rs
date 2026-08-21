//! Lint-Owl: a taint static analyzer whose result is the data-flow PATH from an
//! untrusted source to a dangerous sink, not a flat list of warnings.
//!
//! v0.1 proves one property deeply: does taint reach a dangerous sink, over a
//! Python subset. It handles assignment, string concat, f-string interpolation,
//! method chaining, `with`/keyword-led statements, semicolons, and multi-line
//! calls. Honest limits (see DESIGN.md): no control flow, no sanitizers, single
//! scope, so results are candidate paths a human confirms.

use serde::Serialize;
use std::collections::HashMap;

pub mod mcp;
pub mod server;

/// Parser recursion bound. Past this, deeply nested input is truncated instead of
/// overflowing the native stack (an unauthenticated crash otherwise).
const MAX_DEPTH: usize = 200;

/// Leading keywords we skip so the expression after them is still analyzed
/// (e.g. `with open(p) as f:`, `return run(x)`).
const LEAD_KEYWORDS: &[&str] = &[
    "with", "if", "elif", "while", "for", "return", "assert", "await", "del", "yield",
    "raise", "else", "try", "except", "finally", "async",
];

// ---- Sources and sinks ----

const SOURCE_CALLS: &[&str] = &[
    "input",
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "os.getenv",
];
const SOURCE_NAMES: &[&str] = &[
    "sys.argv",
    "request.args",
    "request.form",
    "request.data",
    "request.values",
];
const COMMAND_SINKS: &[&str] = &[
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
    "eval",
    "exec",
];
const SSRF_SINKS: &[&str] = &[
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.head",
    "requests.request",
    "urllib.request.urlopen",
    "urlopen",
    "httpx.get",
    "httpx.post",
];
const DESERIALIZE_SINKS: &[&str] = &[
    "pickle.loads",
    "pickle.load",
    "yaml.load",
    "marshal.loads",
    "dill.loads",
];

/// Which vulnerability class, if any, a called function is a sink for.
fn sink_class(name: &str) -> Option<&'static str> {
    if COMMAND_SINKS.contains(&name) {
        return Some("command-injection");
    }
    if name == "execute" || name.ends_with(".execute") || name.ends_with(".executemany") {
        return Some("sql-injection");
    }
    if SSRF_SINKS.contains(&name) || name.ends_with(".urlopen") {
        return Some("ssrf");
    }
    if name == "open" {
        return Some("path-traversal");
    }
    if DESERIALIZE_SINKS.contains(&name) {
        return Some("insecure-deserialization");
    }
    None
}

fn is_source_call(name: &str) -> bool {
    SOURCE_CALLS.contains(&name)
}

/// Calls that neutralize taint for our string sinks. Conservative on purpose:
/// numeric casts cannot inject, and shell-quoting escapes command metacharacters.
const SANITIZERS: &[&str] = &["int", "float", "bool", "shlex.quote", "pipes.quote"];

fn is_sanitizer(name: &str) -> bool {
    SANITIZERS.contains(&name)
}

/// Severity of a vulnerability class.
pub fn severity(vuln: &str) -> &'static str {
    match vuln {
        "command-injection" | "sql-injection" | "insecure-deserialization" => "critical",
        _ => "high",
    }
}

// ---- AST ----

#[derive(Debug, Clone)]
enum Expr {
    Name(String),
    Lit,
    Call { name: String, args: Vec<Expr> },
    /// A method call on a receiver: `recv.name(args)`.
    Method { recv: Box<Expr>, name: String, args: Vec<Expr> },
    Concat(Vec<Expr>),
}

#[derive(Debug, Clone)]
enum Stmt {
    Assign { name: String, value: Expr, line: usize },
    Eval { value: Expr, line: usize },
}

// ---- Findings ----

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub vuln: String,
    /// Line numbers from the source, through each propagation, to the sink.
    pub path: Vec<usize>,
}

impl Finding {
    pub fn source_line(&self) -> usize {
        *self.path.first().unwrap_or(&0)
    }
    pub fn sink_line(&self) -> usize {
        *self.path.last().unwrap_or(&0)
    }
    pub fn severity(&self) -> &'static str {
        severity(&self.vuln)
    }
}

/// Analyze a Python-subset source string and return tainted source-to-sink paths.
pub fn analyze(src: &str) -> Vec<Finding> {
    run_taint(&parse(src))
}

/// Scan source and return findings as JSON, each with its source-to-sink hops.
pub fn scan_json(src: &str) -> serde_json::Value {
    let findings = analyze(src);
    let lines: Vec<&str> = src.lines().collect();
    let out: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let hops: Vec<serde_json::Value> = f
                .path
                .iter()
                .enumerate()
                .map(|(i, &ln)| {
                    let tag = if i == 0 {
                        "source"
                    } else if i == f.path.len() - 1 {
                        "sink"
                    } else {
                        "flows"
                    };
                    serde_json::json!({
                        "line": ln,
                        "tag": tag,
                        "code": lines.get(ln - 1).map(|s| s.trim()).unwrap_or(""),
                    })
                })
                .collect();
            serde_json::json!({ "vuln": f.vuln, "severity": f.severity(), "path": hops })
        })
        .collect();
    serde_json::json!({ "count": findings.len(), "findings": out })
}

/// Render a finding as its source-to-sink chain against the original source.
pub fn render(src: &str, f: &Finding) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = format!("{} [{}]: tainted data reaches a {} sink\n", f.vuln, f.severity(), f.vuln);
    for (i, &ln) in f.path.iter().enumerate() {
        let code = lines.get(ln - 1).map(|s| s.trim()).unwrap_or("");
        let tag = if i == 0 {
            "source"
        } else if i == f.path.len() - 1 {
            "sink"
        } else {
            "flows"
        };
        out.push_str(&format!("  [{tag}] line {ln}: {code}\n"));
    }
    out
}

// ---- Lexer ----

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Name(String),
    Lit,
    LParen,
    RParen,
    Comma,
    Plus,
    Eq,
    Semi,
}

fn is_name_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '.')
}

fn lex_line(line: &str) -> Vec<Tok> {
    let mut toks = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '#' => break,
            c if c.is_whitespace() => i += 1,
            '(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            ',' => {
                toks.push(Tok::Comma);
                i += 1;
            }
            '+' => {
                toks.push(Tok::Plus);
                i += 1;
            }
            ';' => {
                toks.push(Tok::Semi);
                i += 1;
            }
            '=' => {
                if chars.get(i + 1) == Some(&'=') {
                    toks.push(Tok::Lit);
                    i += 2;
                } else {
                    toks.push(Tok::Eq);
                    i += 1;
                }
            }
            '"' | '\'' => {
                i = lex_string(&chars, i, &mut toks, false);
            }
            c if c.is_ascii_digit() => {
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    i += 1;
                }
                toks.push(Tok::Lit);
            }
            c if is_name_char(c) => {
                let start = i;
                while i < chars.len() && is_name_char(chars[i]) {
                    i += 1;
                }
                let name: String = chars[start..i].iter().collect();
                // String prefix (f/r/b and combinations) directly followed by a quote.
                let is_str_prefix = name.len() <= 2
                    && name.chars().all(|c| matches!(c, 'f' | 'F' | 'r' | 'R' | 'b' | 'B'));
                if is_str_prefix && matches!(chars.get(i), Some('"') | Some('\'')) {
                    let fstring = name.to_ascii_lowercase().contains('f');
                    i = lex_string(&chars, i, &mut toks, fstring);
                } else {
                    toks.push(Tok::Name(name));
                }
            }
            // Anything else (brackets, colons, operators we do not model) is skipped
            // so the subset parser stays lenient on real code.
            _ => i += 1,
        }
    }
    toks
}

/// Lex a quoted string starting at `chars[i]` (the opening quote). If `fstring`,
/// emit interpolations `{expr}` as nested tokens joined by `+` so taint flows.
/// Returns the index just past the closing quote.
fn lex_string(chars: &[char], mut i: usize, toks: &mut Vec<Tok>, fstring: bool) -> usize {
    let quote = chars[i];
    i += 1;
    if !fstring {
        while i < chars.len() {
            if chars[i] == '\\' {
                i += 2;
                continue;
            }
            if chars[i] == quote {
                i += 1;
                break;
            }
            i += 1;
        }
        toks.push(Tok::Lit);
        return i;
    }
    // f-string: literal segments are Lit, {..} interiors are lexed and grouped.
    toks.push(Tok::Lit);
    while i < chars.len() {
        if chars[i] == '\\' {
            i += 2;
            continue;
        }
        if chars[i] == quote {
            i += 1;
            break;
        }
        if chars[i] == '{' {
            // `{{` is a literal brace.
            if chars.get(i + 1) == Some(&'{') {
                i += 2;
                continue;
            }
            let start = i + 1;
            let mut j = start;
            let mut depth = 1;
            while j < chars.len() && depth > 0 {
                match chars[j] {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    break;
                }
                j += 1;
            }
            let inner: String = chars[start..j].iter().collect();
            // Keep only the expression: drop the format spec (`:...`), the
            // conversion (`!r`/`!s`), and a trailing debug `=` (`{x=}`).
            let inner = inner
                .split(|c| c == ':' || c == '!')
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches('=')
                .to_string();
            let inner_toks = lex_line(&inner);
            toks.push(Tok::Plus);
            toks.push(Tok::LParen);
            toks.extend(inner_toks);
            toks.push(Tok::RParen);
            toks.push(Tok::Plus);
            toks.push(Tok::Lit);
            i = j + 1;
            continue;
        }
        i += 1;
    }
    i
}

// ---- Parser ----

struct P {
    toks: Vec<Tok>,
    pos: usize,
    depth: usize,
}

impl P {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expr(&mut self) -> Expr {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.depth -= 1;
            return Expr::Lit;
        }
        let mut parts = vec![self.postfix()];
        while matches!(self.peek(), Some(Tok::Plus)) {
            self.next();
            parts.push(self.postfix());
        }
        self.depth -= 1;
        if parts.len() == 1 {
            parts.pop().unwrap()
        } else {
            Expr::Concat(parts)
        }
    }

    /// A primary followed by any number of `.method(args)` chains.
    fn postfix(&mut self) -> Expr {
        let mut e = self.primary();
        loop {
            match self.peek() {
                Some(Tok::Name(n)) if n.starts_with('.') => {
                    let name = n.trim_start_matches('.').to_string();
                    self.next();
                    let args = if matches!(self.peek(), Some(Tok::LParen)) {
                        self.next();
                        self.args()
                    } else {
                        Vec::new()
                    };
                    e = Expr::Method {
                        recv: Box::new(e),
                        name,
                        args,
                    };
                }
                _ => break,
            }
        }
        e
    }

    fn args(&mut self) -> Vec<Expr> {
        let mut args = Vec::new();
        if !matches!(self.peek(), Some(Tok::RParen) | None) {
            args.push(self.expr());
            while matches!(self.peek(), Some(Tok::Comma)) {
                self.next();
                args.push(self.expr());
            }
        }
        if matches!(self.peek(), Some(Tok::RParen)) {
            self.next();
        }
        args
    }

    fn primary(&mut self) -> Expr {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.depth -= 1;
            // Consume one token so we always make progress.
            self.next();
            return Expr::Lit;
        }
        let e = match self.next() {
            Some(Tok::Name(n)) => {
                if matches!(self.peek(), Some(Tok::LParen)) {
                    self.next();
                    let args = self.args();
                    Expr::Call { name: n, args }
                } else {
                    Expr::Name(n)
                }
            }
            Some(Tok::LParen) => {
                let inner = self.expr();
                if matches!(self.peek(), Some(Tok::RParen)) {
                    self.next();
                }
                inner
            }
            _ => Expr::Lit,
        };
        self.depth -= 1;
        e
    }
}

/// Merge physical lines into logical lines. A logical line continues while parens
/// are open, a triple-quoted string is open, or the line ends in a backslash, so
/// multi-line calls and docstrings parse as one statement (and a stray `(` inside a
/// docstring can never swallow the rest of the file).
fn logical_lines(src: &str) -> Vec<(usize, String)> {
    let phys: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < phys.len() {
        let start = i + 1;
        let mut buf = phys[i].to_string();
        loop {
            let (paren, triple_open) = scan(&buf);
            let cont = paren > 0 || triple_open || buf.trim_end().ends_with('\\');
            if !cont || i + 1 >= phys.len() {
                break;
            }
            if buf.trim_end().ends_with('\\') {
                let t = buf.trim_end();
                buf.truncate(t.len() - 1);
            }
            i += 1;
            buf.push('\n');
            buf.push_str(phys[i]);
        }
        out.push((start, buf));
        i += 1;
    }
    out
}

/// Net open parens outside strings, and whether a triple-quoted string is still
/// open at the end. Handles `'`/`"`, `'''`/`"""`, escapes, and `#` comments.
fn scan(s: &str) -> (i32, bool) {
    let ch: Vec<char> = s.chars().collect();
    let n = ch.len();
    let triple_at = |i: usize, q: char| ch.get(i) == Some(&q) && ch.get(i + 1) == Some(&q) && ch.get(i + 2) == Some(&q);
    let mut i = 0;
    let mut paren = 0i32;
    let mut triple: Option<char> = None;
    while i < n {
        if let Some(q) = triple {
            if triple_at(i, q) {
                triple = None;
                i += 3;
            } else {
                i += 1;
            }
            continue;
        }
        match ch[i] {
            '#' => {
                while i < n && ch[i] != '\n' {
                    i += 1;
                }
            }
            c @ ('"' | '\'') => {
                if triple_at(i, c) {
                    triple = Some(c);
                    i += 3;
                } else {
                    // single-line string: skip to its close on this line
                    i += 1;
                    while i < n {
                        if ch[i] == '\\' {
                            i += 2;
                            continue;
                        }
                        if ch[i] == c || ch[i] == '\n' {
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                }
            }
            '(' => {
                paren += 1;
                i += 1;
            }
            ')' => {
                paren -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    (paren, triple.is_some())
}

fn parse(src: &str) -> Vec<Stmt> {
    let mut out = Vec::new();
    for (line, buf) in logical_lines(src) {
        let toks = lex_line(&buf);
        // Split on ';' into separate statements.
        for stmt_toks in toks.split(|t| *t == Tok::Semi) {
            let mut toks = stmt_toks.to_vec();
            // Strip leading statement keywords so the real expression is analyzed.
            while matches!(toks.first(), Some(Tok::Name(n)) if LEAD_KEYWORDS.contains(&n.as_str())) {
                toks.remove(0);
            }
            if toks.is_empty() {
                continue;
            }
            if let (Some(Tok::Name(n)), Some(Tok::Eq)) = (toks.first(), toks.get(1)) {
                let name = n.clone();
                let mut p = P {
                    toks: toks[2..].to_vec(),
                    pos: 0,
                    depth: 0,
                };
                out.push(Stmt::Assign {
                    name,
                    value: p.expr(),
                    line,
                });
            } else {
                let mut p = P {
                    toks,
                    pos: 0,
                    depth: 0,
                };
                out.push(Stmt::Eval {
                    value: p.expr(),
                    line,
                });
            }
        }
    }
    out
}

// ---- Taint engine ----

fn run_taint(stmts: &[Stmt]) -> Vec<Finding> {
    let mut tainted: HashMap<String, Vec<usize>> = HashMap::new();
    let mut findings = Vec::new();

    for stmt in stmts {
        let (value, line) = match stmt {
            Stmt::Assign { value, line, .. } => (value, *line),
            Stmt::Eval { value, line } => (value, *line),
        };
        find_sinks(value, line, &tainted, &mut findings);

        if let Stmt::Assign { name, .. } = stmt {
            match expr_taint(value, &tainted, line) {
                Some(mut chain) => {
                    if chain.last() != Some(&line) {
                        chain.push(line);
                    }
                    tainted.insert(name.clone(), chain);
                }
                None => {
                    tainted.remove(name);
                }
            }
        }
    }
    findings
}

/// A tainted variable used as the receiver of a dotted name (e.g. `name.lower`
/// when `name` is tainted). `.` is a name char, so such calls lex as one Name;
/// this recovers the receiver taint. Checks every dotted prefix.
fn dotted_prefix(name: &str, tainted: &HashMap<String, Vec<usize>>) -> Option<Vec<usize>> {
    for (i, c) in name.char_indices() {
        if c == '.' {
            if let Some(chain) = tainted.get(&name[..i]) {
                return Some(chain.clone());
            }
        }
    }
    None
}

/// If this expression is tainted, return the provenance chain (source ... here).
fn expr_taint(e: &Expr, tainted: &HashMap<String, Vec<usize>>, line: usize) -> Option<Vec<usize>> {
    match e {
        Expr::Name(n) => {
            if SOURCE_NAMES.contains(&n.as_str()) {
                Some(vec![line])
            } else {
                tainted.get(n).cloned().or_else(|| dotted_prefix(n, tainted))
            }
        }
        Expr::Lit => None,
        Expr::Concat(parts) => parts.iter().find_map(|p| expr_taint(p, tainted, line)),
        Expr::Call { name, args } => {
            if is_sanitizer(name) {
                None // a sanitizer clears taint, even on a tainted argument
            } else if is_source_call(name) {
                Some(vec![line])
            } else {
                args.iter()
                    .find_map(|a| expr_taint(a, tainted, line))
                    .or_else(|| dotted_prefix(name, tainted))
            }
        }
        Expr::Method { recv, args, .. } => expr_taint(recv, tainted, line)
            .or_else(|| args.iter().find_map(|a| expr_taint(a, tainted, line))),
    }
}

/// Record a finding for every sink call in this expression with a tainted arg.
fn find_sinks(
    e: &Expr,
    line: usize,
    tainted: &HashMap<String, Vec<usize>>,
    findings: &mut Vec<Finding>,
) {
    match e {
        Expr::Call { name, args } => {
            if let Some(class) = sink_class(name) {
                if let Some(chain) = args.iter().find_map(|a| expr_taint(a, tainted, line)) {
                    let mut path = chain;
                    path.push(line);
                    findings.push(Finding {
                        vuln: class.into(),
                        path,
                    });
                }
            }
            for a in args {
                find_sinks(a, line, tainted, findings);
            }
        }
        Expr::Method { recv, name, args } => {
            if let Some(class) = sink_class(name) {
                if let Some(chain) = args.iter().find_map(|a| expr_taint(a, tainted, line)) {
                    let mut path = chain;
                    path.push(line);
                    findings.push(Finding {
                        vuln: class.into(),
                        path,
                    });
                }
            }
            find_sinks(recv, line, tainted, findings);
            for a in args {
                find_sinks(a, line, tainted, findings);
            }
        }
        Expr::Concat(parts) => {
            for p in parts {
                find_sinks(p, line, tainted, findings);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_source_to_sink_path() {
        let src = "cmd = input()\nfull = \"ping \" + cmd\nos.system(full)\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "command-injection");
        assert_eq!(f[0].path, vec![1, 2, 3]);
    }

    #[test]
    fn no_finding_when_sink_arg_is_a_literal() {
        assert!(analyze("os.system(\"ls -la\")\n").is_empty());
    }

    #[test]
    fn no_finding_when_source_never_reaches_sink() {
        assert!(analyze("cmd = input()\nsafe = \"ls\"\nos.system(safe)\n").is_empty());
    }

    #[test]
    fn reassigning_clean_clears_taint() {
        assert!(analyze("x = input()\nx = \"ls\"\nos.system(x)\n").is_empty());
    }

    #[test]
    fn direct_source_into_sink() {
        let f = analyze("os.system(input())\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].path, vec![1, 1]);
    }

    #[test]
    fn bare_name_source_sys_argv() {
        let f = analyze("arg = sys.argv\nos.system(arg)\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].source_line(), 1);
    }

    #[test]
    fn detects_sql_injection() {
        let src = "name = request.args.get(\"name\")\nq = \"SELECT \" + name\ncur.execute(q)\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "sql-injection");
    }

    #[test]
    fn detects_ssrf() {
        let f = analyze("url = request.args.get(\"url\")\nrequests.get(url)\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "ssrf");
    }

    #[test]
    fn detects_path_traversal() {
        let f = analyze("p = request.args.get(\"file\")\nopen(p)\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "path-traversal");
    }

    #[test]
    fn detects_insecure_deserialization() {
        let f = analyze("blob = request.data\npickle.loads(blob)\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "insecure-deserialization");
    }

    // ---- Audit regressions ----

    #[test]
    fn method_chaining_execute() {
        let src = "q = request.args.get(\"q\")\nconn.cursor().execute(q)\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "sql-injection");
    }

    #[test]
    fn with_open_statement() {
        let src = "p = request.args.get(\"file\")\nwith open(p) as fp:\n    data = fp.read()\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "path-traversal");
    }

    #[test]
    fn fstring_interpolation() {
        let src = "name = request.args.get(\"name\")\nq = f\"SELECT * FROM u WHERE n = {name}\"\ncur.execute(q)\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "sql-injection");
    }

    #[test]
    fn semicolon_second_statement() {
        let src = "cmd = input()\nx = 1; os.system(cmd)\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "command-injection");
    }

    #[test]
    fn multiline_call() {
        let src = "host = input()\nos.system(\n    host\n)\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "command-injection");
    }

    #[test]
    fn taint_through_method_on_a_bare_var() {
        // name.lower() lexes as one Call; the receiver taint must still flow.
        let src = "name = request.args.get(\"name\")\ncur.execute(name.lower())\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "sql-injection");
    }

    #[test]
    fn docstring_with_unbalanced_paren_does_not_swallow_file() {
        let src = "x = \"\"\"\n(\n\"\"\"\ny = input()\nos.system(y)\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "command-injection");
    }

    #[test]
    fn fstring_with_conversion_flag() {
        let src = "url = request.args.get(\"url\")\nrequests.get(f\"{url!r}\")\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "ssrf");
    }

    #[test]
    fn sanitizer_clears_taint() {
        // int() and shlex.quote() neutralize the taint before the sink.
        assert!(analyze("n = input()\nos.system(\"kill \" + int(n))\n").is_empty());
        assert!(analyze("h = input()\nos.system(shlex.quote(h))\n").is_empty());
    }

    #[test]
    fn severity_is_set() {
        let f = analyze("h = input()\nos.system(h)\n");
        assert_eq!(f[0].severity(), "critical");
        let f2 = analyze("u = request.args.get(\"u\")\nrequests.get(u)\n");
        assert_eq!(f2[0].severity(), "high");
    }

    #[test]
    fn deeply_nested_parens_does_not_overflow() {
        let mut s = String::from("os.system(");
        for _ in 0..100_000 {
            s.push('(');
        }
        s.push('x');
        for _ in 0..100_000 {
            s.push(')');
        }
        s.push(')');
        // Must return, not abort the process.
        let _ = analyze(&s);
    }
}
