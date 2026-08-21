//! Lint-Owl: a taint static analyzer whose result is the data-flow PATH from an
//! untrusted source to a dangerous sink, not a flat list of warnings.
//!
//! v0.1 proves one property deeply: does taint reach a command-execution sink,
//! over a Python subset. It is intentionally small and honest about its limits
//! (see DESIGN.md): line-based, flow-forward, intra-scope, no control flow yet.

use serde::Serialize;
use std::collections::HashMap;

// ---- What counts as a source and a sink (command injection, v0.1) ----

/// Calls that return attacker-controlled data, e.g. `input()`.
const SOURCE_CALLS: &[&str] = &[
    "input",
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "os.getenv",
];
/// Bare names that are attacker-controlled, e.g. `sys.argv`.
const SOURCE_NAMES: &[&str] = &[
    "sys.argv",
    "request.args",
    "request.form",
    "request.data",
    "request.values",
];
/// Command-execution sinks. Tainted data reaching one is command injection.
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

// ---- AST ----

#[derive(Debug, Clone)]
enum Expr {
    Name(String),
    Lit,
    Call { name: String, args: Vec<Expr> },
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
}

/// Analyze a Python-subset source string and return command-injection paths.
pub fn analyze(src: &str) -> Vec<Finding> {
    let stmts = parse(src);
    run_taint(&stmts)
}

/// Render a finding as its source-to-sink chain against the original source.
pub fn render(src: &str, f: &Finding) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = format!("{}: tainted data reaches a {} sink\n", f.vuln, f.vuln);
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

// ---- Lexer (per line) ----

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Name(String),
    Lit,
    LParen,
    RParen,
    Comma,
    Plus,
    Eq,
}

fn lex_line(line: &str) -> Vec<Tok> {
    let is_name = |c: char| c.is_alphanumeric() || matches!(c, '_' | '.');
    let mut toks = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            '#' => break, // comment to end of line
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                toks.push(Tok::LParen);
            }
            ')' => {
                chars.next();
                toks.push(Tok::RParen);
            }
            ',' => {
                chars.next();
                toks.push(Tok::Comma);
            }
            '+' => {
                chars.next();
                toks.push(Tok::Plus);
            }
            '=' => {
                chars.next();
                // treat == as not-an-assignment; collapse to a literal-ish no-op
                if chars.peek() == Some(&'=') {
                    chars.next();
                    toks.push(Tok::Lit);
                } else {
                    toks.push(Tok::Eq);
                }
            }
            '"' | '\'' => {
                let q = c;
                chars.next();
                while let Some(ch) = chars.next() {
                    if ch == '\\' {
                        chars.next();
                        continue;
                    }
                    if ch == q {
                        break;
                    }
                }
                toks.push(Tok::Lit);
            }
            c if c.is_ascii_digit() => {
                while let Some(&ch) = chars.peek() {
                    if ch.is_ascii_digit() || ch == '.' {
                        chars.next();
                    } else {
                        break;
                    }
                }
                toks.push(Tok::Lit);
            }
            c if is_name(c) => {
                let mut s = String::new();
                while let Some(&ch) = chars.peek() {
                    if is_name(ch) {
                        s.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                toks.push(Tok::Name(s));
            }
            // Anything else (brackets, colons, operators we do not model) is
            // skipped so the subset parser stays lenient on real-ish code.
            _ => {
                chars.next();
            }
        }
    }
    toks
}

// ---- Parser (per line) ----

struct P {
    toks: Vec<Tok>,
    pos: usize,
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
        // concat: primary ('+' primary)*
        let mut parts = vec![self.primary()];
        while matches!(self.peek(), Some(Tok::Plus)) {
            self.next();
            parts.push(self.primary());
        }
        if parts.len() == 1 {
            parts.pop().unwrap()
        } else {
            Expr::Concat(parts)
        }
    }

    fn primary(&mut self) -> Expr {
        match self.next() {
            Some(Tok::Name(n)) => {
                if matches!(self.peek(), Some(Tok::LParen)) {
                    self.next(); // (
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
                    Expr::Call { name: n, args }
                } else {
                    Expr::Name(n)
                }
            }
            Some(Tok::LParen) => {
                let e = self.expr();
                if matches!(self.peek(), Some(Tok::RParen)) {
                    self.next();
                }
                e
            }
            _ => Expr::Lit,
        }
    }
}

fn parse(src: &str) -> Vec<Stmt> {
    let mut out = Vec::new();
    for (idx, raw) in src.lines().enumerate() {
        let line = idx + 1;
        let toks = lex_line(raw);
        if toks.is_empty() {
            continue;
        }
        // Assignment: NAME '=' expr
        if let (Some(Tok::Name(n)), Some(Tok::Eq)) = (toks.first(), toks.get(1)) {
            let name = n.clone();
            let mut p = P {
                toks: toks[2..].to_vec(),
                pos: 0,
            };
            out.push(Stmt::Assign {
                name,
                value: p.expr(),
                line,
            });
        } else {
            let mut p = P { toks, pos: 0 };
            out.push(Stmt::Eval {
                value: p.expr(),
                line,
            });
        }
    }
    out
}

// ---- Taint engine ----

fn run_taint(stmts: &[Stmt]) -> Vec<Finding> {
    // var -> provenance chain (line numbers from source to where it was set).
    let mut tainted: HashMap<String, Vec<usize>> = HashMap::new();
    let mut findings = Vec::new();

    for stmt in stmts {
        let (value, line) = match stmt {
            Stmt::Assign { value, line, .. } => (value, *line),
            Stmt::Eval { value, line } => (value, *line),
        };
        // 1. Any tainted data reaching a sink call in this statement is a finding.
        find_sinks(value, line, &tainted, &mut findings);

        // 2. Update taint of the assigned variable.
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

/// If this expression is tainted, return the provenance chain (source ... here).
fn expr_taint(e: &Expr, tainted: &HashMap<String, Vec<usize>>, line: usize) -> Option<Vec<usize>> {
    match e {
        Expr::Name(n) => {
            if SOURCE_NAMES.contains(&n.as_str()) {
                Some(vec![line])
            } else {
                tainted.get(n).cloned()
            }
        }
        Expr::Lit => None,
        Expr::Concat(parts) => parts.iter().find_map(|p| expr_taint(p, tainted, line)),
        Expr::Call { name, args } => {
            if SOURCE_CALLS.contains(&name.as_str()) {
                Some(vec![line])
            } else {
                // A non-source call passes taint through from a tainted argument.
                args.iter().find_map(|a| expr_taint(a, tainted, line))
            }
        }
    }
}

/// Record a finding for every sink call in this expression that has a tainted arg.
fn find_sinks(
    e: &Expr,
    line: usize,
    tainted: &HashMap<String, Vec<usize>>,
    findings: &mut Vec<Finding>,
) {
    if let Expr::Call { name, args } = e {
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
    } else if let Expr::Concat(parts) = e {
        for p in parts {
            find_sinks(p, line, tainted, findings);
        }
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
        assert_eq!(f[0].source_line(), 1);
        assert_eq!(f[0].sink_line(), 3);
        assert_eq!(f[0].path, vec![1, 2, 3]);
    }

    #[test]
    fn no_finding_when_sink_arg_is_a_literal() {
        let src = "os.system(\"ls -la\")\n";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn no_finding_when_source_never_reaches_sink() {
        let src = "cmd = input()\nsafe = \"ls\"\nos.system(safe)\n";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn reassigning_clean_clears_taint() {
        let src = "x = input()\nx = \"ls\"\nos.system(x)\n";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn direct_source_into_sink() {
        let src = "os.system(input())\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].path, vec![1, 1]);
    }

    #[test]
    fn bare_name_source_sys_argv() {
        let src = "arg = sys.argv\nos.system(arg)\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].source_line(), 1);
    }

    #[test]
    fn detects_sql_injection() {
        let src = "name = request.args.get(\"name\")\nq = \"SELECT * FROM u WHERE n = \" + name\ncur.execute(q)\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "sql-injection");
    }

    #[test]
    fn detects_ssrf() {
        let src = "url = request.args.get(\"url\")\nrequests.get(url)\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "ssrf");
    }

    #[test]
    fn detects_path_traversal() {
        let src = "p = request.args.get(\"file\")\nopen(p)\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "path-traversal");
    }

    #[test]
    fn detects_insecure_deserialization() {
        let src = "blob = request.data\npickle.loads(blob)\n";
        let f = analyze(src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].vuln, "insecure-deserialization");
    }
}
