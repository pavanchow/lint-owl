<img src="docs/logo.svg" alt="Lint-Owl logo" width="96">

# Lint-Owl: a taint-tracking static analyzer in Rust

Lint-Owl is a taint-tracking static analyzer written in Rust whose result is the
data-flow path from an untrusted source to a dangerous sink, not a flat list of warnings.
It proves whether tainted input actually reaches a command, SQL, SSRF, path traversal, or
deserialization sink in Python, JavaScript, TypeScript, and PHP, and prints the exact
source-to-sink chain. Built for real bug-bounty and code-review work.

**[Live demo](https://pavanchow.github.io/lint-owl/)** · MIT licensed · written in Rust

Built from scratch by [Pavan Nallamothu](https://pavanchow.github.io/) ([LinkedIn](https://www.linkedin.com/in/pavanchow/), [GitHub](https://github.com/pavanchow)).

## Try it

```
cargo run -- scan examples/vuln.py        # one file
cargo run -- scan path/to/your/repo       # a whole tree of .py files
```

Exits non-zero when it finds anything, so it drops into CI or a pre-commit hook
(`--exit-zero` to override). Known sanitizers (`int`, `shlex.quote`, ...) clear taint,
so quoted or cast input is not flagged.

```
== examples/vuln.py ==
command-injection [critical]: tainted data reaches a command-injection sink
  [source] line 4: host = request.args.get("host")
  [flows] line 5: cmd = "ping -c 1 " + host
  [sink] line 6: os.system(cmd)


1 tainted path(s) across 1 file(s)
```

The source starts inside `handle`, a function the file never calls, so this also
shows the analyzer walking each function body as its own scope, not just top-level
code.

JSON output for tooling: `cargo run -- scan examples/vuln.py --json`.

## How it differs

Linters flag local smells. Semgrep matches patterns but does not prove the input
reaches the sink. CodeQL proves it but is heavy and needs a database and a query
language. Lint-Owl is one small binary whose output is the tainted path itself, and it
is built to be agent-native (an MCP tool an AI asks "does user input reach this exec").

## HTTP API and console

```
cargo run -- serve --port 8080
```

Open the URL, paste code, and see each finding as a source-to-sink chain with severity
badges. Or POST directly: `curl -s localhost:8080/scan -H 'content-type: application/json' -d '{"code":"..."}'`.

## MCP server (agent-native)

```
cargo run -- mcp
claude mcp add lint-owl -- /path/to/lint-owl mcp
```

Tool `lint_owl_scan` takes `{code}` and returns the tainted paths, so an AI reviewing a
diff can ask "does user input reach a sink here" and get the chain back.

## Languages and output

Scans `.py`, `.js`/`.ts`, and `.php`. Emits readable paths, JSON (`--json`), or SARIF
(`--sarif`) for GitHub code scanning. Add your framework's sources/sinks with `--config`.

## Stack

Rust. Hand-written lexers and a shared recursive-descent parser per language, and a
forward taint engine that tracks provenance so every finding carries its source-to-sink
line chain. See [DESIGN.md](DESIGN.md).

## Status

v0.3: Python, JavaScript, and PHP. Source-to-sink paths for command injection, SQL
injection, SSRF, path traversal, insecure deserialization, and more. Control-flow (loop)
and inter-procedural (cross-function) taint, sanitizer awareness, configurable
sources/sinks (`--config`), SARIF output (`--sarif`), directory/repo scanning, CI exit
codes, severity, CLI + HTTP API + console + MCP. Two independent audits fixed. Results are
candidate paths a human confirms.
