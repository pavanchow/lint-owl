# Lint-Owl

**A static analyzer whose result is the data-flow path from an untrusted source to a
dangerous sink.** Not a flat list of warnings. It proves one property deeply, does
tainted input actually reach a command-execution sink, and shows the exact chain from
source to sink. Aimed at real bug-bounty and code-review work. By Pavan Nallamothu.

## Try it

```
cargo run -- scan examples/vuln.py        # one file
cargo run -- scan path/to/your/repo       # a whole tree of .py files
```

Exits non-zero when it finds anything, so it drops into CI or a pre-commit hook
(`--exit-zero` to override). Known sanitizers (`int`, `shlex.quote`, ...) clear taint,
so quoted or cast input is not flagged.

```
1 tainted path(s) to a command sink in examples/vuln.py:

command-injection: tainted data reaches a command sink
  [source] line 4: host = request.args.get("host")
  [flows]  line 5: cmd = "ping -c 1 " + host
  [sink]   line 6: os.system(cmd)
```

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

## Stack

Rust. A hand-written lexer and recursive-descent parser for a Python subset, and a
forward taint engine that tracks provenance so every finding carries its source-to-sink
line chain. See [DESIGN.md](DESIGN.md).

## Status

v0.2: five vuln classes over a Python subset, source-to-sink paths, directory/repo
scanning, CI exit codes, basic sanitizer awareness, severity, CLI + HTTP API + console +
MCP. Two independent audits fixed. Results are candidate paths (no control flow or
inter-procedural flow yet). Next: control-flow and cross-function taint, more languages,
and SARIF output.
