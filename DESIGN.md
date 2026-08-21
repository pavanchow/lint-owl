# Lint-Owl, design

Lint-Owl is a static analyzer whose result is the data-flow path from an untrusted
source to a dangerous sink, not a flat list of line-number warnings. It proves one
property deeply (does taint reach the sink) instead of running many shallow rules.

This is the same idea as Oracle: the answer is a walkable path, here through code.

## Prior art, and where Lint-Owl differs

- **Linters (pylint, eslint, ruff)** flag style and local smells. No cross-statement
  data flow, no source-to-sink reasoning.
- **Semgrep** matches syntactic patterns. Great for known-shape bugs, but a pattern
  does not prove that attacker input actually reaches the sink through assignments.
- **CodeQL** is a real dataflow engine, but heavy: build a database, learn QL, and it
  is closed-ish. Powerful for teams, overkill for a bounty hunter on one file.

Lint-Owl's difference: the output IS the tainted path (source line, each hop, sink
line), it is one small binary, and it is agent-native (an MCP tool an AI asks "does
user input reach this exec"). It aims to be the fastest way to get a believable
source-to-sink answer on real code.

## Model (v0.1)

- **Sources**: calls/names that return attacker data (`input()`, `request.args.get`,
  `sys.argv`, ...).
- **Sinks**: command-execution calls (`os.system`, `subprocess.*`, `eval`, `exec`).
- **Propagation**: taint flows through assignment and string concatenation, and passes
  through non-sink calls that take a tainted argument.
- **Finding**: a tainted argument reaching a sink call. The path is the line numbers
  from the source, through each assignment, to the sink.

## Handled idioms

Assignment, string concatenation, f-string interpolation (`f"... {x} ..."`), method
chaining (`conn.cursor().execute(q)`), keyword-led statements (`with open(p) as f:`,
`return run(x)`), semicolons, and multi-line calls (joined by paren balance). The
parser is depth-bounded so hostile deeply-nested input truncates instead of
overflowing the stack.

## Honest limits (v0.1, on purpose)

- One language (a Python subset), five vuln classes.
- Forward, single scope: no control flow (if/for branch conditions), no flow across
  function calls, no sanitizer awareness yet. So results are *candidate* paths a human
  confirms, the same honesty stance Oracle takes. Sanitizers and inter-procedural flow
  are the headline correctness work for v0.2.

## Roadmap

### v0.1
1. Taint engine + Python-subset front end + CLI (done in this slice).
2. More vuln classes (SQL injection, SSRF, path traversal, unsafe deserialization),
   each source/sink set is data, so this is additive.
3. HTTP API + a small results UI, then an MCP server (`lint_owl_scan`), mirroring Oracle.

### v0.2
4. Sanitizer awareness (a tainted value passed through an escaper is cleared).
5. Control flow and inter-procedural flow (taint across function calls).
6. A second real language front end.
