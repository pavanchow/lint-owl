//! MCP server so an AI reviewing code can ask Lint-Owl for source-to-sink paths.
//! JSON-RPC 2.0 over stdio (newline-delimited).

use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

enum Reply {
    Ok(Value),
    Err(i64, String),
    Silent,
}

pub fn serve_mcp() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id = req.get("id").cloned();
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let reply = handle(method, req.get("params"));
        let envelope = match reply {
            Reply::Silent => continue,
            Reply::Ok(result) => match id {
                Some(id) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
                None => continue,
            },
            Reply::Err(code, msg) => match id {
                Some(id) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } }),
                None => continue,
            },
        };
        writeln!(stdout, "{envelope}")?;
        stdout.flush()?;
    }
    Ok(())
}

fn handle(method: &str, params: Option<&Value>) -> Reply {
    match method {
        "initialize" => Reply::Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "lint-owl", "version": env!("CARGO_PKG_VERSION") }
        })),
        "notifications/initialized" => Reply::Silent,
        "ping" => Reply::Ok(json!({})),
        "tools/list" => Reply::Ok(json!({ "tools": [
            {
                "name": "lint_owl_scan",
                "description": "Scan source code (Python subset) and return data-flow paths from an untrusted source to a dangerous sink (command injection, SQL injection, SSRF, path traversal, insecure deserialization). Each finding lists the source line, the flow, and the sink line.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "code": { "type": "string", "description": "The source code to scan." } },
                    "required": ["code"]
                }
            }
        ] })),
        "tools/call" => {
            let params = params.cloned().unwrap_or(json!({}));
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            if name != "lint_owl_scan" {
                return Reply::Ok(json!({
                    "content": [{ "type": "text", "text": format!("unknown tool: {name}") }],
                    "isError": true
                }));
            }
            let code = params
                .get("arguments")
                .and_then(|a| a.get("code"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let result = crate::scan_json(code);
            Reply::Ok(json!({
                "content": [{ "type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_default() }],
                "isError": false
            }))
        }
        _ => Reply::Err(-32601, format!("method not found: {method}")),
    }
}
