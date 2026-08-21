use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "lint-owl",
    version,
    about = "A static analyzer whose result is the data-flow path from an untrusted source to a dangerous sink"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan a Python file or a directory tree for tainted source-to-sink paths.
    Scan {
        /// A .py file or a directory (scanned recursively).
        path: String,
        /// Emit findings as JSON instead of readable paths.
        #[arg(long)]
        json: bool,
        /// Emit SARIF 2.1.0 (for GitHub code scanning and IDEs).
        #[arg(long)]
        sarif: bool,
        /// A JSON file adding custom sources/sinks/sanitizers.
        #[arg(long)]
        config: Option<String>,
        /// Always exit 0, even when findings exist (default is exit 1 on findings).
        #[arg(long)]
        exit_zero: bool,
    },
    /// Serve the HTTP API + paste-and-scan console.
    Serve {
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },
    /// Run as an MCP server over stdio so an agent can scan code.
    Mcp,
}

/// Collect .py files under a path (the path itself if it is a file).
fn py_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.is_file() {
        out.push(root.to_path_buf());
        return out;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for e in entries.flatten() {
            let p = e.path();
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name.starts_with('.') || name == "venv" || name == "node_modules" {
                continue;
            }
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|s| s.to_str()) == Some("py") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Scan { path, json, sarif, config, exit_zero } => {
            let mut cfg = lint_owl::python_config();
            if let Some(cfile) = &config {
                let raw = std::fs::read_to_string(cfile)?;
                let v: serde_json::Value = serde_json::from_str(&raw)?;
                cfg.merge_json(&v);
            }
            let files = py_files(Path::new(&path));
            let mut total = 0usize;
            let mut per_file_json = Vec::new();
            let mut for_sarif: Vec<(String, String, Vec<lint_owl::Finding>)> = Vec::new();

            for file in &files {
                let src = match std::fs::read_to_string(file) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let findings = lint_owl::analyze_cfg(&src, &cfg);
                total += findings.len();
                if sarif {
                    for_sarif.push((file.display().to_string(), src, findings));
                } else if json {
                    let mut v = lint_owl::scan_json_cfg(&src, &cfg);
                    v["file"] = serde_json::json!(file.display().to_string());
                    per_file_json.push(v);
                } else if !findings.is_empty() {
                    println!("== {} ==", file.display());
                    for f in &findings {
                        println!("{}", lint_owl::render(&src, f));
                    }
                }
            }

            if sarif {
                println!("{}", serde_json::to_string_pretty(&lint_owl::sarif(&for_sarif))?);
            } else if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "files_scanned": files.len(),
                        "total_findings": total,
                        "results": per_file_json,
                    }))?
                );
            } else if total == 0 {
                println!("no tainted paths in {} file(s)", files.len());
            } else {
                println!("\n{total} tainted path(s) across {} file(s)", files.len());
            }

            // Non-zero exit on findings so this is usable in CI and pre-commit.
            if total > 0 && !exit_zero {
                std::process::exit(1);
            }
        }
        Cmd::Serve { port } => lint_owl::server::serve(port)?,
        Cmd::Mcp => lint_owl::mcp::serve_mcp()?,
    }
    Ok(())
}
