use anyhow::Result;
use clap::{Parser, Subcommand};

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
    /// Scan a file for tainted-data paths into a dangerous sink.
    Scan {
        file: String,
        /// Emit findings as JSON instead of readable paths.
        #[arg(long)]
        json: bool,
    },
    /// Serve the HTTP API + paste-and-scan console.
    Serve {
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },
    /// Run as an MCP server over stdio so an agent can scan code.
    Mcp,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Scan { file, json } => {
            let src = std::fs::read_to_string(&file)?;
            let findings = lint_owl::analyze(&src);
            if json {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            } else if findings.is_empty() {
                println!("no tainted path to a command sink in {file}");
            } else {
                println!(
                    "{} tainted path(s) to a command sink in {file}:\n",
                    findings.len()
                );
                for f in &findings {
                    println!("{}", lint_owl::render(&src, f));
                }
            }
        }
        Cmd::Serve { port } => lint_owl::server::serve(port)?,
        Cmd::Mcp => lint_owl::mcp::serve_mcp()?,
    }
    Ok(())
}
