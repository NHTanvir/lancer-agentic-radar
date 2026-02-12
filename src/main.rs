//! lancer-agentic-radar
//! Rust clone of agentic-radar. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-agentic-radar", version, about = "Rust clone of agentic-radar")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-agentic-radar - scaffold ready. Implement per plan.md.");
    Ok(())
}
