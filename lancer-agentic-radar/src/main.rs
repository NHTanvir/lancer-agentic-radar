//! `lancer-agentic-radar` — opens the native GUI by default; pass a subcommand
//! or `--cli` for the command-line surface. See `lib.rs` for the entry logic.

fn main() -> anyhow::Result<()> {
    lancer_agentic_radar::run_default()
}
