//! `lancer-agentic-radar-cli` — headless companion binary that always drops
//! into the CLI surface (equivalent to `lancer-agentic-radar --cli`).

fn main() -> anyhow::Result<()> {
    lancer_agentic_radar::run_cli_forced()
}
