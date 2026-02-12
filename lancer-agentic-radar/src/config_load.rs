//! Loading `ar.toml` / `--config <yaml>` into an [`ar_core::Config`], then
//! merging CLI overrides on top.

use std::path::Path;

use ar_core::{ComplianceMode, Config, Severity};

/// Load configuration. Resolution order:
/// 1. explicit `--config <file>` (`.toml` or `.yaml`/`.yml` by extension),
/// 2. `ar.toml` in the scan root,
/// 3. defaults.
pub fn load_config(explicit: Option<&Path>, scan_root: &Path) -> anyhow::Result<Config> {
    if let Some(path) = explicit {
        return parse_config_file(path);
    }
    // Implicit ar.toml next to / inside the scan root.
    let candidate = if scan_root.is_dir() {
        scan_root.join("ar.toml")
    } else {
        scan_root
            .parent()
            .map(|p| p.join("ar.toml"))
            .unwrap_or_else(|| Path::new("ar.toml").to_path_buf())
    };
    if candidate.exists() {
        return parse_config_file(&candidate);
    }
    Ok(Config::default())
}

fn parse_config_file(path: &Path) -> anyhow::Result<Config> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.display()))?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let cfg: Config = match ext.as_str() {
        "yaml" | "yml" => serde_yaml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parsing YAML config {}: {e}", path.display()))?,
        _ => toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parsing TOML config {}: {e}", path.display()))?,
    };
    Ok(cfg)
}

/// Apply CLI overrides onto a loaded config.
pub fn merge_cli(
    mut cfg: Config,
    fail_on: &[String],
    compliance: &[String],
    exclude: &[String],
) -> anyhow::Result<Config> {
    for s in fail_on {
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let sev: Severity = part
                .parse()
                .map_err(|e| anyhow::anyhow!("--fail-on: {e}"))?;
            if !cfg.fail_on.contains(&sev) {
                cfg.fail_on.push(sev);
            }
        }
    }
    for s in compliance {
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let mode: ComplianceMode = part
                .parse()
                .map_err(|e| anyhow::anyhow!("--compliance-mode: {e}"))?;
            if !cfg.compliance_modes.contains(&mode) {
                cfg.compliance_modes.push(mode);
            }
        }
    }
    for e in exclude {
        for part in e.split(',') {
            let part = part.trim();
            if !part.is_empty() {
                cfg.detectors.exclude.push(part.to_string());
            }
        }
    }
    Ok(cfg)
}
