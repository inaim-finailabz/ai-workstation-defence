//! Replays a JSON-lines file of `RawEvent`s -- for demos, tests and
//! re-checking a recorded session against new rules.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use awd_core::RawEvent;

pub fn read(path: &Path) -> Result<Vec<RawEvent>> {
    let reader = BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    let mut out = Vec::new();
    for (n, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(serde_json::from_str(&line).with_context(|| format!("line {}", n + 1))?);
    }
    Ok(out)
}
