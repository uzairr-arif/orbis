//! Small std-only helpers shared by the collectors.

use std::env;
use std::path::PathBuf;

/// True when `tool` (tool.exe on Windows) exists on PATH.
/// Avoids spawning processes just to probe availability.
pub fn tool_exists(tool: &str) -> bool {
    let path = match env::var_os("PATH") {
        Some(p) => p,
        None => return false,
    };

    let candidates: Vec<PathBuf> = if cfg!(windows) {
        vec![
            format!("{tool}.exe"),
            format!("{tool}.com"),
            tool.to_string(),
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect()
    } else {
        vec![PathBuf::from(tool)]
    };

    env::split_paths(&path).any(|dir| candidates.iter().any(|c| dir.join(c).is_file()))
}
