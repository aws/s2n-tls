use anyhow::Result;
use chrono::Utc;
use std::path::Path;
use std::process::Command;
use uuid::Uuid;

/// Generate a unique ID for a snapshot
#[allow(dead_code)]
pub fn generate_snapshot_id() -> String {
    Uuid::new_v4().to_string()
}

/// Generate a timestamp-based ID for a snapshot
pub fn generate_timestamp_id() -> String {
    let now = Utc::now();
    now.format("%Y%m%d_%H%M%S").to_string()
}

/// Get the current git commit hash
pub fn get_git_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    
    if output.status.success() {
        String::from_utf8(output.stdout)
            .map(|s| s.trim().to_string())
            .ok()
    } else {
        None
    }
}

/// Get the current git branch
pub fn get_git_branch() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()?;
    
    if output.status.success() {
        String::from_utf8(output.stdout)
            .map(|s| s.trim().to_string())
            .ok()
    } else {
        None
    }
}

/// Check if a path is within a git repository
#[allow(dead_code)]
pub fn is_git_repository<P: AsRef<Path>>(path: P) -> bool {
    let output = Command::new("git")
        .current_dir(path)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output();
    
    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.trim() == "true"
        }
        _ => false,
    }
}

/// Get the relative path from the git repository root
#[allow(dead_code)]
pub fn get_relative_path<P: AsRef<Path>>(path: P) -> Result<String> {
    let path = path.as_ref();
    
    let output = Command::new("git")
        .current_dir(path)
        .args(["rev-parse", "--show-toplevel"])
        .output()?;
    
    if !output.status.success() {
        anyhow::bail!("Failed to get git repository root");
    }
    
    let repo_root = String::from_utf8(output.stdout)?.trim().to_string();
    let repo_root_path = Path::new(&repo_root);
    
    let absolute_path = path.canonicalize()?;
    let relative_path = absolute_path.strip_prefix(repo_root_path)?;
    
    Ok(relative_path.to_string_lossy().to_string())
}
