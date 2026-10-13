use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Global application settings, persisted as JSON in the platform config
/// directory so they survive application restarts.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct AppConfig {
    pub log_dir: String,
    pub ping_interval_s: f32,
    pub ping_timeout_s: f32,
    pub trace_max_hops: u8,
    pub trace_interval_s: f32,
    pub trace_timeout_s: f32,
    pub trace_resolve_names: bool,
    pub dns_use_system: bool,
    pub dns_custom_servers: String,
    pub dns_record_type: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            log_dir: default_log_dir(),
            ping_interval_s: 1.0,
            ping_timeout_s: 2.0,
            trace_max_hops: 30,
            trace_interval_s: 1.0,
            trace_timeout_s: 1.0,
            trace_resolve_names: false,
            dns_use_system: true,
            dns_custom_servers: "8.8.8.8\n1.1.1.1".to_string(),
            dns_record_type: "A".to_string(),
        }
    }
}

fn default_log_dir() -> String {
    directories::UserDirs::new()
        .and_then(|d| d.document_dir().map(|p| p.join("RustyTools").join("logs")))
        .unwrap_or_else(|| PathBuf::from("logs"))
        .to_string_lossy()
        .into_owned()
}

pub fn config_path() -> PathBuf {
    directories::ProjectDirs::from("com", "RustyTools", "RustyTools")
        .map(|d| d.config_dir().join("config.json"))
        .unwrap_or_else(|| PathBuf::from("rustytools-config.json"))
}

impl AppConfig {
    pub fn load() -> Self {
        std::fs::read_to_string(config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create config directory: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| format!("failed to write {}: {e}", path.display()))
    }
}

/// Removes what the application wrote on this machine: the log subfolders
/// and the config file. Everything is deleted by exact name or with a
/// non-recursive `remove_dir`, so a file we did not create is never touched.
pub fn remove_traces(log_dir: &str) -> Result<(), String> {
    crate::util::delete_log_dir(log_dir)?;
    // The default log folder is Documents/RustyTools/logs: drop the now-empty
    // RustyTools folder too. A custom log folder's parent is not ours.
    if log_dir.trim() == default_log_dir() {
        if let Some(parent) = Path::new(log_dir.trim()).parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }

    let path = config_path();
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("cannot delete {}: {e}", path.display())),
    }
    if let Some(dir) = path.parent() {
        remove_empty_app_dirs(dir);
    }
    Ok(())
}

/// Removes `dir` and then its parents, as long as each one is empty and is
/// named after the application (Windows nests RustyTools/RustyTools/config).
/// Stops at the first folder that is not ours, e.g. AppData/Roaming.
fn remove_empty_app_dirs(dir: &Path) {
    let ours = |p: &Path| {
        p.file_name().is_some_and(|n| n.to_string_lossy().to_lowercase().contains("rustytools"))
    };
    // The config folder itself is ours even when it is just called "config".
    let mut current = Some(dir).filter(|d| ours(d) || d.parent().is_some_and(ours));
    while let Some(d) = current {
        if std::fs::remove_dir(d).is_err() {
            break; // not empty (or already gone): leave everything above alone
        }
        current = d.parent().filter(|p| ours(p));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_empty_app_folders_are_removed() {
        let root = std::env::temp_dir().join(format!("rt_cfg_test_{}", std::process::id()));
        let config = root.join("RustyTools").join("RustyTools").join("config");
        std::fs::create_dir_all(&config).unwrap();

        // A foreign file in the middle folder stops the cleanup there.
        let foreign = root.join("RustyTools").join("notes.txt");
        std::fs::write(&foreign, "mine").unwrap();
        remove_empty_app_dirs(&config);
        assert!(!root.join("RustyTools").join("RustyTools").exists());
        assert!(foreign.exists());

        // Once empty, the app folders go, but never the folder above them.
        std::fs::remove_file(&foreign).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        remove_empty_app_dirs(&config);
        assert!(!root.join("RustyTools").exists());
        assert!(root.exists(), "a folder that is not ours was removed");

        // A folder unrelated to the app is never touched, even when empty.
        let other = root.join("other");
        std::fs::create_dir_all(&other).unwrap();
        remove_empty_app_dirs(&other);
        assert!(other.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
