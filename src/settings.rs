use std::path::PathBuf;

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
