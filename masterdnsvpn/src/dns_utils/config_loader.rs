// MasterDnsVPN Config Loader
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Return the directory of the running executable or main script.
pub fn get_app_dir() -> PathBuf {
    // Try the executable path first
    if let Ok(exe_path) = env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            return parent.to_path_buf();
        }
    }
    // Fallback to current working directory
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Return the full path to the config file next to the exe/script.
pub fn get_config_path(config_filename: &str) -> PathBuf {
    get_app_dir().join(config_filename)
}

/// Load configuration from a TOML file located next to the executable or main script.
/// Returns an empty HashMap if the file is not found or cannot be parsed.
pub fn load_config(config_filename: &str) -> HashMap<String, toml::Value> {
    let config_path = get_config_path(config_filename);
    load_config_from_path(&config_path)
}

/// Load configuration from an explicit path.
pub fn load_config_from_path(config_path: &Path) -> HashMap<String, toml::Value> {
    if !config_path.is_file() {
        return HashMap::new();
    }
    match fs::read_to_string(config_path) {
        Ok(content) => match content.parse::<toml::Value>() {
            Ok(toml::Value::Table(table)) => table
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect(),
            Ok(_) => {
                eprintln!(
                    "[MasterDnsVPN] Config file '{}' is not a TOML table",
                    config_path.display()
                );
                HashMap::new()
            }
            Err(e) => {
                eprintln!(
                    "[MasterDnsVPN] Failed to parse config file '{}': {}",
                    config_path.display(),
                    e
                );
                HashMap::new()
            }
        },
        Err(e) => {
            eprintln!(
                "[MasterDnsVPN] Failed to read config file '{}': {}",
                config_path.display(),
                e
            );
            HashMap::new()
        }
    }
}

/// Helper trait for convenient value extraction from TOML config.
pub trait TomlValueExt {
    fn get_str(&self, key: &str) -> Option<String>;
    fn get_i64(&self, key: &str) -> Option<i64>;
    fn get_f64(&self, key: &str) -> Option<f64>;
    fn get_bool(&self, key: &str) -> Option<bool>;
    fn get_str_or(&self, key: &str, default: &str) -> String;
    fn get_i64_or(&self, key: &str, default: i64) -> i64;
    fn get_f64_or(&self, key: &str, default: f64) -> f64;
    fn get_bool_or(&self, key: &str, default: bool) -> bool;
    fn get_string_array(&self, key: &str) -> Vec<String>;
    fn get_i64_array(&self, key: &str) -> Vec<i64>;
}

impl TomlValueExt for HashMap<String, toml::Value> {
    fn get_str(&self, key: &str) -> Option<String> {
        self.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.as_integer())
    }

    fn get_f64(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(|v| match v {
            toml::Value::Float(f) => Some(*f),
            toml::Value::Integer(i) => Some(*i as f64),
            _ => None,
        })
    }

    fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }

    fn get_str_or(&self, key: &str, default: &str) -> String {
        self.get_str(key).unwrap_or_else(|| default.to_string())
    }

    fn get_i64_or(&self, key: &str, default: i64) -> i64 {
        self.get_i64(key).unwrap_or(default)
    }

    fn get_f64_or(&self, key: &str, default: f64) -> f64 {
        self.get_f64(key).unwrap_or(default)
    }

    fn get_bool_or(&self, key: &str, default: bool) -> bool {
        self.get_bool(key).unwrap_or(default)
    }

    fn get_string_array(&self, key: &str) -> Vec<String> {
        self.get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn get_i64_array(&self, key: &str) -> Vec<i64> {
        self.get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_integer())
                    .collect()
            })
            .unwrap_or_default()
    }
}
