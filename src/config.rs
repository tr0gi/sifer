use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub encryption: EncryptionConfig,
    #[serde(default)]
    pub registry: RegistryConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptionConfig {
    pub encrypt_filenames: bool,
    pub encrypt_algorithm: bool, // true=aes256, false=aes128
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            encrypt_filenames: true,
            encrypt_algorithm: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct RegistryConfig {
    #[serde(default)]
    pub encrypted_directory: HashSet<String>,
    #[serde(default)]
    pub encrypted_drive: HashSet<String>,
}

pub fn load_config() -> Config {
    let config_path = PathBuf::from("config.toml");
    if config_path.exists() {
        toml::from_str(&std::fs::read_to_string(config_path).unwrap_or_default())
            .unwrap_or_default()
    } else {
        Config::default()
    }
}

pub fn save_config(config: &Config) -> std::io::Result<()> {
    let config_str = toml::to_string(&config).unwrap();
    std::fs::write("config.toml", config_str)
}