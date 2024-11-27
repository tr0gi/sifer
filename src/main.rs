mod config;
mod ui;
mod crypto;

use ui::{Menu, MenuItem, MenuItemType};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut menu = Menu::new();
    
    // Encryption menu
    let mut encryption = MenuItem::new("Encryption", MenuItemType::Dropdown);
    let mut dir_encryption = MenuItem::new("Directory", MenuItemType::Dropdown);
    dir_encryption.add_child(MenuItem::new("Path", MenuItemType::TextField {
        value: String::new(),
        label: "Path".to_string(),
    }));
    dir_encryption.add_child(MenuItem::new("Key", MenuItemType::TextField {
        value: String::new(),
        label: "Key".to_string(),
    }));
    dir_encryption.add_child(MenuItem::new("Key Confirmation", MenuItemType::TextField {
        value: String::new(),
        label: "Key Confirmation".to_string(),
    }));
    encryption.add_child(dir_encryption);
    encryption.add_child(MenuItem::new("Drive", MenuItemType::Dropdown));
    
    // Decryption menu
    let mut decryption = MenuItem::new("Decryption", MenuItemType::Dropdown);

    let mut dir_decryption = MenuItem::new("Directory", MenuItemType::Dropdown);
    dir_decryption.add_child(MenuItem::new("Path", MenuItemType::TextField {
        value: String::new(),
        label: "Path".to_string(),
    }));
    dir_decryption.add_child(MenuItem::new("Key", MenuItemType::TextField {
        value: String::new(),
        label: "Key".to_string(),
    }));
    dir_decryption.add_child(MenuItem::new("Key Confirmation", MenuItemType::TextField {
        value: String::new(),
        label: "Key Confirmation".to_string(),
    }));
    decryption.add_child(dir_decryption);
    decryption.add_child(MenuItem::new("Drive", MenuItemType::Dropdown));
    
    // Settings menu
    let mut settings = MenuItem::new("Settings", MenuItemType::Dropdown);
    
    let mut dir_encryption_settings = MenuItem::new("Directory Encryption", MenuItemType::Dropdown);
    dir_encryption_settings.add_child(MenuItem::new("Filename encryption", MenuItemType::Toggle {
        value: true,
        label: "Filename encryption".to_string(),
    }));
    
    let mut encryption_algorithm = MenuItem::new("Encryption Algorithm", MenuItemType::Dropdown);
    encryption_algorithm.add_child(MenuItem::new("AES-128", MenuItemType::RadioButton {
        selected: false,
        label: "AES-128".to_string(),
    }));
    encryption_algorithm.add_child(MenuItem::new("AES-256", MenuItemType::RadioButton {
        selected: true,
        label: "AES-256".to_string(),
    }));
    
    settings.add_child(dir_encryption_settings);
    settings.add_child(encryption_algorithm);
    
    // Add all main menu items
    menu.add_item(encryption);
    menu.add_item(decryption);
    menu.add_item(settings);
    
    menu.run().await
}

#[cfg(target_os = "windows")]
pub fn get_available_drives() -> Vec<String> {
    use std::path::PathBuf;

    let mut drives = Vec::new();
    
    // Windows drive letters from A to Z
    for c in b'A'..=b'Z' {
        let drive = format!("{}:\\", c as char);
        let path = PathBuf::from(&drive);
        
        // Check if drive exists and is ready
        if path.exists() {
            drives.push(drive);
        }
    }
    
    drives
}

#[cfg(target_os = "linux")]
pub fn get_available_drives() -> Vec<String> {
    let mut drives = Vec::new();
    
    // Read /proc/partitions or use sysfs
    if let Ok(content) = std::fs::read_to_string("/proc/partitions") {
        for line in content.lines().skip(2) { // Skip header lines
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(device) = parts.get(3) {
                // Filter out partition numbers and only include main devices
                if device.starts_with("sd") || device.starts_with("nvme") {
                    if !device.chars().any(char::is_numeric) {
                        drives.push(format!("/dev/{}", device));
                    }
                }
            }
        }
    }
    
    drives
}