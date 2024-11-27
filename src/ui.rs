use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    terminal::{self, ClearType},
};
use std::io::{self, Write};
use std::collections::HashMap;
use crate::config::{Config, EncryptionConfig};
use crate::crypto::{self, CryptoConfig};

#[derive(Debug, Clone, PartialEq)]
pub enum MenuItemType {
    Dropdown,
    TextField { value: String, label: String },
    Toggle { value: bool, label: String },
    RadioButton { selected: bool, label: String },
    Checkbox { selected: bool, label: String },
}

#[derive(Debug, Clone)]
pub struct MenuItem {
    pub text: String,
    pub item_type: MenuItemType,
    pub children: Vec<MenuItem>,
    pub expanded: bool,
    pub depth: usize,
}

#[derive(Clone)]
struct ItemState {
    expanded: bool,
    item_type: MenuItemType,
}

impl MenuItem {
    pub fn new(text: &str, item_type: MenuItemType) -> Self {
        Self {
            text: text.to_string(),
            item_type,
            children: Vec::new(),
            expanded: false,
            depth: 0,
        }
    }

    pub fn add_child(&mut self, mut child: MenuItem) {
        child.depth = self.depth + 1;
        self.children.push(child);
    }
}

pub struct Menu {
    items: Vec<MenuItem>,
    selected_index: usize,
    config: Config,
}

impl Menu {
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            selected_index: 0,
            config: Config::default(),
        }
    }

    pub fn add_item(&mut self, mut item: MenuItem) {
        item.depth = 0;
        self.items.push(item);
    }

    fn to_crypto_config(&self, enc_config: &EncryptionConfig) -> CryptoConfig {
        CryptoConfig {
            encrypt_filenames: enc_config.encrypt_filenames,
            use_aes_256: enc_config.encrypt_algorithm, // true = AES-256, false = AES-128
        }
    }

    // Update the handler functions
    async fn handle_directory_encryption(&self, path: &str, key: &str, config: &EncryptionConfig) -> io::Result<()> {
        let crypto_config = self.to_crypto_config(config);
        crypto::encrypt_directory(path, key, &crypto_config).await
    }

    async fn handle_directory_decryption(&self, path: &str, key: &str, config: &EncryptionConfig) -> io::Result<()> {
        let crypto_config = self.to_crypto_config(config);
        crypto::decrypt_directory(path, key, &crypto_config).await
    }

    async fn handle_drive_encryption(&self, drives: Vec<String>, key: &str, config: &EncryptionConfig) -> io::Result<()> {
        let crypto_config = self.to_crypto_config(config);
        crypto::encrypt_drives(drives, key, &crypto_config).await
    }

    async fn handle_drive_decryption(&self, drives: Vec<String>, key: &str, config: &EncryptionConfig) -> io::Result<()> {
        let crypto_config = self.to_crypto_config(config);
        crypto::decrypt_drives(drives, key, &crypto_config).await
    }

    pub fn refresh_drive_list(&mut self) {
        for menu_type in &["Encryption", "Decryption"] {
            if let Some(menu) = self.items.iter_mut().find(|item| item.text == *menu_type) {
                if let Some(drive_menu) = menu.children.iter_mut().find(|item| item.text == "Drive") {
                    drive_menu.children.clear();
                    
                    // Add key fields first
                    drive_menu.add_child(MenuItem::new("Key", MenuItemType::TextField {
                        value: String::new(),
                        label: "Key".to_string(),
                    }));
                    
                    drive_menu.add_child(MenuItem::new("Key Confirmation", MenuItemType::TextField {
                        value: String::new(),
                        label: "Key Confirmation".to_string(),
                    }));
                    
                    // Add available drives as checkboxes
                    for drive in crate::get_available_drives() {
                        drive_menu.add_child(MenuItem::new(&drive.clone(), MenuItemType::Checkbox {
                            selected: false,
                            label: drive,
                        }));
                    }
                }
            }
        }
    }

    fn get_flattened_items(&self) -> Vec<MenuItem> {
        let mut flattened = Vec::new();
        for item in &self.items {
            Self::flatten_item_into(&item, &mut flattened, 0);
        }
        flattened
    }

    fn flatten_item_into(item: &MenuItem, flattened: &mut Vec<MenuItem>, current_depth: usize) {
        let mut item_clone = item.clone();
        item_clone.depth = current_depth;
        flattened.push(item_clone);
        
        if item.expanded {
            for child in &item.children {
                Self::flatten_item_into(child, flattened, current_depth + 1);
            }
        }
    }

    fn update_items(&mut self, flattened: &[MenuItem]) {
        let mut states: HashMap<String, ItemState> = HashMap::new();
        
        for item in flattened {
            states.insert(item.text.clone(), ItemState {
                expanded: item.expanded,
                item_type: item.item_type.clone(),
            });
        }

        for item in &mut self.items {
            Self::update_item_state(item, &states);
        }

        self.save_configuration();
    }

    fn save_configuration(&mut self) {
        for item in &self.items {
            Self::update_config_from_item(&mut self.config, item);
        }
        
        let _ = crate::config::save_config(&self.config);
    }

    fn update_config_from_item(config: &mut Config, item: &MenuItem) {
        match &item.item_type {
            MenuItemType::Checkbox { selected, label } => {
                if *selected {
                    config.registry.encrypted_drive.insert(label.clone());
                } else {
                    config.registry.encrypted_drive.remove(label);
                }
            }
            _ => match item.text.as_str() {
                "Filename encryption" => {
                    if let MenuItemType::Toggle { value, .. } = item.item_type {
                        config.encryption.encrypt_filenames = value;
                    }
                }
                "AES-256" => {
                    if let MenuItemType::RadioButton { selected, .. } = item.item_type {
                        config.encryption.encrypt_algorithm = selected;
                    }
                }
                _ => {}
            }
        }
        
        for child in &item.children {
            Self::update_config_from_item(config, child);
        }
    }

    fn handle_password_input(&self) -> io::Result<Option<String>> {
        let mut password = String::new();
        
        execute!(
            io::stdout(),
            terminal::Clear(ClearType::FromCursorDown),
            cursor::MoveTo(0, 25)
        )?;
        
        terminal::disable_raw_mode()?;
        crossterm::execute!(io::stdout(), cursor::Show)?;
        
        print!("Enter value: ");
        io::stdout().flush()?;
        
        loop {
            if let Event::Key(key_event) = event::read()? {
                match key_event.code {
                    KeyCode::Enter => break,
                    KeyCode::Char(c) => {
                        password.push(c);
                        print!("*");
                        io::stdout().flush()?;
                    }
                    KeyCode::Backspace => {
                        if !password.is_empty() {
                            password.pop();
                            print!("\x08 \x08");
                            io::stdout().flush()?;
                        }
                    }
                    _ => {}
                }
            }
        }
        
        println!();
        terminal::enable_raw_mode()?;
        crossterm::execute!(io::stdout(), cursor::Hide)?;
        
        Ok(Some(password))
    }

    pub async fn run(&mut self) -> io::Result<()> {
        terminal::enable_raw_mode()?;
    
        // Load config and apply it
        let initial_config = crate::config::load_config();
        self.apply_config_owned(initial_config);
        self.refresh_drive_list();
    
        loop {
            let mut flattened = self.get_flattened_items();
            self.draw(&flattened)?;
    
            if let Event::Key(KeyEvent { code, .. }) = event::read()? {
                match code {
                    KeyCode::Up => {
                        if self.selected_index > 0 {
                            self.selected_index -= 1;
                        }
                    }
                    KeyCode::Down => {
                        if self.selected_index < flattened.len() - 1 {
                            self.selected_index += 1;
                        }
                    }
                    KeyCode::Enter => {
                        if self.selected_index < flattened.len() {
                            match &flattened[self.selected_index].item_type.clone() {
                                MenuItemType::TextField { label, .. } => {
                                    let input = if label.contains("Key") {
                                        self.handle_password_input()?
                                    } else {
                                        self.handle_text_input()?
                                    };
    
                                    if let Some(value) = input {
                                        let is_key_confirmation = label == "Key Confirmation";
                                        
                                        flattened[self.selected_index].item_type = MenuItemType::TextField {
                                            value,
                                            label: label.clone(),
                                        };
                                        
                                        // Update items first
                                        self.update_items(&flattened);
                                        
                                        if is_key_confirmation {
                                            // First get confirmation
                                            let operation_result = self.check_keys_and_process(&flattened, self.selected_index).await;
                                            
                                            if operation_result.is_ok() { // Only proceed with spinner if confirmed
                                                // Create channel for progress indicator
                                                let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
                                                
                                                // Start the signal sender task
                                                let tx_clone = tx.clone();
                                                tokio::spawn(async move {
                                                    loop {
                                                        if let Err(_) = tx_clone.send(()).await {
                                                            break;
                                                        }
                                                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                                                    }
                                                });
                                        
                                                // Get the algorithm setting before spawn
                                                let use_aes_256 = self.config.encryption.encrypt_algorithm;
                                        
                                                // Start the progress display task
                                                let progress_handle = tokio::spawn(async move {
                                                    let mut result = Ok(());
                                                    'progress: loop {
                                                        match rx.recv().await {
                                                            Some(_) => {
                                                                if let Err(e) = execute!(
                                                                    io::stdout(),
                                                                    terminal::Clear(ClearType::CurrentLine),
                                                                    cursor::MoveTo(0, 25)
                                                                ) {
                                                                    result = Err(e);
                                                                    break 'progress;
                                                                }
                                                                
                                                                static SPINNER: [char; 4] = ['|', '/', '-', '\\'];
                                                                static mut SPINNER_IDX: usize = 0;
                                                                
                                                                let idx = unsafe {
                                                                    let current = SPINNER_IDX;
                                                                    SPINNER_IDX = (SPINNER_IDX + 1) % SPINNER.len();
                                                                    current
                                                                };
                                                                
                                                                let algorithm = if use_aes_256 {
                                                                    "AES-256"
                                                                } else {
                                                                    "AES-128"
                                                                };
                                                                
                                                                if let Err(e) = write!(io::stdout(), "Processing with {}, please wait {}", 
                                                                    algorithm,
                                                                    SPINNER[idx]
                                                                ) {
                                                                    result = Err(e);
                                                                    break 'progress;
                                                                }
                                                                
                                                                if let Err(e) = io::stdout().flush() {
                                                                    result = Err(e);
                                                                    break 'progress;
                                                                }
                                                            }
                                                            None => break 'progress,
                                                        }
                                                    }
                                                    result
                                                });
                                        
                                                // Process the operation
                                                let _ = self.actual_processing(&flattened, self.selected_index).await;
                                                
                                                // Stop the progress indicator
                                                drop(tx);
                                                let _ = progress_handle.await;
                                                
                                                // Clear the progress line
                                                execute!(
                                                    io::stdout(),
                                                    terminal::Clear(ClearType::CurrentLine),
                                                    cursor::MoveTo(0, 25)
                                                )?;
                                                
                                                self.show_message("Operation completed successfully")?;
                                            }
                                        }
                                    }
                                }
                                MenuItemType::Toggle { label, value } => {
                                    flattened[self.selected_index].item_type = MenuItemType::Toggle {
                                        value: !*value,
                                        label: label.clone(),
                                    };
                                    self.update_items(&flattened);
                                }
                                MenuItemType::RadioButton { label, .. } => {
                                    let target_label = label.clone();
                                    let current_depth = flattened[self.selected_index].depth;
                                    
                                    for item in flattened.iter_mut() {
                                        if item.depth == current_depth {
                                            if let MenuItemType::RadioButton { selected: s, label: l } = &mut item.item_type {
                                                *s = *l == target_label;
                                            }
                                        }
                                    }
                                    self.update_items(&flattened);
                                }
                                MenuItemType::Checkbox { selected, label } => {
                                    flattened[self.selected_index].item_type = MenuItemType::Checkbox {
                                        selected: !*selected,
                                        label: label.clone(),
                                    };
                                    self.update_items(&flattened);
                                }
                                MenuItemType::Dropdown => {
                                    flattened[self.selected_index].expanded = !flattened[self.selected_index].expanded;
                                    self.update_items(&flattened);
                                }
                            }
                        }
                    }
                    KeyCode::Esc => break,
                    _ => {}
                }
            }
        }
    
        terminal::disable_raw_mode()?;
        Ok(())
    }

    async fn check_keys_and_process(&mut self, flattened: &[MenuItem], current_index: usize) -> io::Result<bool> {
        let mut key = String::new();
        let mut key_confirmation = String::new();
        let mut path = String::new();
        let mut selected_drives = Vec::new();
    
        // Find current context
        let mut current_item = &flattened[current_index];
        let mut parent_texts = Vec::new();
        
        for i in (0..=current_index).rev() {
            let item = &flattened[i];
            if item.depth < current_item.depth {
                parent_texts.push(item.text.as_str());
                current_item = item;
            }
        }
        parent_texts.reverse();
    
        let is_drive = parent_texts.contains(&"Drive");
        let is_encryption = parent_texts.contains(&"Encryption");
    
        // Collect form values
        for item in flattened {
            match &item.item_type {
                MenuItemType::TextField { value, label } => {
                    match label.as_str() {
                        "Key" => key = value.clone(),
                        "Key Confirmation" => key_confirmation = value.clone(),
                        "Path" => path = value.clone(),
                        _ => {}
                    }
                }
                MenuItemType::Checkbox { selected: true, label } => {
                    selected_drives.push(label.clone());
                }
                _ => {}
            }
        }
    
        // Verify keys match
        if key.is_empty() || key_confirmation.is_empty() {
            self.show_message("Please fill in both key fields")?;
            return Ok(false);
        }
    
        if key != key_confirmation {
            self.show_message("Keys do not match")?;
            return Ok(false);
        }
    
        // Verify other requirements
        if is_drive {
            if selected_drives.is_empty() {
                self.show_message("Please select at least one drive")?;
                return Ok(false);
            }
        } else {
            if path.is_empty() {
                self.show_message("Please enter a path")?;
                return Ok(false);
            }
        }
    
        // Ask for confirmation
        let operation = if is_encryption { "encryption" } else { "decryption" };
        let target = if is_drive { "drive" } else { "directory" };
        let message = format!("Start {} {} process? (y/N)", target, operation);
        if !self.confirm_operation(&message)? {
            return Ok(false);
        }
    
        Ok(true)
    }

    fn show_message(&self, message: &str) -> io::Result<()> {
        execute!(
            io::stdout(),
            terminal::Clear(ClearType::FromCursorDown),
            cursor::MoveTo(0, 25)
        )?;
        
        println!("{}", message);
        println!("Press any key to continue...");
        event::read()?;
        Ok(())
    }

    fn confirm_operation(&self, message: &str) -> io::Result<bool> {
        execute!(
            io::stdout(),
            terminal::Clear(ClearType::FromCursorDown),
            cursor::MoveTo(0, 25)
        )?;
        
        println!("{}", message);
        
        if let Event::Key(KeyEvent { code, .. }) = event::read()? {
            Ok(matches!(code, KeyCode::Char('y') | KeyCode::Char('Y')))
        } else {
            Ok(false)
        }
    }

    fn update_item_state(item: &mut MenuItem, states: &HashMap<String, ItemState>) {
        if let Some(state) = states.get(&item.text) {
            item.expanded = state.expanded;
            item.item_type = state.item_type.clone();
        }
        for child in &mut item.children {
            Self::update_item_state(child, states);
        }
    }

    fn handle_text_input(&self) -> io::Result<Option<String>> {
        let mut input = String::new();
        
        execute!(
            io::stdout(),
            terminal::Clear(ClearType::FromCursorDown),
            cursor::MoveTo(0, 25)
        )?;
        
        terminal::disable_raw_mode()?;
        
        print!("Enter value: ");
        io::stdout().flush()?;
        
        io::stdin().read_line(&mut input)?;
        terminal::enable_raw_mode()?;
        
        Ok(Some(input.trim().to_string()))
    }

    fn apply_config_owned(&mut self, config: Config) {
        for item in &mut self.items {
            Self::apply_config_to_item(item, &config);
        }
        self.config = config;
    }

    fn draw(&self, flattened: &[MenuItem]) -> io::Result<()> {
        execute!(
            io::stdout(),
            terminal::Clear(ClearType::All),
            cursor::MoveTo(0, 0)
        )?;

        let ascii_art = r#"   _____ _ ____
  / ___/(_) __/__  _____
  \__ \/ / /_/ _ \/ ___/
 ___/ / / __/  __/ /
/____/_/_/  \___/_/    Sifer v1.0.0 - Use the arrow keys to navigate and the Enter key to select.
    "#;

        println!("{}\n", ascii_art);

        let mut current_line = 6;

        for (index, item) in flattened.iter().enumerate() {
            let prefix = if index == self.selected_index { ">" } else { " " };
            
            let indent = "   ".repeat(item.depth);
            
            let tree_symbol = if item.depth > 0 { "└ " } else { "" };
            
            let display_text = match &item.item_type {
                MenuItemType::Dropdown => item.text.clone(),
                MenuItemType::TextField { value, label } => {
                    if label.contains("Key") {
                        if value.is_empty() {
                            format!("{} : ", item.text)
                        } else {
                            format!("{} : {}", item.text, "*".repeat(value.len()))
                        }
                    } else {
                        if value.is_empty() {
                            format!("{} : ", item.text)
                        } else {
                            format!("{} : {}", item.text, value)
                        }
                    }
                }
                MenuItemType::Toggle { value, .. } => {
                    format!("{} = {}", item.text, if *value { "true" } else { "false" })
                }
                MenuItemType::RadioButton { selected, .. } => {
                    format!("[{}] {}", if *selected { "+" } else { " " }, item.text)
                }
                MenuItemType::Checkbox { selected, .. } => {
                    format!("[{}] {}", if *selected { "x" } else { " " }, item.text)
                }
            };

            execute!(
                io::stdout(),
                cursor::MoveTo(0, current_line)
            )?;
            
            print!("{}{}{}{}", prefix, indent, tree_symbol, display_text);
            current_line += 1;
        }

        io::stdout().flush()?;
        Ok(())
    }

    fn apply_config_to_item(item: &mut MenuItem, config: &Config) {
        if let MenuItemType::Checkbox { ref mut selected, ref label } = item.item_type {
            *selected = config.registry.encrypted_drive.contains(label);
        } else {
            match item.text.as_str() {
                "Filename encryption" => {
                    if let MenuItemType::Toggle { ref mut value, .. } = item.item_type {
                        *value = config.encryption.encrypt_filenames;
                    }
                }
                "AES-256" => {
                    if let MenuItemType::RadioButton { ref mut selected, .. } = item.item_type {
                        *selected = config.encryption.encrypt_algorithm;
                    }
                }
                "AES-128" => {
                    if let MenuItemType::RadioButton { ref mut selected, .. } = item.item_type {
                        *selected = !config.encryption.encrypt_algorithm;
                    }
                }
                _ => {}
            }
        }
        
        for child in &mut item.children {
            Self::apply_config_to_item(child, config);
        }
    }

    async fn actual_processing(&self, flattened: &[MenuItem], current_index: usize) -> io::Result<()> {
        let mut key = String::new();
        let mut path = String::new();
        let mut selected_drives = Vec::new();
    
        // Collect form values
        for item in flattened {
            match &item.item_type {
                MenuItemType::TextField { value, label } => {
                    match label.as_str() {
                        "Key" => key = value.clone(),
                        "Path" => path = value.clone(),
                        _ => {}
                    }
                }
                MenuItemType::Checkbox { selected: true, label } => {
                    selected_drives.push(label.clone());
                }
                _ => {}
            }
        }
    
        // Find the current menu context
        let mut current_item = &flattened[current_index];
        let mut parent_texts = Vec::new();
        
        // Walk backwards through flattened items to build path from root to current
        for i in (0..=current_index).rev() {
            let item = &flattened[i];
            if item.depth < current_item.depth {
                parent_texts.push(item.text.as_str());
                current_item = item;
            }
        }
        parent_texts.reverse();
    
        let is_drive = parent_texts.contains(&"Drive");
        let is_encryption = parent_texts.contains(&"Encryption");
    
        // Process based on operation type
        if is_drive {
            if is_encryption {
                self.handle_drive_encryption(selected_drives, &key, &self.config.encryption).await?;
            } else {
                self.handle_drive_decryption(selected_drives, &key, &self.config.encryption).await?;
            }
        } else {
            if is_encryption {
                self.handle_directory_encryption(&path, &key, &self.config.encryption).await?;
            } else {
                self.handle_directory_decryption(&path, &key, &self.config.encryption).await?;
            }
        }
    
        Ok(())
    }
}