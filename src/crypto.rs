use std::fs::{self, File};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::path::Path;
use walkdir::WalkDir;
use aes::{Aes128, Aes256, cipher::{
    BlockEncrypt, BlockDecrypt,
    KeyInit,
    generic_array::GenericArray,
}};
use xts_mode::{Xts128, get_tweak_default};
use sha2::{Sha256, Digest};

const SECTOR_SIZE: usize = 0x200;

pub struct CryptoConfig {
    pub encrypt_filenames: bool,
    pub use_aes_256: bool,
}

fn derive_key(password: &str, use_aes_256: bool) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    
    if use_aes_256 {
        let mut key = [0u8; 64];
        let mut hasher2 = Sha256::new();
        hasher2.update(&result);
        let result2 = hasher2.finalize();
        
        key[..32].copy_from_slice(&result);
        key[32..].copy_from_slice(&result2);
        key.to_vec()
    } else {
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key.to_vec()
    }
}

fn encrypt_file(path: &Path, key: &[u8], use_aes_256: bool) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let encrypted = if use_aes_256 {
        let cipher = Aes256::new(GenericArray::from_slice(&key[..32]));
        let mut blocks = contents.chunks_exact_mut(16).collect::<Vec<_>>();
        for block in &mut blocks {
            let mut block_array = GenericArray::from_slice(block).to_owned();
            cipher.encrypt_block(&mut block_array);
            block.copy_from_slice(&block_array);
        }
        contents
    } else {
        let cipher = Aes128::new(GenericArray::from_slice(&key[..16]));
        let mut blocks = contents.chunks_exact_mut(16).collect::<Vec<_>>();
        for block in &mut blocks {
            let mut block_array = GenericArray::from_slice(block).to_owned();
            cipher.encrypt_block(&mut block_array);
            block.copy_from_slice(&block_array);
        }
        contents
    };

    let mut file = File::create(path)?;
    file.write_all(&encrypted)?;
    
    Ok(())
}

fn decrypt_file(path: &Path, key: &[u8], use_aes_256: bool) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    if use_aes_256 {
        let key = GenericArray::from_slice(&key[..32]);
        let cipher = Aes256::new(key);
        
        for chunk in contents.chunks_exact_mut(16) {
            let mut block = GenericArray::from_slice(chunk).to_owned();
            cipher.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
    } else {
        let key = GenericArray::from_slice(&key[..16]);
        let cipher = Aes128::new(key);
        
        for chunk in contents.chunks_exact_mut(16) {
            let mut block = GenericArray::from_slice(chunk).to_owned();
            cipher.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
    }

    if let Some(&padding) = contents.last() {
        let padding = padding as usize;
        if padding <= 16 {
            contents.truncate(contents.len() - padding);
        }
    }

    let mut file = File::create(path)?;
    file.write_all(&contents)?;
    Ok(())
}

pub async fn encrypt_drive(drive_path: &str, password: &str, config: &CryptoConfig) -> io::Result<()> {
    let key = derive_key(password, config.use_aes_256);
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(drive_path)?;
    
    let file_size = file.metadata()?.len();
    let total_sectors = (file_size + SECTOR_SIZE as u64 - 1) / SECTOR_SIZE as u64;
    
    if config.use_aes_256 {
        let cipher_1 = Aes256::new(GenericArray::from_slice(&key[..32]));
        let cipher_2 = Aes256::new(GenericArray::from_slice(&key[32..]));
        let xts = Xts128::new(&cipher_1, &cipher_2);
        
        for sector in 0..total_sectors {
            let mut buffer = vec![0u8; SECTOR_SIZE];
            file.seek(SeekFrom::Start(sector * SECTOR_SIZE as u64))?;
            file.read_exact(&mut buffer)?;
            
            xts.encrypt_area(&mut buffer, SECTOR_SIZE, u128::from(sector), get_tweak_default);
            
            file.seek(SeekFrom::Start(sector * SECTOR_SIZE as u64))?;
            file.write_all(&buffer)?;
        }
    } else {
        let cipher_1 = Aes128::new(GenericArray::from_slice(&key[..16]));
        let cipher_2 = Aes128::new(GenericArray::from_slice(&key[16..]));
        let xts = Xts128::new(&cipher_1, &cipher_2);
        
        for sector in 0..total_sectors {
            let mut buffer = vec![0u8; SECTOR_SIZE];
            file.seek(SeekFrom::Start(sector * SECTOR_SIZE as u64))?;
            file.read_exact(&mut buffer)?;
            
            xts.encrypt_area(&mut buffer, SECTOR_SIZE, u128::from(sector), get_tweak_default);
            
            file.seek(SeekFrom::Start(sector * SECTOR_SIZE as u64))?;
            file.write_all(&buffer)?;
        }
    }
    
    file.sync_all()?;
    Ok(())
}

pub async fn decrypt_drive(drive_path: &str, password: &str, config: &CryptoConfig) -> io::Result<()> {
    let key = derive_key(password, config.use_aes_256);
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(drive_path)?;
    
    let file_size = file.metadata()?.len();
    let total_sectors = (file_size + SECTOR_SIZE as u64 - 1) / SECTOR_SIZE as u64;
    
    if config.use_aes_256 {
        let cipher_1 = Aes256::new(GenericArray::from_slice(&key[..32]));
        let cipher_2 = Aes256::new(GenericArray::from_slice(&key[32..]));
        let xts = Xts128::new(&cipher_1, &cipher_2);
        
        for sector in 0..total_sectors {
            let mut buffer = vec![0u8; SECTOR_SIZE];
            file.seek(SeekFrom::Start(sector * SECTOR_SIZE as u64))?;
            file.read_exact(&mut buffer)?;
            
            xts.decrypt_area(&mut buffer, SECTOR_SIZE, u128::from(sector), get_tweak_default);
            
            file.seek(SeekFrom::Start(sector * SECTOR_SIZE as u64))?;
            file.write_all(&buffer)?;
        }
    } else {
        let cipher_1 = Aes128::new(GenericArray::from_slice(&key[..16]));
        let cipher_2 = Aes128::new(GenericArray::from_slice(&key[16..]));
        let xts = Xts128::new(&cipher_1, &cipher_2);
        
        for sector in 0..total_sectors {
            let mut buffer = vec![0u8; SECTOR_SIZE];
            file.seek(SeekFrom::Start(sector * SECTOR_SIZE as u64))?;
            file.read_exact(&mut buffer)?;
            
            xts.decrypt_area(&mut buffer, SECTOR_SIZE, u128::from(sector), get_tweak_default);
            
            file.seek(SeekFrom::Start(sector * SECTOR_SIZE as u64))?;
            file.write_all(&buffer)?;
        }
    }
    
    file.sync_all()?;
    Ok(())
}

fn encrypt_filename(filename: &str, key: &[u8], use_aes_256: bool) -> io::Result<String> {
    // Convert filename to bytes and pad to 16-byte blocks
    let mut filename_bytes = filename.as_bytes().to_vec();
    let padding = (16 - (filename_bytes.len() % 16)) % 16;
    filename_bytes.extend(vec![padding as u8; padding]);

    // Encrypt the filename bytes
    if use_aes_256 {
        let key = GenericArray::from_slice(&key[..32]);
        let cipher = Aes256::new(key);
        
        for chunk in filename_bytes.chunks_exact_mut(16) {
            let mut block = GenericArray::from_slice(chunk).to_owned();
            cipher.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
    } else {
        let key = GenericArray::from_slice(&key[..16]);
        let cipher = Aes128::new(key);
        
        for chunk in filename_bytes.chunks_exact_mut(16) {
            let mut block = GenericArray::from_slice(chunk).to_owned();
            cipher.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
    }

    // Convert to hex string
    Ok(hex::encode(&filename_bytes))
}

fn decrypt_filename(encrypted_hex: &str, key: &[u8], use_aes_256: bool) -> io::Result<String> {
    // Convert hex back to bytes
    let mut encrypted_bytes = hex::decode(encrypted_hex)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Decrypt the filename bytes
    if use_aes_256 {
        let key = GenericArray::from_slice(&key[..32]);
        let cipher = Aes256::new(key);
        
        for chunk in encrypted_bytes.chunks_exact_mut(16) {
            let mut block = GenericArray::from_slice(chunk).to_owned();
            cipher.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
    } else {
        let key = GenericArray::from_slice(&key[..16]);
        let cipher = Aes128::new(key);
        
        for chunk in encrypted_bytes.chunks_exact_mut(16) {
            let mut block = GenericArray::from_slice(chunk).to_owned();
            cipher.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
    }

    // Remove padding
    if let Some(&padding) = encrypted_bytes.last() {
        let padding = padding as usize;
        if padding <= 16 {
            encrypted_bytes.truncate(encrypted_bytes.len() - padding);
        }
    }

    // Convert back to string
    String::from_utf8(encrypted_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub async fn encrypt_directory(path: &str, password: &str, config: &CryptoConfig) -> io::Result<()> {
    let key = derive_key(password, config.use_aes_256);
    
    // First collect all files to avoid modification during iteration
    let files: Vec<_> = WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_owned())
        .collect();
    
    // Process each file
    for file_path in files {
        encrypt_file(&file_path, &key, config.use_aes_256)?;
        
        if config.encrypt_filenames {
            let parent = file_path.parent().unwrap_or_else(|| Path::new(""));
            let filename = file_path.file_name().unwrap().to_string_lossy();
            
            let encrypted_name = encrypt_filename(&filename, &key, config.use_aes_256)?;
            let new_path = parent.join(encrypted_name);
            fs::rename(&file_path, new_path)?;
        }
    }
    
    Ok(())
}

pub async fn decrypt_directory(path: &str, password: &str, config: &CryptoConfig) -> io::Result<()> {
    let key = derive_key(password, config.use_aes_256);
    
    // Collect all files first
    let files: Vec<_> = WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_owned())
        .collect();

    // Process each file
    for file_path in files {
        // Decrypt file contents
        decrypt_file(&file_path, &key, config.use_aes_256)?;
        
        // Decrypt filename if needed
        if config.encrypt_filenames {
            if let Some(filename) = file_path.file_name() {
                if let Some(filename_str) = filename.to_str() {
                    // Try to decrypt the filename
                    if let Ok(decrypted_name) = decrypt_filename(filename_str, &key, config.use_aes_256) {
                        let parent = file_path.parent().unwrap_or_else(|| Path::new(""));
                        let new_path = parent.join(decrypted_name);
                        fs::rename(&file_path, new_path)?;
                    }
                }
            }
        }
    }
    
    Ok(())
}

pub async fn encrypt_drives(drives: Vec<String>, password: &str, config: &CryptoConfig) -> io::Result<()> {
    for drive in drives {
        encrypt_drive(&drive, password, config).await?;
    }
    Ok(())
}

pub async fn decrypt_drives(drives: Vec<String>, password: &str, config: &CryptoConfig) -> io::Result<()> {
    for drive in drives {
        decrypt_drive(&drive, password, config).await?;
    }
    Ok(())
}