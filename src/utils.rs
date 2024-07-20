use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use sha2::{Sha512, Digest};
use hex::{encode, decode};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;


#[derive(Debug)]
pub struct DiskInfo {
    pub name: String,
    pub file_system: Vec<u8>,
    pub mount_point: PathBuf,
    pub total_space: u64,
    pub available_space: u64,
}

impl DiskInfo {
    pub fn get_aes_key(&self) -> [u8; 32] {
        let total_space_str = self.total_space.to_string();
        let mut hasher = Sha512::new();
        hasher.update(total_space_str.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        key
    }

    pub fn encrypt(&self, data: &[u8], iv: &[u8; 16]) -> String {
        let key = self.get_aes_key();
        let cipher = Aes256Cbc::new_from_slices(&key, iv).unwrap();
        let encrypted_data = cipher.encrypt_vec(data);
        encode(&encrypted_data)  // Convert encrypted data to hex string
    }

    pub fn decrypt(&self, encrypted_data_hex: &str, iv: &[u8; 16]) -> Vec<u8> {
        let key = self.get_aes_key();
        let cipher = Aes256Cbc::new_from_slices(&key, iv).unwrap();
        let encrypted_data = decode(encrypted_data_hex).unwrap();
        cipher.decrypt_vec(&encrypted_data).unwrap()
    }
}


use sysinfo::{DiskExt, System, SystemExt};


pub fn choose_folder_func() -> String {
    // use std::path::PathBuf;
    use rfd::FileDialog;

    let path = FileDialog::new().pick_folder();
    match path {
        Some(path_buf) => path_buf.display().to_string(),
        None => "Pls enter folder to save .pass file".to_string(),
    }
}

pub fn choose_file_func() -> String {
    // use std::path::PathBuf;
    use rfd::FileDialog;

    let path = FileDialog::new().pick_file();
    match path {
        Some(path_buf) => path_buf.display().to_string(),
        None => "Pls enter folder to save .pass file".to_string(),
    }
}

pub fn read_key<P: AsRef<Path>>(path: P) -> Option<String> {
    let mut file = match File::open(&path) {
        Err(why) => {
            println!("couldn't open {}: {}", path.as_ref().display(), why);
            return None;
        }
        Ok(file) => file,
    };

    let mut key = String::new();
    if let Err(why) = file.read_to_string(&mut key) {
        println!("couldn't read {}: {}", path.as_ref().display(), why);
        return None;
    }

    if key.trim().is_empty() {
        None
    } else {
        Some(key)
    }
}

pub fn find_disks() -> Vec<DiskInfo> {
    // Создаем новый объект System для получения информации о системе
    let mut sys = System::new_all();
    
    // Обновляем информацию о дисках
    sys.refresh_disks_list();
    
    // Получаем список дисков
    let disks = sys.disks();
    
    // Вектор для хранения информации о съемных дисках
    let mut removable_disks = Vec::new();
    
    // Проходим по каждому диску и собираем информацию о нем
    for disk in disks {
        if disk.is_removable() {
            let disk_info = DiskInfo {
                name: disk.name().to_string_lossy().to_string(),
                file_system: disk.file_system().to_vec(),
                mount_point: disk.mount_point().to_path_buf(),
                total_space: disk.total_space(),
                available_space: disk.available_space(),
            };
            removable_disks.push(disk_info);
        }
    }
    
    removable_disks
}

pub fn get_disk_info_for_folder(folder_path: &str) -> Result<DiskInfo, String> {
    let removable_disks = find_disks();
    let folder_path_buf = PathBuf::from(folder_path);

    for disk_info in removable_disks {
        if folder_path_buf.starts_with(&disk_info.mount_point) {
            return Ok(disk_info);
        }
    }

    Err("The selected folder is not on a removable disk.".to_string())
}