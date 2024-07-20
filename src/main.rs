#[macro_use]
extern crate lazy_static;
use std::sync::RwLock;

mod ssh_key;
mod utils;

use slint::SharedString;
slint::include_modules!();

use std::fs::File;
use std::io::{Read, Write};
use std::string::ToString;
use std::path::Path;

use hex::decode;

lazy_static! {
    static ref KEYS: RwLock<[String; 2]> = RwLock::new(["".to_string(), "".to_string()]);
}

fn find_keys_arr(disk_info: &utils::DiskInfo) -> [String; 2] {
    let private_key_path = disk_info.mount_point.join("private.key");
    let public_key_path = disk_info.mount_point.join("public.key");

    let private_key = utils::read_key(&private_key_path);
    let public_key = utils::read_key(&public_key_path);

    if private_key.is_none() {
        return ["".to_string(), "".to_string()];
    }

    let iv = [31, 86, 4, 87, 123, 136, 58, 187, 11, 182, 22, 25, 218, 1, 52, 141];
    let decrypted_private_key = disk_info.decrypt(&private_key.unwrap(), &iv);
    let private_key_str = String::from_utf8(decrypted_private_key).unwrap();

    println!("{:?}", private_key_str);

    let keys = [private_key_str, public_key.unwrap()];
    return keys;
}


fn find_keys_disk() -> [String; 2] {
    let disks: Vec<utils::DiskInfo> = utils::find_disks();
    let mut keys: [String; 2] = ["".to_string(), "".to_string()];
    for disk in disks {
        keys = find_keys_arr(&disk);
        if keys != ["".to_string(), "".to_string()] {
            break;
        }
    }
    return keys;
}

fn main() -> Result<(), slint::PlatformError> {
    println!("{:?}", utils::find_disks());

    let disk_info = utils::find_disks();

    let data = b"Hi bro, wts?";
    let iv = [0u8; 16]; // In a real-world scenario, IV should be random and unique per encryption

    let encrypted_data = disk_info[0].encrypt(data, &iv);
    println!("Encrypted data: {:?}", encrypted_data);

    let decrypted_data = disk_info[0].decrypt(&encrypted_data, &iv);
    println!("Decrypted data: {:?}", String::from_utf8(decrypted_data).unwrap());

    {
        let mut keys = KEYS.write().unwrap();
        *keys = find_keys_disk();
    }

    let ui = AppWindow::new()?;

    {
        let keys = KEYS.read().unwrap();
        if *keys != ["".to_string(), "".to_string()] {
            ui.set_decode_bottons_active(true);
            ui.set_public_key_disk("Private key was found".into());
        }
    }

    ui.on_code_text({
        let ui_handle = ui.as_weak();
        move |public_key: SharedString, string: SharedString, directory: SharedString, file_name| {
            let ui: AppWindow = ui_handle.unwrap();

            let encryptet_data = ssh_key::encrypt_with_public_key(&public_key.to_string(), &string);

            let directory_str: String = directory.to_string();
            let file_name_str: String = file_name.to_string();

            let path = Path::new(&directory_str).join(file_name_str).with_extension("pass");
            let mut file = match File::create(&path) {
                Err(why) => panic!("couldn't create {}: {}", path.display(), why),
                Ok(file) => file,
            };

            match file.write_all(encryptet_data.as_bytes()) {
                Err(why) => panic!("couldn't write to {}: {}", path.display(), why),
                Ok(_) => println!("successfully wrote to {}", path.display()),
            }

            ui.set_encrypted_hash(encryptet_data.into());
        }
    });

    ui.on_decode_file({
        let ui_handle = ui.as_weak();
        move |coded_file: SharedString| {
            let ui: AppWindow = ui_handle.unwrap();

            let private_key = {
                let keys = KEYS.read().unwrap();
                keys[0].clone()
            };

            let mut file = match File::open(&*coded_file) {
                Err(why) => panic!("couldn't create {}", why),
                Ok(file) => file,
            };

            let mut coded_text = String::new();
            let _ = file.read_to_string(&mut coded_text);

            println!("Coded text is: {}", coded_text);

            let decoded_text = ssh_key::decrypt_with_private_key(&private_key, &coded_text);

            if decoded_text == "" {
                ui.set_decoded_text("Something going wrong!".into());
            } else {
                ui.set_decoded_text(decoded_text.into());
            }
        }
    });

    ui.on_choose_folder({
        let ui_handle = ui.as_weak();
        move || {
            let ui: AppWindow = ui_handle.unwrap();
            let path = utils::choose_folder_func();
            ui.set_path(path.into());
        }
    });

    ui.on_get_public_key({
        let ui_handle = ui.as_weak();
        move || {
            let ui: AppWindow = ui_handle.unwrap();
            let public_key = {
                let keys = KEYS.read().unwrap();
                keys[1].clone()
            };
            ui.set_public_key(public_key.into());
        }
    });

    ui.on_generate_disk({
        let ui_handle = ui.as_weak();
        move || {
            let ui: AppWindow = ui_handle.unwrap();
            let path = utils::choose_folder_func();
            let disk_info = utils::get_disk_info_for_folder(&path);
            match disk_info {
                Ok(disk_info) => {
                    ssh_key::generate_key_pair(&disk_info);
                    {
                        let mut keys = KEYS.write().unwrap();
                        *keys = find_keys_disk();
                        if *keys != ["".to_string(), "".to_string()] {
                            ui.set_decode_bottons_active(true);
                            ui.set_public_key_disk("Private key was found".into());
                        }
                    }
                },
                Err(err) => {
                    println!("Error: {}", err);
                    ui.set_decode_bottons_active(false);
                    ui.set_public_key_disk(err.into());
                }
            }

        }
    });

    ui.on_find_disk({
        let ui_handle = ui.as_weak();
        move || {
            let ui: AppWindow = ui_handle.unwrap();
            {
                let mut keys = KEYS.write().unwrap();
                *keys = find_keys_disk();
                print!("{:?}", keys);
                if *keys != ["".to_string(), "".to_string()] {
                    ui.set_decode_bottons_active(true);
                    ui.set_public_key_disk("Private key was found".into());
                }
            }
        }
    });

    ui.on_choose_private_key({
        let ui_handle = ui.as_weak();
        move || {
            let ui: AppWindow = ui_handle.unwrap();
            let path = utils::choose_file_func();
            ui.set_private_key_path(path.into());
        }
    });

    ui.on_choose_coded_file({
        let ui_handle = ui.as_weak();
        move || {
            let ui: AppWindow = ui_handle.unwrap();
            let path = utils::choose_file_func();
            ui.set_coded_file(path.into());
        }
    });

    ui.run()
}
