extern crate base64;
extern crate openssl;
extern crate pem;

use crate::utils::DiskInfo;

use base64::{engine::general_purpose, Engine as _}; // Importing Engine trait
use openssl::rsa::{Rsa, Padding};
use pem::{Pem, parse, encode};


use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn generate_key_pair_old(directory_str: &str) {
    // Generate a new 4096-bit key.
    let rsa = Rsa::generate(4096).unwrap();

    let public_key = rsa.public_key_to_der().unwrap();
    let private_key = rsa.private_key_to_der().unwrap();

    // Encode the private key to PEM format
    let private_pem = Pem::new("RSA PRIVATE KEY", private_key.clone());
    let private_pem_str = encode(&private_pem);

    // Encode the public key to PEM format
    let public_pem = Pem::new("PUBLIC KEY", public_key.clone());
    let public_pem_str = encode(&public_pem);

    let private_name_str = "private.key";
    let public_str = "public.key";

    // Creating a Private Key File
    let private_path = Path::new(&directory_str).join(private_name_str);
    let mut private_file = match File::create(&private_path) {
        Err(why) => panic!("couldn't create {}: {}", private_path.display(), why),
        Ok(file) => file,
    };

    match private_file.write_all(private_pem_str.as_bytes()) {
        Err(why) => panic!("couldn't write to {}: {}", private_path.display(), why),
        Ok(_) => println!("successfully wrote to {}", private_path.display()),
    }

    // Creating a Public Key File
    let public_path = Path::new(&directory_str).join(public_str);
    let mut public_file = match File::create(&public_path) {
        Err(why) => panic!("couldn't create {}: {}", public_path.display(), why),
        Ok(file) => file,
    };

    match public_file.write_all(public_pem_str.as_bytes()) {
        Err(why) => panic!("couldn't write to {}: {}", public_path.display(), why),
        Ok(_) => println!("successfully wrote to {}", public_path.display()),
    }

    println!("Private Key:\n{}", private_pem_str);
    println!("Public Key:\n{}", public_pem_str);
}

pub fn generate_key_pair(disk_info: &DiskInfo) {
    // Generate a new 4096-bit key.
    let rsa = Rsa::generate(4096).unwrap();

    let public_key = rsa.public_key_to_der().unwrap();
    let private_key = rsa.private_key_to_der().unwrap();

    // Encode the private key to PEM format
    let private_pem = Pem::new("RSA PRIVATE KEY", private_key.clone());
    let private_pem_str = encode(&private_pem);

    // Encode the public key to PEM format
    let public_pem = Pem::new("PUBLIC KEY", public_key.clone());
    let public_pem_str = encode(&public_pem);

    let private_name_str = "private.key";
    let public_str = "public.key";

    // Encrypt the private key PEM string
    let iv = [31, 86, 4, 87, 123, 136, 58, 187, 11, 182, 22, 25, 218, 1, 52, 141];
    let encrypted_private_pem = disk_info.encrypt(private_pem_str.as_bytes(), &iv);

    // Creating a Private Key File
    let private_path = Path::new(&disk_info.mount_point).join(private_name_str);
    let mut private_file = match File::create(&private_path) {
        Err(why) => panic!("couldn't create {}: {}", private_path.display(), why),
        Ok(file) => file,
    };

    match private_file.write_all(&encrypted_private_pem.as_bytes()) {
        Err(why) => panic!("couldn't write to {}: {}", private_path.display(), why),
        Ok(_) => println!("successfully wrote to {}", private_path.display()),
    }

    // Creating a Public Key File
    let public_path = Path::new(&disk_info.mount_point).join(public_str);
    let mut public_file = match File::create(&public_path) {
        Err(why) => panic!("couldn't create {}: {}", public_path.display(), why),
        Ok(file) => file,
    };

    match public_file.write_all(public_pem_str.as_bytes()) {
        Err(why) => panic!("couldn't write to {}: {}", public_path.display(), why),
        Ok(_) => println!("successfully wrote to {}", public_path.display()),
    }

    println!("Private Key (encrypted): {:?}", private_pem_str);
    println!("Public Key:\n{}", public_pem_str);
}

pub fn encrypt_with_public_key(public_key_pem: &str, data: &str) -> String {
    // Parse the PEM-encoded public key string to PEM struct
    let public_pem = parse(public_key_pem).expect("Failed to parse PEM");

    // Convert PEM contents to DER format (byte array)
    let public_key_der = public_pem.contents();

    let rsa = Rsa::public_key_from_der(&public_key_der).unwrap();
    let mut buffer: Vec<u8> = vec![0; rsa.size() as usize];
    let _ = rsa.public_encrypt(data.as_bytes(), &mut buffer, Padding::PKCS1).unwrap();

    // Encode encrypted data to Base64 string
    general_purpose::STANDARD.encode(&buffer)
}

pub fn decrypt_with_private_key(private_key_pem: &str, encrypted_data: &str) -> String {
    // Attempt to parse the PEM-encoded private key string
    let private_pem = match parse(private_key_pem) {
        Ok(pem) => pem,
        Err(_) => return String::new(), // Return empty string if parsing fails
    };

    // Convert PEM contents to DER format (byte array)
    let private_key_der = private_pem.contents();

    let rsa = match Rsa::private_key_from_der(&private_key_der) {
        Ok(key) => key,
        Err(_) => return String::new(), // Return empty string if conversion fails
    };

    // Decode the Base64-encoded encrypted data to byte array
    let encrypted_data_bytes = match general_purpose::STANDARD.decode(encrypted_data) {
        Ok(bytes) => bytes,
        Err(_) => return String::new(), // Return empty string if decoding fails
    };

    let mut buffer: Vec<u8> = vec![0; rsa.size() as usize];
    let len = match rsa.private_decrypt(&encrypted_data_bytes, &mut buffer, Padding::PKCS1) {
        Ok(len) => len,
        Err(_) => return String::new(), // Return empty string if decryption fails
    };
    buffer.resize(len, 0);

    // Convert decrypted byte array to String
    match String::from_utf8(buffer) {
        Ok(s) => s,
        Err(_) => String::new(), // Return empty string if conversion fails
    }
}
