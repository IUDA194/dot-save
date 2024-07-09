extern crate base64;
extern crate openssl;
extern crate pem;

use base64::{encode as base64_encode, decode as base64_decode};
use openssl::rsa::{Rsa, Padding};
use pem::{Pem, parse};

pub fn generate_key_pair() {
    // Generate a new 4096-bit key.
    let rsa = Rsa::generate(4096).unwrap();

    let public_key = rsa.public_key_to_der().unwrap();
    let private_key = rsa.private_key_to_der().unwrap();

    // Encode the private key to PEM format
    let private_pem = Pem::new("RSA PRIVATE KEY", private_key.clone());
    let private_pem_str = pem::encode(&private_pem);

    // Encode the public key to PEM format
    let public_pem = Pem::new("PUBLIC KEY", public_key.clone());
    let public_pem_str = pem::encode(&public_pem);

    println!("Private Key:\n{}", private_pem_str);
    println!("Public Key:\n{}", public_pem_str);

    //let data = b"Hi bro!";
    //let encrypted_data = encrypt_with_public_key(&public_key, data);
    //println!("Encrypted data: {:?}", encrypted_data);

    //let decrypted_data = decrypt_with_private_key(&PRIVATE_KEY, &encrypted_data);
    //println!("Decrypted data: {:?}", String::from_utf8(decrypted_data).unwrap());
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
    base64_encode(&buffer)
}

pub fn decrypt_with_private_key(private_key_pem: &str, encrypted_data: &str) -> String {
    // Parse the PEM-encoded private key string to PEM struct
    let private_pem = parse(private_key_pem).expect("Failed to parse PEM");

    // Convert PEM contents to DER format (byte array)
    let private_key_der = private_pem.contents();

    let rsa = Rsa::private_key_from_der(&private_key_der).unwrap();

    // Decode the Base64-encoded encrypted data to byte array
    let encrypted_data_bytes = base64_decode(encrypted_data).expect("Failed to decode Base64");

    let mut buffer: Vec<u8> = vec![0; rsa.size() as usize];
    let len = rsa.private_decrypt(&encrypted_data_bytes, &mut buffer, Padding::PKCS1).unwrap();
    buffer.resize(len, 0);

    // Convert decrypted byte array to String
    String::from_utf8(buffer).expect("Failed to convert decrypted data to String")
}