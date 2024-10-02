use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use walkdir::WalkDir;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage:");
        eprintln!("  Encrypt: {} encrypt <directory_path>", args[0]);
        eprintln!(
            "  Decrypt: {} decrypt <directory_path> <key_hex> <nonce_hex>",
            args[0]
        );
        std::process::exit(1);
    }

    let mode = &args[1];
    let dir_path = &args[2];

    match mode.as_str() {
        "encrypt" => {
            let key: [u8; 32] = rand::thread_rng().gen();
            let nonce: [u8; 12] = rand::thread_rng().gen();
            println!("Encryption key (hex): {}", hex::encode(&key));
            println!("Nonce (hex): {}", hex::encode(&nonce));
            encrypt_directory(dir_path, &key, &nonce);
        }
        "decrypt" => {
            if args.len() != 5 {
                eprintln!("Decryption requires key and nonce");
                std::process::exit(1);
            }
            let key = hex::decode(&args[3]).expect("Invalid key hex");
            let nonce = hex::decode(&args[4]).expect("Invalid nonce hex");
            decrypt_directory(dir_path, &key, &nonce);
        }
        _ => {
            eprintln!("Invalid mode. Use 'encrypt' or 'decrypt'");
            std::process::exit(1);
        }
    }
}

fn encrypt_directory(dir_path: &str, key: &[u8], nonce: &[u8]) {
    for entry in WalkDir::new(dir_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && !path.to_str().unwrap_or("").ends_with(".ccat") {
            encrypt_file(path, key, nonce);
        }
    }
}

fn decrypt_directory(dir_path: &str, key: &[u8], nonce: &[u8]) {
    for entry in WalkDir::new(dir_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && path.to_str().unwrap_or("").ends_with(".ccat") {
            decrypt_file(path, key, nonce);
        }
    }
}

fn encrypt_file(file_path: &Path, key: &[u8], nonce: &[u8]) {
    let mut file = File::open(file_path).expect("Failed to open file");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .expect("Failed to read file");

    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(nonce);
    let ciphertext = cipher
        .encrypt(nonce, contents.as_ref())
        .expect("encryption failure!");

    let mut encrypted_path = file_path.to_path_buf();
    encrypted_path.set_extension(format!(
        "{}.ccat",
        encrypted_path
            .extension()
            .unwrap_or_default()
            .to_str()
            .unwrap_or("")
    ));

    let mut encrypted_file =
        File::create(&encrypted_path).expect("Failed to create encrypted file");
    encrypted_file
        .write_all(&ciphertext)
        .expect("Failed to write encrypted file");

    fs::remove_file(file_path).expect("Failed to remove original file");

    println!(
        "Encrypted: {} -> {}",
        file_path.display(),
        encrypted_path.display()
    );
}

fn decrypt_file(file_path: &Path, key: &[u8], nonce: &[u8]) {
    let mut file = File::open(file_path).expect("Failed to open file");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .expect("Failed to read file");

    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, contents.as_ref())
        .expect("decryption failure!");

    let decrypted_path = file_path.with_extension("");
    let mut decrypted_file =
        File::create(&decrypted_path).expect("Failed to create decrypted file");
    decrypted_file
        .write_all(&plaintext)
        .expect("Failed to write decrypted file");

    fs::remove_file(file_path).expect("Failed to remove encrypted file");

    println!(
        "Decrypted: {} -> {}",
        file_path.display(),
        decrypted_path.display()
    );
}
