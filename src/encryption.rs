use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{stream, NewAead},
    XChaCha20Poly1305,
};
use rand::prelude::*;
use ring::digest::{Context as DigestContext, SHA256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroize;
use crate::file_types;
use crate::file_types::{HashType, LocalFile};

pub fn create_encryption(password: &str, salt: &[u8; 32]) -> Result<XChaCha20Poly1305> {
    let argon2_config = argon2_config();

    let mut key = argon2::hash_raw(password.as_bytes(), salt, &argon2_config)?;
    let encryption = XChaCha20Poly1305::new(key[..32].as_ref().into());
    key.zeroize();
    Ok(encryption)
}

pub fn write_encrypted_file_from_buffer(
    buffer: &[u8],
    write_dir: &str,
    file_name: &str,
    encryption: &XChaCha20Poly1305,
    encryption_salt: &[u8; 32],
) -> Result<LocalFile> {
    // TODO:? reference article uses 19 bytes but algorithm generally takes in 24:
    //   https://kerkour.com/rust-file-encryption-chacha20poly1305-argon2 vs
    //   https://docs.rs/chacha20poly1305/0.3.0/chacha20poly1305/struct.XChaCha20Poly1305.html
    let mut nonce = [0u8; 19];
    thread_rng().fill_bytes(&mut nonce);

    // TODO:? I'd really like to farm this out to another function, but getting the return type
    //   right requires a hard dependency on some additional crates. Is it worth it?
    let stream_encryptor =
        stream::EncryptorBE32::from_aead(encryption.clone(), nonce.as_ref().into());

    // BEGIN: file operations

    let file_path = format!("{}/{}", write_dir, file_name);
    let mut file_out = File::create(&file_path)?;

    // Generate and write ciphertext
    let ciphertext = stream_encryptor
        .encrypt_last(buffer)
        .map_err(|err| anyhow!("Failure encrypting bytes: {}", err))?;
    file_out.write_all(encryption_salt)?;
    file_out.write_all(&nonce)?;
    file_out.write_all(&ciphertext)?;

    // While we have the values in memory, calculate checksum
    let mut context = DigestContext::new(&SHA256);
    context.update(encryption_salt);
    context.update(&nonce);
    context.update(&ciphertext);

    Ok(LocalFile {
        file_name: String::from(file_name),
        file_dir: String::from(write_dir),
        content_length: ciphertext.len(),
        checksum: file_types::finalize_hash(context.finish(), HashType::SHA256),
    })
}

pub fn write_decrypted_file_from_encrypted_file(
    encrypted_file: &mut File,
    write_dir: &str,
    file_name: &str,
    encryption: &XChaCha20Poly1305,
    encryption_nonce: &[u8; 19],
) -> Result<()> {
    let mut stream_decryptor =
        stream::DecryptorBE32::from_aead(encryption.clone(), encryption_nonce.as_ref().into());

    let out_file_path = format!("{}/{}", write_dir, file_name);
    let mut out_file = File::create(Path::new(&out_file_path))?;
    println!("after file create");

    // TODO: buffer should be global or cacheable. Note that the size should be whatever the
    //   encrypted buffer was, plus 16. See:
    //   https://kerkour.com/rust-file-encryption-chacha20poly1305-argon2#/%2F=
    //   ... or just assume that the buffers can always fit in memory?
    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        println!("about to read");
        let read_count = encrypted_file.read(&mut buffer)?;
        println!("successful read");
        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            out_file.write_all(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            out_file.write_all(&plaintext)?;
            break;
        }
    }
    Ok(())
}

fn argon2_config<'a>() -> argon2::Config<'a> {
    argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    }
}
