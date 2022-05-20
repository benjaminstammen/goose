use anyhow::{anyhow, Result};
use aws_sdk_s3::types::ByteStream;
use aws_sdk_s3::{Client, Config, Credentials, Endpoint, Region};
use chacha20poly1305::{
    aead::{stream, NewAead},
    XChaCha20Poly1305,
};
use data_encoding::HEXLOWER;
use rand::prelude::*;
use ring::digest::{Context, Digest, SHA256};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Write};
use std::path::Path;
use std::{env, fs};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize)]
enum HashType {
    SHA256,
}

#[derive(Debug, Serialize, Deserialize)]
struct Hash {
    pub hash_value: String,
    pub hash_type: HashType,
}

#[derive(Debug, Serialize, Deserialize)]
struct MotherGoose {
    pub id: String,
    pub goslings: Vec<Gosling>,
    pub checksum: Hash,
}

#[derive(Debug, Serialize, Deserialize)]
struct Gosling {
    pub id: String,
    pub checksum: Hash,
}

struct LocalFile {
    pub file_name: String,
    pub file_dir: String,
    pub content_length: usize,
    pub checksum: Hash,
}

pub async fn file_gooser(file_path: &str, gosling_size: usize, password: &str) -> Result<()> {
    let file = File::open(file_path)?;

    let mut goslings = Vec::new();
    let mut reader = BufReader::with_capacity(gosling_size, file);

    let s3_client = build_client().await;
    let mut salt = [0u8; 32];
    thread_rng().fill_bytes(&mut salt);
    let encryption = create_encryption(password, &salt)?;

    let working_dir = format!("{}.d", file_path);
    fs::create_dir_all(&working_dir)?;

    let mut hash_context = Context::new(&SHA256);
    loop {
        let buffer = reader.fill_buf().expect("Error reading file!");
        let length = buffer.len();
        if length == 0 {
            break;
        }

        hash_context.update(buffer);
        let gosling_file = create_gosling_file(buffer, &working_dir, &encryption, &salt)?;
        upload_file(&s3_client, &gosling_file).await?;
        goslings.push(Gosling {
            id: gosling_file.file_name.clone(),
            checksum: gosling_file.checksum,
        });

        reader.consume(length);
        // TODO: Better progress indicator
        print!(".");
        let _ = std::io::stdout().flush();
    }
    println!("Finished spawning goslings.");

    let mother_goose = MotherGoose {
        id: format!("{}.goose", Uuid::new_v4()),
        goslings,
        checksum: finalize_hash(hash_context.finish(), HashType::SHA256),
    };
    let serialized_goose = serde_json::to_vec(&mother_goose)?;
    let goose_file = write_encrypted_file_from_buffer(
        serialized_goose.as_slice(),
        &working_dir,
        &mother_goose.id,
        &encryption,
        &salt,
    )?;
    upload_file(&s3_client, &goose_file).await?;
    println!("Mother goose says wak: {:#?}", &mother_goose);
    Ok(())
}

pub async fn file_ungooser(
    goose_url: &Url,
    _destination_path: &str,
    _password: &str,
) -> Result<()> {
    let response = reqwest::get(goose_url.clone()).await?;
    let goose_path = format!(
        "/tmp/{}",
        goose_url.path_segments().unwrap().last().unwrap()
    );
    let mut file = File::create(Path::new(&goose_path))?;
    let mut content = Cursor::new(response.bytes().await?);
    std::io::copy(&mut content, &mut file)?;
    Ok(())
}

fn create_encryption(password: &str, salt: &[u8; 32]) -> Result<XChaCha20Poly1305> {
    let argon2_config = argon2_config();

    let mut key = argon2::hash_raw(password.as_bytes(), salt, &argon2_config)?;
    let encryption = XChaCha20Poly1305::new(key[..32].as_ref().into());
    key.zeroize();
    Ok(encryption)
}

fn create_gosling_file(
    buffer: &[u8],
    write_dir: &str,
    encryption: &XChaCha20Poly1305,
    encryption_salt: &[u8; 32],
) -> Result<LocalFile> {
    let gosling_name = format!("{}.gosling", Uuid::new_v4());
    write_encrypted_file_from_buffer(
        buffer,
        write_dir,
        &gosling_name,
        encryption,
        encryption_salt,
    )
}

fn write_encrypted_file_from_buffer(
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
    let mut context = Context::new(&SHA256);
    context.update(encryption_salt);
    context.update(&nonce);
    context.update(&ciphertext);

    Ok(LocalFile {
        file_name: String::from(file_name),
        file_dir: String::from(write_dir),
        content_length: ciphertext.len(),
        checksum: finalize_hash(context.finish(), HashType::SHA256),
    })
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

fn write_file_from_buffer(buffer: &[u8], write_dir: &str, file_name: &str) -> Result<LocalFile> {
    let path = format!("{}/{}", write_dir, file_name);
    fs::write(&path, buffer)?;
    Ok(LocalFile {
        file_name: String::from(file_name),
        file_dir: String::from(write_dir),
        content_length: buffer.len(),
        checksum: sha256_digest(buffer),
    })
}

async fn build_client() -> Client {
    let access_key =
        env::var("GOOSE_B2_ACCESS_KEY").expect("Need GOOSE_B2_ACCESS_KEY set for now.");
    let secret_key =
        env::var("GOOSE_B2_SECRET_KEY").expect("Need GOOSE_B2_SECRET_KEY set for now.");

    // per https://nickb.dev/blog/access-public-and-private-b2-s3-buckets-in-rust, doesn't seem like provider matters.
    let provider_name = "local-credentials";
    let credentials = Credentials::new(&access_key, &secret_key, None, None, provider_name);

    let b2_s3 = "https://s3.us-west-002.backblazeb2.com";
    let b2_endpoint = Endpoint::immutable(b2_s3.parse().unwrap());

    let config = Config::builder()
        .region(Region::new("us-west-002"))
        .endpoint_resolver(b2_endpoint)
        .credentials_provider(credentials)
        .build();

    Client::from_conf(config)
}

async fn upload_file(client: &Client, local_file: &LocalFile) -> Result<()> {
    let bucket_name =
        env::var("GOOSE_B2_UPLOAD_BUCKET").expect("Need GOOSE_B2_UPLOAD_BUCKET set for now.");

    let full_path = format!("{}/{}", local_file.file_dir, local_file.file_name);
    let body = ByteStream::from_path(Path::new(&full_path)).await;
    client
        .put_object()
        .bucket(bucket_name)
        .key(&local_file.file_name)
        .content_length(local_file.content_length as i64)
        .body(body.unwrap())
        .send()
        .await?;
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> Hash {
    let mut context = Context::new(&SHA256);
    context.update(bytes);
    finalize_hash(context.finish(), HashType::SHA256)
}

fn finalize_hash(digest: Digest, hash_type: HashType) -> Hash {
    Hash {
        hash_value: HEXLOWER.encode(digest.as_ref()),
        hash_type,
    }
}
