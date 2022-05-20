mod encryption;
mod file_types;

use anyhow::{anyhow, Context, Result};
use aws_sdk_s3::types::ByteStream;
use aws_sdk_s3::{Client, Config, Credentials, Endpoint, Region};
use chacha20poly1305::{
    XChaCha20Poly1305,
};
use rand::prelude::*;
use ring::digest::{Context as DigestContext, SHA256};
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::path::Path;
use std::{env, fs};
use url::Url;
use uuid::Uuid;
use file_types::{Gosling, MotherGoose};
use crate::file_types::{HashType, LocalFile};

pub async fn file_gooser(file_path: &str, gosling_size: usize, password: &str) -> Result<()> {
    let file = File::open(file_path)?;

    let mut goslings = Vec::new();
    let mut reader = BufReader::with_capacity(gosling_size, file);

    let s3_client = build_client().await;
    let mut salt = [0u8; 32];
    thread_rng().fill_bytes(&mut salt);
    let encryption = encryption::create_encryption(password, &salt)?;

    let working_dir = format!("{}.d", file_path);
    fs::create_dir_all(&working_dir)?;

    let mut hash_context = DigestContext::new(&SHA256);
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
        checksum: file_types::finalize_hash(hash_context.finish(), HashType::SHA256),
    };
    let serialized_goose = serde_json::to_vec(&mother_goose)?;
    let goose_file = encryption::write_encrypted_file_from_buffer(
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
    destination_path: &str,
    password: &str,
) -> Result<()> {
    let response = reqwest::get(goose_url.clone()).await?;
    let goose_file_name = goose_url.path_segments().context("Grabbing segments")?.last().context("Grabbing last segment")?;
    let goose_path = format!("/tmp/{}", goose_file_name);
    println!("Goose path: {}", &goose_path);

    let mut create_file = File::create(Path::new(&goose_path))?;
    let mut content = Cursor::new(response.bytes().await?);
    std::io::copy(&mut content, &mut create_file)?;

    // decrypt the downloaded goose file
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];


    let mut read_file = File::open(Path::new(&goose_path))?;
    println!("Read {}", &goose_path);

    let mut read_count = read_file.read(&mut salt)?;
    if read_count != salt.len() {
        return Err(anyhow!("Error reading salt."));
    }

    read_count = read_file.read(&mut nonce)?;
    if read_count != nonce.len() {
        return Err(anyhow!("Error reading nonce."));
    }

    let encryption = encryption::create_encryption(password, &salt)?;
    encryption::write_decrypted_file_from_encrypted_file(
        &mut read_file,
        destination_path,
        goose_file_name,
        &encryption,
        &nonce,
    )?;
    Ok(())
}

fn create_gosling_file(
    buffer: &[u8],
    write_dir: &str,
    encryption: &XChaCha20Poly1305,
    encryption_salt: &[u8; 32],
) -> Result<LocalFile> {
    let gosling_name = format!("{}.gosling", Uuid::new_v4());
    encryption::write_encrypted_file_from_buffer(
        buffer,
        write_dir,
        &gosling_name,
        encryption,
        encryption_salt,
    )
}

fn write_file_from_buffer(buffer: &[u8], write_dir: &str, file_name: &str) -> Result<LocalFile> {
    let path = format!("{}/{}", write_dir, file_name);
    fs::write(&path, buffer)?;
    Ok(LocalFile {
        file_name: String::from(file_name),
        file_dir: String::from(write_dir),
        content_length: buffer.len(),
        checksum: file_types::sha256_digest(buffer),
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
