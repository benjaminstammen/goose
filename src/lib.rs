use anyhow::Result;
use aws_sdk_s3::types::ByteStream;
use aws_sdk_s3::{Client, Config, Credentials, Endpoint, Region};
use data_encoding::HEXLOWER;
use ring::digest::{Context, Digest, SHA256};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Result as IOResult, Write};
use std::path::Path;
use std::{env, fs};
use uuid::Uuid;

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
}

#[derive(Debug, Serialize, Deserialize)]
struct Gosling {
    pub id: String,
}

struct LocalFile {
    pub file_name: String,
    pub file_dir: String,
    pub content_length: usize,
    pub checksum: Option<Hash>,
}

pub async fn file_gooser(file_path: &str, gosling_size: usize) -> Result<()> {
    let file = File::open(file_path)?;

    let mut goslings = Vec::new();
    let mut reader = BufReader::with_capacity(gosling_size, file);

    let s3_client = build_client().await;

    let working_dir = format!("{}.d", file_path);
    fs::create_dir_all(&working_dir)?;

    loop {
        let buffer = reader.fill_buf().expect("Error reading file!");
        let length = buffer.len();
        if length == 0 {
            break;
        }

        let gosling_file = create_gosling_file(buffer, &working_dir)?;
        upload_file(&s3_client, &gosling_file).await?;
        goslings.push(Gosling {
            id: gosling_file.file_name.clone(),
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
    };
    let serialized_goose = serde_json::to_vec(&mother_goose)?;
    let goose_file =
        write_file_from_buffer(serialized_goose.as_slice(), &working_dir, &mother_goose.id)?;
    upload_file(&s3_client, &goose_file).await?;
    println!("Mother goose says wak: {:#?}", &mother_goose);
    Ok(())
}

fn create_gosling_file(buffer: &[u8], write_dir: &str) -> Result<LocalFile> {
    let gosling_name = format!("{}.gosling", Uuid::new_v4());
    write_file_from_buffer(buffer, write_dir, &gosling_name)
}

// TODO: (optionally?) stream bytes through checksum algorithm so that it's always present on the
//   resulting object.
fn write_file_from_buffer(buffer: &[u8], write_dir: &str, file_name: &str) -> Result<LocalFile> {
    let path = format!("{}/{}", write_dir, file_name);
    fs::write(&path, buffer)?;
    let digest = sha256_digest_for_file(&path)?;
    Ok(LocalFile {
        file_name: String::from(file_name),
        file_dir: String::from(write_dir),
        content_length: buffer.len(),
        checksum: Some(Hash {
            hash_value: digest,
            hash_type: HashType::SHA256,
        }),
    })
}

fn sha256_digest_for_file(file_path: &str) -> IOResult<String> {
    let input = File::open(file_path)?;
    let reader = BufReader::new(input);
    let digest = sha256_digest(reader)?;
    Ok(HEXLOWER.encode(digest.as_ref()))
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

// Lifted from the Rust Cookbook here: https://rust-lang-nursery.github.io/rust-cookbook/cryptography/hashing.html
// TODO: find a way to compute the hash rapidly while creating goslings. Not doing so now because it's been
//     prohibitively slow.
fn sha256_digest<R: Read>(mut reader: R) -> IOResult<Digest> {
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish())
}
