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
    pub file_path: String,
    pub hash: Hash,
    pub goslings: Vec<Gosling>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Gosling {
    pub id: String,
    pub content_length: usize,
    pub file_path: String,
}

impl Gosling {
    pub fn new(id: String, content_length: usize, file_path: String) -> Gosling {
        Gosling {
            id,
            content_length,
            file_path,
        }
    }
}

pub async fn file_gooser(file_path: &str, gosling_size: usize) -> Result<()> {
    let file = File::open(file_path)?;

    let mut goslings = Vec::new();
    let mut reader = BufReader::with_capacity(gosling_size, file);

    let s3_client = build_client().await;

    let gosling_dir = format!("{}.d", file_path);
    fs::create_dir_all(&gosling_dir)?;

    loop {
        let buffer = reader.fill_buf().expect("Error reading file!");
        let length = buffer.len();
        if length == 0 {
            break;
        }

        let gosling = spawn_gosling_for_buffer(buffer, &gosling_dir);
        upload_gosling(&s3_client, &gosling).await?;
        goslings.push(gosling);

        reader.consume(length);
        // TODO: Better progress indicator
        print!(".");
        let _ = std::io::stdout().flush();
    }
    println!("Finished spawning goslings.");

    // TODO: This is weird. We're serializing an object and writing out a file that describes
    //  itself. Really, there should be a LocalFile object or something that gets uploaded and then
    //  a cloud-aware Goose/Gosling object that can resolve to a LocalFile if there's one present.
    let mother_goose_id = format!("{}.goose", Uuid::new_v4());
    let mother_goose_path = format!("{}/{}.goose", &gosling_dir, Uuid::new_v4());
    let file_hash = Hash {
        hash_value: sha256_digest_for_file(file_path).expect("Failed to compute hash"),
        hash_type: HashType::SHA256,
    };
    let mother_goose = MotherGoose {
        id: mother_goose_id,
        file_path: mother_goose_path,
        hash: file_hash,
        goslings,
    };
    let serialized_mother_goose = serde_json::to_string(&mother_goose)?;
    fs::write(&mother_goose.file_path, &serialized_mother_goose).expect("Unable to write file");
    upload_mother_goose(&s3_client, &mother_goose).await?;
    println!("Mother goose says wak: {:#?}", &serialized_mother_goose);
    Ok(())
}

fn spawn_gosling_for_buffer(buffer: &[u8], write_dir: &str) -> Gosling {
    let gosling_name = format!("{}.gosling", Uuid::new_v4());
    let gosling_path = format!("{}/{}", write_dir, gosling_name);
    fs::write(&gosling_path, buffer).expect("Unable to write file");
    Gosling::new(gosling_name, buffer.len(), gosling_path)
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

async fn upload_mother_goose(client: &Client, mother_goose: &MotherGoose) -> Result<()> {
    upload_file(client, &mother_goose.file_path, &mother_goose.id, None).await
}

async fn upload_gosling(client: &Client, gosling: &Gosling) -> Result<()> {
    upload_file(
        client,
        &gosling.file_path,
        &gosling.id,
        Some(gosling.content_length as i64),
    )
    .await
}

async fn upload_file(
    client: &Client,
    source_file_path: &str,
    destination_key: &str,
    content_length: Option<i64>,
) -> Result<()> {
    let bucket_name =
        env::var("GOOSE_B2_UPLOAD_BUCKET").expect("Need GOOSE_B2_UPLOAD_BUCKET set for now.");
    let body = ByteStream::from_path(Path::new(&source_file_path)).await;
    let mut builder = client
        .put_object()
        .bucket(bucket_name)
        .key(destination_key)
        .body(body.unwrap());
    // Content length is optional for now
    // TODO: should it always be provided?
    if content_length.is_some() {
        builder = builder.content_length(content_length.unwrap());
    }
    builder.send().await?;
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
