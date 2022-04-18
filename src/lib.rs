use anyhow::Result;
use aws_sdk_s3::types::ByteStream;
use aws_sdk_s3::{Client, Config, Credentials, Endpoint, Region};
use data_encoding::HEXLOWER;
use ring::digest::{Context, Digest, SHA256};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Result as IOResult, Write};
use std::path::Path;
use std::{env, fs};
use uuid::Uuid;

#[derive(Debug)]
enum HashType {
    SHA256,
}

#[derive(Debug)]
struct Hash {
    pub hash_value: String,
    pub hash_type: HashType,
}

#[derive(Debug)]
struct MotherGoose {
    pub hash: Hash,
    pub goslings: Vec<Gosling>,
}

#[derive(Debug)]
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

    // let s3_client = build_client().await;

    loop {
        let length = {
            let buffer = reader.fill_buf().expect("Error reading file!");
            let gosling = spawn_gosling_for_buffer(buffer, file_path);
            // upload_file(&s3_client, &gosling).await?;
            goslings.push(gosling);
            buffer.len()
        };
        if length == 0 {
            break;
        }
        reader.consume(length);
        // TODO: Better progress indicator
        print!(".");
        let _ = std::io::stdout().flush();
    }
    println!("Finished spawning goslings.");

    let file_hash = Hash {
        hash_value: sha256_digest_for_file(file_path).expect("Failed to compute hash"),
        hash_type: HashType::SHA256,
    };
    let mother_goose = MotherGoose {
        hash: file_hash,
        goslings,
    };
    println!("Mother goose says wak: {:#?}", mother_goose);
    Ok(())
}

fn spawn_gosling_for_buffer(buffer: &[u8], write_path: &str) -> Gosling {
    let gosling_name = format!("{}.gos", Uuid::new_v4());
    let gosling_path = format!("{}.d/{}", write_path, gosling_name);
    fs::write(gosling_path.clone(), buffer).expect("Unable to write file");
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

async fn upload_file(client: &Client, gosling: &Gosling) -> Result<()> {
    let bucket_name =
        env::var("GOOSE_B2_UPLOAD_BUCKET").expect("Need GOOSE_B2_UPLOAD_BUCKET set for now.");
    let body = ByteStream::from_path(Path::new(&gosling.file_path)).await;
    client
        .put_object()
        .bucket(bucket_name)
        .key(&gosling.id)
        .body(body.unwrap())
        .content_length(gosling.content_length as i64)
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
