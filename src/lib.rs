use data_encoding::HEXLOWER;
use ring::digest::{Context, Digest, SHA256};
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Result};
use uuid::Uuid;

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

pub fn file_gooser(file_path: &str, gosling_size: usize) {
    let file = File::open(file_path).expect("Unable to open file!");

    let mut goslings = Vec::new();
    let mut reader = BufReader::with_capacity(gosling_size, file);
    loop {
        let length = {
            let buffer = reader.fill_buf().expect("Error reading file!");
            goslings.push(spawn_gosling_for_buffer(buffer, file_path));
            buffer.len()
        };
        if length == 0 {
            break;
        }
        reader.consume(length);
    }
    println!("Finished spawning goslings.");

    println!(
        "{}",
        sha256_digest_for_file(file_path).expect("Failed to compute hash")
    );
}

fn spawn_gosling_for_buffer(buffer: &[u8], write_path: &str) -> Gosling {
    let gosling_name = format!("{}.gos", Uuid::new_v4());
    let gosling_path = format!("{}.d/{}", write_path, gosling_name);
    fs::write(gosling_path.clone(), buffer).expect("Unable to write file");
    Gosling::new(gosling_name, buffer.len(), gosling_path)
}

fn sha256_digest_for_file(file_path: &str) -> Result<String> {
    let input = File::open(file_path)?;
    let reader = BufReader::new(input);
    let digest = sha256_digest(reader)?;
    Ok(HEXLOWER.encode(digest.as_ref()))
}

// Lifted from the Rust Cookbook here: https://rust-lang-nursery.github.io/rust-cookbook/cryptography/hashing.html
// TODO: find a way to compute the hash rapidly while creating goslings. Not doing so now because it's been
//     prohibitively slow.
fn sha256_digest<R: Read>(mut reader: R) -> Result<Digest> {
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