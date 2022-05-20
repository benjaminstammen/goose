use ring::digest::{Context as DigestContext, Digest, SHA256};
use serde::{Deserialize, Serialize};
use data_encoding::HEXLOWER;

#[derive(Debug, Serialize, Deserialize)]
pub enum HashType {
    SHA256,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Hash {
    pub hash_value: String,
    pub hash_type: HashType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MotherGoose {
    pub id: String,
    pub goslings: Vec<Gosling>,
    pub checksum: Hash,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Gosling {
    pub id: String,
    pub checksum: Hash,
}

pub struct LocalFile {
    pub file_name: String,
    pub file_dir: String,
    pub content_length: usize,
    pub checksum: Hash,
}

// BEGIN: Hashing functions:

pub fn sha256_digest(bytes: &[u8]) -> Hash {
    let mut context = DigestContext::new(&SHA256);
    context.update(bytes);
    finalize_hash(context.finish(), HashType::SHA256)
}

pub fn finalize_hash(digest: Digest, hash_type: HashType) -> Hash {
    Hash {
        hash_value: HEXLOWER.encode(digest.as_ref()),
        hash_type,
    }
}