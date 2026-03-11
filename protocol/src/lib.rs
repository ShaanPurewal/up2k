use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256, Sha512};

pub const WARK_SALT: &str = "up2k";
pub const MIN_CHUNK_SIZE: u64 = 1024 * 1024;
pub const MAX_CHUNKS: u64 = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadHandshake {
    pub filename: String,
    pub filesize: u64,
    pub chunk_size: u64,
    #[serde(with = "hash_list_serde")]
    pub hashes: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSessionResponse {
    pub wark: String,
    pub missing_chunks: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkUpload {
    pub wark: String,
    pub index: u32,
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeUpload {
    pub wark: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkUploadResponse {
    pub stored: bool,
    pub duplicate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeResponse {
    pub complete: bool,
    pub missing_chunks: Vec<u32>,
}

pub fn select_chunk_size(filesize: u64) -> u64 {
    let mut chunk_size = MIN_CHUNK_SIZE;
    while filesize.div_ceil(chunk_size) > MAX_CHUNKS {
        chunk_size *= 2;
    }
    chunk_size
}

pub fn chunk_count(filesize: u64, chunk_size: u64) -> u32 {
    if filesize == 0 {
        0
    } else {
        filesize.div_ceil(chunk_size) as u32
    }
}

pub fn chunk_range(filesize: u64, chunk_size: u64, index: u32) -> Option<(usize, usize)> {
    let start = u64::from(index).checked_mul(chunk_size)?;
    if start > filesize {
        return None;
    }

    let end = start.saturating_add(chunk_size).min(filesize);
    if start == end && start == filesize && filesize != 0 {
        return None;
    }

    let start = usize::try_from(start).ok()?;
    let end = usize::try_from(end).ok()?;
    Some((start, end))
}

pub fn chunk_len(filesize: u64, chunk_size: u64, index: u32) -> Option<u64> {
    let start = u64::from(index).checked_mul(chunk_size)?;
    if start >= filesize {
        return None;
    }

    Some((filesize - start).min(chunk_size))
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

pub fn encode_hash(hash: &[u8; 32]) -> String {
    STANDARD.encode(hash)
}

pub fn compute_wark(filesize: u64, hashes: &[[u8; 32]]) -> String {
    let mut parts = Vec::with_capacity(hashes.len() + 2);
    parts.push(WARK_SALT.to_owned());
    parts.push(filesize.to_string());
    for hash in hashes {
        parts.push(encode_hash(hash));
    }

    let joined = parts.join("\n");
    let digest = Sha512::digest(joined.as_bytes());
    STANDARD.encode(&digest[..33])
}

mod hash_list_serde {
    use super::*;

    pub fn serialize<S>(hashes: &Vec<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: Vec<String> = hashes.iter().map(encode_hash).collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Vec::<String>::deserialize(deserializer)?;
        encoded
            .into_iter()
            .map(|value| decode_hash(&value).map_err(serde::de::Error::custom))
            .collect()
    }

    fn decode_hash(value: &str) -> Result<[u8; 32], DecodeHashError> {
        let bytes = STANDARD.decode(value).map_err(DecodeHashError::InvalidBase64)?;
        if bytes.len() != 32 {
            return Err(DecodeHashError::WrongLength(bytes.len()));
        }

        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(hash)
    }

    #[derive(Debug)]
    enum DecodeHashError {
        InvalidBase64(base64::DecodeError),
        WrongLength(usize),
    }

    impl fmt::Display for DecodeHashError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidBase64(error) => write!(f, "invalid base64 hash: {error}"),
                Self::WrongLength(length) => {
                    write!(f, "expected 32-byte hash, got {length} bytes")
                }
            }
        }
    }
}

mod base64_bytes {
    use super::*;

    pub fn serialize<S>(data: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(data))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}
