use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

pub type ChunkHash = [u8; 32];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UploadHandshake {
    pub filename: String,
    pub filesize: u64,
    pub chunk_size: u64,
    pub hashes: Vec<ChunkHash>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UploadSessionResponse {
    pub wark: String,
    pub missing_chunks: Vec<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChunkUpload {
    pub wark: String,
    pub index: u32,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FinalizeUpload {
    pub wark: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChunkUploadProgress {
    pub wark: String,
    pub index: u32,
    pub uploaded_chunks: u32,
    pub total_chunks: u32,
    pub uploaded_bytes: u64,
    pub total_bytes: u64,
    pub percent_complete: f64,
    pub throughput_bytes_per_sec: f64,
    pub eta_seconds: f64,
}

// Chunk Hashing
pub fn compute_chunk_size(filesize: u64) -> u64 {
    const MIB: u64 = 1 << 20;
    const LARGE_CHUNK_THRESHOLD: u64 = 32 * MIB;

    let mut chunk_size = MIB;
    let mut step_size = MIB / 2;
    let mut double_step = false;

    loop {
        let chunk_count = (filesize / chunk_size) + u64::from(!filesize.is_multiple_of(chunk_size));
        if chunk_count <= 256 || (chunk_size >= LARGE_CHUNK_THRESHOLD && chunk_count <= 4096) {
            return chunk_size;
        }

        chunk_size = chunk_size.saturating_add(step_size);
        if double_step {
            step_size = step_size.saturating_mul(2);
        }
        double_step = !double_step;
    }
}

pub fn hash_chunk(data: &[u8]) -> ChunkHash {
    Sha256::digest(data).into()
}

// WARK
pub fn compute_wark(salt: &str, filesize: u64, hashes: &[ChunkHash]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(salt.as_bytes());
    hasher.update(b"\n");

    let filesize_text = filesize.to_string();
    hasher.update(filesize_text.as_bytes());

    for hash in hashes {
        hasher.update(b"\n");
        hasher.update(hash);
    }

    let digest = hasher.finalize();
    STANDARD.encode(&digest[..33])
}
