use std::{env, fs::File, io, path::PathBuf, sync::Arc, time::Instant};

use memmap2::{Mmap, MmapOptions};
mod metrics;
use bytes::Bytes;
use metrics::{ClientChunkStats, FinalizeStats, HandshakeStats, MetadataStats, UploadMetrics};
use protocol::{
    ChunkUploadProgress, FinalizeUpload, UploadHandshake, UploadSessionResponse,
    compute_chunk_size, compute_wark, hash_chunk,
};
use rayon::prelude::*;
use reqwest::Client;
use tokio::task::JoinSet;

const SALT: &str = "test_salt";
const MAX_PARALLEL_UPLOADS: usize = 8;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, BoxError>;

#[derive(Clone)]
struct FileInfo {
    wark: String,
    mmap: Arc<Mmap>,
    filesize: u64,
    chunk_size: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);

    let first = args.next().expect("usage: client [server_url] <path>");
    let second = args.next();

    let (server_url, path) = match second {
        Some(path) => (first, PathBuf::from(path)),
        None => ("http://127.0.0.1:3000".to_string(), PathBuf::from(first)),
    };

    upload_file(&server_url, path).await
}

async fn upload_chunk(
    client: &Client,
    server_url: &str,
    file_info: &FileInfo,
    index: u32,
    metrics: &UploadMetrics,
) -> Result<ChunkUploadProgress> {
    let total_started = Instant::now();
    let inflight = metrics.inflight_guard();

    let prep_started = Instant::now();
    let offset = u64::from(index)
        .checked_mul(file_info.chunk_size)
        .ok_or_else(|| io::Error::other(format!("chunk {}: chunk offset overflow", index)))?;
    let chunk_end = offset
        .saturating_add(file_info.chunk_size)
        .min(file_info.filesize);
    let start = usize::try_from(offset)
        .map_err(|_| io::Error::other(format!("chunk {}: offset too large", index)))?;
    let end = usize::try_from(chunk_end)
        .map_err(|_| io::Error::other(format!("chunk {}: chunk end too large", index)))?;
    let chunk = &file_info.mmap[start..end];
    let prep_elapsed = prep_started.elapsed();

    let body_copy_started = Instant::now();
    let body = Bytes::copy_from_slice(chunk);
    let body_copy_elapsed = body_copy_started.elapsed();

    let send_started = Instant::now();
    let response = client
        .post(endpoint(server_url, "/upload/chunk"))
        .query(&[
            ("wark", file_info.wark.clone()),
            ("index", index.to_string()),
        ])
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(body)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|error| io::Error::other(format!("chunk {}: request failed: {}", index, error)))?;
    let send_elapsed = send_started.elapsed();

    let decode_started = Instant::now();
    let progress = response
        .json::<ChunkUploadProgress>()
        .await
        .map_err(|error| {
            io::Error::other(format!(
                "chunk {}: invalid progress response: {}",
                index, error
            ))
        })?;
    let decode_elapsed = decode_started.elapsed();

    let success = progress.wark == file_info.wark && progress.index == index;

    metrics.record_chunk(ClientChunkStats {
        index,
        chunk_size: chunk.len(),
        inflight_at_start: inflight.inflight_at_start(),
        prep: prep_elapsed,
        body_copy: body_copy_elapsed,
        send_wait: send_elapsed,
        response_decode: decode_elapsed,
        total: total_started.elapsed(),
        success,
    });

    if !success {
        return Err(
            io::Error::other(format!("chunk {}: progress response mismatch", index)).into(),
        );
    }

    Ok(progress)
}

async fn upload_chunks(
    client: &Client,
    server_url: &str,
    file_info: &FileInfo,
    missing_chunks: Vec<u32>,
    metrics: &UploadMetrics,
) -> Result<()> {
    if missing_chunks.is_empty() {
        return Ok(());
    }

    let mut tasks = JoinSet::new();
    let mut pending = missing_chunks.into_iter();
    let mut first_error: Option<String> = None;

    loop {
        while tasks.len() < MAX_PARALLEL_UPLOADS.max(1) {
            let Some(index) = pending.next() else { break };
            let client = client.clone();
            let file_info = file_info.clone();
            let server_url = server_url.to_owned();
            let metrics = metrics.clone();

            tasks.spawn(async move {
                let result = upload_chunk(&client, &server_url, &file_info, index, &metrics).await;
                (index, result)
            });
        }

        if tasks.is_empty() {
            break;
        }

        match tasks
            .join_next()
            .await
            .ok_or_else(|| io::Error::other("upload task set ended unexpectedly"))?
        {
            Ok((index, Ok(progress))) => {
                let _ = (index, progress);
            }
            Ok((index, Err(error))) if first_error.is_none() => {
                first_error = Some(format!("chunk {} failed: {}", index, error))
            }
            Err(error) if first_error.is_none() => {
                first_error = Some(format!("chunk upload task failed: {}", error))
            }
            _ => {}
        }
    }

    if let Some(error) = first_error {
        Err(io::Error::other(error).into())
    } else {
        Ok(())
    }
}

async fn upload_file(server_url: &str, path: PathBuf) -> Result<()> {
    let upload_started = Instant::now();
    let metrics = UploadMetrics::new();

    // FILE SETUP
    let file_open_started = Instant::now();
    let file = File::open(&path)?;
    let mmap = Arc::new(unsafe { MmapOptions::new().map(&file)? });
    let file_open_elapsed = file_open_started.elapsed();

    let filesize = file.metadata()?.len();
    if filesize == 0 {
        return Err("the file contains zero bytes".into());
    }
    let filename = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no filename"))?
        .to_string_lossy()
        .into_owned();

    // HASHING / WARK
    let hash_started = Instant::now();
    let chunk_size = compute_chunk_size(filesize);
    let hashes = mmap
        .par_chunks(usize::try_from(chunk_size)?)
        .map(hash_chunk)
        .collect::<Vec<_>>();
    let chunk_count = u32::try_from(hashes.len())?;
    let hash_elapsed = hash_started.elapsed();

    let wark_started = Instant::now();
    let wark = compute_wark(SALT, filesize, &hashes);
    let wark_elapsed = wark_started.elapsed();

    metrics.record_metadata(MetadataStats {
        file_open: file_open_elapsed,
        hash: hash_elapsed,
        wark: wark_elapsed,
        filesize,
        chunk_size,
        chunk_count,
    });

    // HANDSHAKLE / REGISTER
    let client = Client::builder().build()?;
    let handshake_started = Instant::now();
    let handshake_request = UploadHandshake {
        filename,
        filesize,
        chunk_size,
        hashes,
    };
    let response = client
        .post(endpoint(server_url, "/upload/handshake"))
        .json(&handshake_request)
        .send()
        .await?
        .error_for_status()?;

    let session = response.json::<UploadSessionResponse>().await?;
    if session.wark != wark {
        return Err(io::Error::other(format!(
            "server wark mismatch: expected {}, got {}",
            wark, session.wark
        ))
        .into());
    }

    metrics.record_handshake(HandshakeStats {
        elapsed: handshake_started.elapsed(),
        missing_chunks: session.missing_chunks.len(),
    });

    // SEND CHUNKS
    let mut missing_chunks = session.missing_chunks;
    let mut previous_missing_count = usize::MAX;
    let file_info = FileInfo {
        wark: wark.clone(),
        mmap,
        filesize,
        chunk_size,
    };

    loop {
        if !missing_chunks.is_empty() {
            let _ = upload_chunks(&client, server_url, &file_info, missing_chunks, &metrics).await;
        }

        // CHECK IF COMPLETE
        let finalize_started = Instant::now();
        let request = FinalizeUpload {
            wark: wark.to_owned(),
        };
        let response = client
            .post(endpoint(server_url, "/upload/finalize"))
            .json(&request)
            .send()
            .await?
            .error_for_status()?;
        let session = response.json::<UploadSessionResponse>().await?;

        if session.wark != wark {
            return Err(io::Error::other(format!(
                "server finalize wark mismatch: expected {}, got {}",
                wark, session.wark
            ))
            .into());
        }
        let missing_count = session.missing_chunks.len();

        metrics.record_finalize(FinalizeStats {
            elapsed: finalize_started.elapsed(),
            missing_chunks: missing_count,
            completed: missing_count == 0,
        });

        if missing_count == 0 {
            metrics.record_upload_complete(upload_started.elapsed(), &wark);
            println!("upload complete: {wark}");
            return Ok(());
        }

        if missing_count >= previous_missing_count {
            return Err(io::Error::other(format!(
                "upload stopped making progress: {:?}",
                session.missing_chunks
            ))
            .into());
        }
        metrics.record_retry_pass();
        previous_missing_count = missing_count;
        missing_chunks = session.missing_chunks;
    }
}

fn endpoint(url: &str, path: &str) -> String {
    format!(
        "{}/{}",
        url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}
