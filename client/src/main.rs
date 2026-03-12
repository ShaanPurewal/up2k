use std::{
    env,
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use memmap2::{Mmap, MmapOptions};
mod metrics;
use metrics::{
    ClientChunkStats, FinalizeStats, HandshakeStats, MetadataStats, UploadMetrics,
};
use protocol::{
    ChunkUploadProgress, FinalizeUpload, UploadHandshake, UploadSessionResponse,
    compute_chunk_size, compute_wark, hash_chunk,
};
use rayon::prelude::*;
use reqwest::Client;
use tokio::task::JoinSet;

const SERVER_URL: &str = "http://127.0.0.1:3000";
const SALT: &str = "test_salt";
const MAX_PARALLEL_UPLOADS: usize = 8;
const CONNECT_TIMEOUT_SECS: u64 = 10;
const REQUEST_TIMEOUT_SECS: u64 = 120;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, BoxError>;

#[derive(Debug)]
struct UploadPlan {
    filesize: u64,
    chunk_size: u64,
    chunk_count: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args_os();
    let _program = args.next();
    let path = match (args.next(), args.next()) {
        (Some(path), None) => PathBuf::from(path),
        _ => {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "usage: client <path>").into());
        }
    };

    upload_file(path).await
}

fn build_metadata(path: &Path, metrics: &UploadMetrics) -> Result<(UploadHandshake, String)> {
    let file_open_started = Instant::now();
    let file = File::open(path)?;
    let filesize = file.metadata()?.len();
    let file_open_elapsed = file_open_started.elapsed();
    let chunk_size = compute_chunk_size(filesize);
    if chunk_size == 0 {
        return Err(io::Error::other("compute_chunk_size returned 0").into());
    }
    let filename = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no filename"))?
        .to_string_lossy()
        .into_owned();
    let mut mmap_elapsed = Duration::ZERO;
    let mut hash_elapsed = Duration::ZERO;

    let hashes = if filesize == 0 {
        Vec::new()
    } else {
        let chunk_size = usize::try_from(chunk_size)
            .map_err(|_| io::Error::other("chunk size too large for this platform"))?;
        let expected_len = usize::try_from(filesize)
            .map_err(|_| io::Error::other("file too large to map on this platform"))?;
        let mmap_started = Instant::now();
        // SAFETY: the file stays open for the lifetime of the map, and we only read from it.
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        mmap_elapsed = mmap_started.elapsed();
        if mmap.len() != expected_len {
            return Err(io::Error::other(format!(
                "mapped file size changed during hashing: expected {}, got {}",
                expected_len,
                mmap.len()
            ))
            .into());
        }
        let hash_started = Instant::now();
        let hashes = mmap.par_chunks(chunk_size).map(hash_chunk).collect();
        hash_elapsed = hash_started.elapsed();
        hashes
    };

    let wark_started = Instant::now();
    let wark = compute_wark(SALT, filesize, &hashes);
    let wark_elapsed = wark_started.elapsed();
    metrics.record_metadata(MetadataStats {
        file_open: file_open_elapsed,
        mmap: mmap_elapsed,
        hash_wall: hash_elapsed,
        wark: wark_elapsed,
        filesize,
        chunk_size,
        chunk_count: u32::try_from(hashes.len()).unwrap_or(u32::MAX),
    });
    let handshake = UploadHandshake {
        filename,
        filesize,
        chunk_size,
        hashes,
    };

    Ok((handshake, wark))
}

fn build_upload_plan(handshake: &UploadHandshake) -> Result<UploadPlan> {
    if handshake.chunk_size == 0 {
        return Err(io::Error::other("chunk_size must be > 0").into());
    }

    let chunk_count = u32::try_from(handshake.hashes.len())
        .map_err(|_| io::Error::other("chunk count exceeds u32"))?;

    Ok(UploadPlan {
        filesize: handshake.filesize,
        chunk_size: handshake.chunk_size,
        chunk_count,
    })
}

async fn handshake(
    client: &Client,
    handshake: &UploadHandshake,
    wark: &str,
    metrics: &UploadMetrics,
) -> Result<UploadSessionResponse> {
    let started = Instant::now();
    let response = client
        .post(endpoint("/upload/handshake"))
        .json(handshake)
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
        elapsed: started.elapsed(),
        missing_chunks: session.missing_chunks.len(),
    });
    Ok(session)
}

async fn upload_chunk(
    client: &Client,
    upload_plan: &UploadPlan,
    wark: &str,
    mmap: &Mmap,
    index: u32,
    metrics: &UploadMetrics,
) -> Result<ChunkUploadProgress> {
    let total_started = Instant::now();
    let inflight = metrics.inflight_guard();
    if upload_plan.chunk_size == 0 {
        return Err(io::Error::other(format!("chunk {}: chunk_size must be > 0", index)).into());
    }
    if index >= upload_plan.chunk_count {
        return Err(
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("chunk {}: invalid chunk index", index),
            )
            .into(),
        );
    }

    let prep_started = Instant::now();
    let offset = u64::from(index)
        .checked_mul(upload_plan.chunk_size)
        .ok_or_else(|| io::Error::other(format!("chunk {}: chunk offset overflow", index)))?;
    let chunk_end = offset
        .saturating_add(upload_plan.chunk_size)
        .min(upload_plan.filesize);
    let start = usize::try_from(offset)
        .map_err(|_| io::Error::other(format!("chunk {}: offset too large", index)))?;
    let end = usize::try_from(chunk_end)
        .map_err(|_| io::Error::other(format!("chunk {}: chunk end too large", index)))?;
    let chunk = &mmap[start..end];
    let index_text = index.to_string();
    let prep_elapsed = prep_started.elapsed();
    let body_copy_started = Instant::now();
    let body = chunk.to_vec();
    let body_copy_elapsed = body_copy_started.elapsed();

    let send_started = Instant::now();
    let response = client
        .post(endpoint("/upload/chunk"))
        .query(&[("wark", wark), ("index", index_text.as_str())])
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(body)
        .send()
        .await
        .map_err(|error| {
            metrics.record_chunk(ClientChunkStats {
                index,
                chunk_size: chunk.len(),
                inflight_at_start: inflight.inflight_at_start(),
                prep: prep_elapsed,
                body_copy: body_copy_elapsed,
                send_wait: send_started.elapsed(),
                response_decode: Duration::ZERO,
                total: total_started.elapsed(),
                success: false,
            });
            io::Error::other(format!("chunk {}: request failed: {}", index, error))
        })?
        .error_for_status()
        .map_err(|error| {
            metrics.record_chunk(ClientChunkStats {
                index,
                chunk_size: chunk.len(),
                inflight_at_start: inflight.inflight_at_start(),
                prep: prep_elapsed,
                body_copy: body_copy_elapsed,
                send_wait: send_started.elapsed(),
                response_decode: Duration::ZERO,
                total: total_started.elapsed(),
                success: false,
            });
            io::Error::other(format!("chunk {}: server error: {}", index, error))
        })?;
    let send_elapsed = send_started.elapsed();

    let decode_started = Instant::now();
    let progress = response
        .json::<ChunkUploadProgress>()
        .await
        .map_err(|error| {
            metrics.record_chunk(ClientChunkStats {
                index,
                chunk_size: chunk.len(),
                inflight_at_start: inflight.inflight_at_start(),
                prep: prep_elapsed,
                body_copy: body_copy_elapsed,
                send_wait: send_elapsed,
                response_decode: decode_started.elapsed(),
                total: total_started.elapsed(),
                success: false,
            });
            io::Error::other(format!(
                "chunk {}: invalid progress response: {}",
                index, error
            ))
        })?;
    if progress.wark != wark {
        metrics.record_chunk(ClientChunkStats {
            index,
            chunk_size: chunk.len(),
            inflight_at_start: inflight.inflight_at_start(),
            prep: prep_elapsed,
            body_copy: body_copy_elapsed,
            send_wait: send_elapsed,
            response_decode: decode_started.elapsed(),
            total: total_started.elapsed(),
            success: false,
        });
        return Err(io::Error::other(format!(
            "chunk {}: progress response wark mismatch: expected {}, got {}",
            index, wark, progress.wark
        ))
        .into());
    }
    if progress.index != index {
        metrics.record_chunk(ClientChunkStats {
            index,
            chunk_size: chunk.len(),
            inflight_at_start: inflight.inflight_at_start(),
            prep: prep_elapsed,
            body_copy: body_copy_elapsed,
            send_wait: send_elapsed,
            response_decode: decode_started.elapsed(),
            total: total_started.elapsed(),
            success: false,
        });
        return Err(io::Error::other(format!(
            "chunk {}: progress response index mismatch: got {}",
            index, progress.index
        ))
        .into());
    }

    metrics.record_chunk(ClientChunkStats {
        index,
        chunk_size: chunk.len(),
        inflight_at_start: inflight.inflight_at_start(),
        prep: prep_elapsed,
        body_copy: body_copy_elapsed,
        send_wait: send_elapsed,
        response_decode: decode_started.elapsed(),
        total: total_started.elapsed(),
        success: true,
    });
    Ok(progress)
}

async fn upload_chunks(
    client: &Client,
    upload_plan: Arc<UploadPlan>,
    wark: &str,
    mmap: Arc<Mmap>,
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
            let Some(index) = pending.next() else {
                break;
            };

            let client = client.clone();
            let upload_plan = Arc::clone(&upload_plan);
            let wark = wark.to_owned();
            let mmap = Arc::clone(&mmap);
            let metrics = metrics.clone();

            tasks.spawn(async move {
                let result = upload_chunk(&client, &upload_plan, &wark, &mmap, index, &metrics).await;
                (index, result)
            });
        }

        if tasks.is_empty() {
            break;
        }

        let result = tasks
            .join_next()
            .await
            .ok_or_else(|| io::Error::other("upload task set ended unexpectedly"))?;
        match result {
            Ok((index, Ok(progress))) => {
                let _ = (index, progress);
            }
            Ok((index, Err(error))) => {
                if first_error.is_none() {
                    first_error = Some(format!("chunk {} failed: {}", index, error));
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(format!("chunk upload task failed: {}", error));
                }
            }
        }
    }

    if let Some(error) = first_error {
        return Err(io::Error::other(error).into());
    }

    Ok(())
}

async fn finalize_upload(client: &Client, wark: &str) -> Result<UploadSessionResponse> {
    let request = FinalizeUpload {
        wark: wark.to_owned(),
    };

    let response = client
        .post(endpoint("/upload/finalize"))
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

    Ok(session)
}

async fn upload_file(path: PathBuf) -> Result<()> {
    let upload_started = Instant::now();
    let metrics = UploadMetrics::new();
    let (handshake_request, wark) = build_metadata(&path, &metrics)?;
    let upload_plan = Arc::new(build_upload_plan(&handshake_request)?);
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()?;
    let mut missing_chunks = handshake(&client, &handshake_request, &wark, &metrics)
        .await?
        .missing_chunks;
    let mut previous_missing_count = usize::MAX;
    let mmap = if handshake_request.filesize == 0 {
        None
    } else {
        let file = File::open(&path)?;
        let expected_len = usize::try_from(handshake_request.filesize)
            .map_err(|_| io::Error::other("file too large to map on this platform"))?;
        // SAFETY: the file remains open while the map lives, and uploads only read immutable slices.
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        if mmap.len() != expected_len {
            return Err(io::Error::other(format!(
                "mapped file size changed before upload: expected {}, got {}",
                expected_len,
                mmap.len()
            ))
            .into());
        }
        Some(Arc::new(mmap))
    };

    loop {
        let upload_error = if !missing_chunks.is_empty() {
            let mmap = mmap
                .as_ref()
                .ok_or_else(|| io::Error::other("server reported missing chunks for empty file"))?;
            upload_chunks(
                &client,
                Arc::clone(&upload_plan),
                &wark,
                Arc::clone(mmap),
                missing_chunks,
                &metrics,
            )
            .await
            .err()
        } else {
            None
        };

        let finalize_started = Instant::now();
        let session = finalize_upload(&client, &wark).await?;
        metrics.record_finalize(FinalizeStats {
            elapsed: finalize_started.elapsed(),
            missing_chunks: session.missing_chunks.len(),
            completed: session.missing_chunks.is_empty(),
        });
        if session.missing_chunks.is_empty() {
            if let Some(error) = upload_error {
                eprintln!("upload completed after a partial failure in the last pass: {error}");
            }
            metrics.record_upload_complete(upload_started.elapsed(), &wark);
            println!("upload complete: {wark}");
            return Ok(());
        }

        if session.missing_chunks.len() >= previous_missing_count {
            let detail = if let Some(error) = upload_error {
                format!(
                    "upload stopped making progress after a failed batch ({}), still missing chunks: {:?}",
                    error, session.missing_chunks
                )
            } else {
                format!(
                    "upload stopped making progress, still missing chunks: {:?}",
                    session.missing_chunks
                )
            };
            return Err(io::Error::other(detail).into());
        }

        metrics.record_retry_pass();
        previous_missing_count = session.missing_chunks.len();
        missing_chunks = session.missing_chunks;
    }
}

fn endpoint(path: &str) -> String {
    format!(
        "{}/{}",
        SERVER_URL.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}
