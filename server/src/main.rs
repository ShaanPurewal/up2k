use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::net::SocketAddr;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use bitvec::vec::BitVec;
use protocol::{
    chunk_count, chunk_len, compute_wark, sha256_bytes, ChunkUpload, ChunkUploadResponse,
    FinalizeResponse, FinalizeUpload, UploadHandshake, UploadSessionResponse,
};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};

type ApiResult<T> = Result<Json<T>, ApiError>;

#[derive(Clone)]
struct AppState {
    sessions: Arc<RwLock<HashMap<String, Arc<UploadSession>>>>,
    upload_root: PathBuf,
}

struct UploadSession {
    wark: String,
    filename: String,
    filesize: u64,
    chunk_size: u64,
    created_at: Instant,
    received_chunks: Mutex<BitVec>,
    file_path: PathBuf,
    expected_hashes: Vec<[u8; 32]>,
    file: File,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.status, self.message).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let upload_root = PathBuf::from("uploads");
    fs::create_dir_all(&upload_root)?;

    let state = AppState {
        sessions: Arc::new(RwLock::new(HashMap::new())),
        upload_root,
    };

    let app = Router::new()
        .route("/upload/handshake", post(upload_handshake))
        .route("/upload/chunk", post(upload_chunk))
        .route("/upload/finalize", post(finalize_upload))
        .route("/upload/status/{*wark}", get(upload_status))
        .layer(DefaultBodyLimit::disable())
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("server: listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn upload_handshake(
    State(state): State<AppState>,
    Json(request): Json<UploadHandshake>,
) -> ApiResult<UploadSessionResponse> {
    let expected_chunk_size = protocol::select_chunk_size(request.filesize);
    if request.chunk_size != expected_chunk_size {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!(
                "invalid chunk size {}, expected {}",
                request.chunk_size, expected_chunk_size
            ),
        ));
    }

    let expected_chunks = chunk_count(request.filesize, request.chunk_size) as usize;
    if request.hashes.len() != expected_chunks {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!(
                "invalid hash count {}, expected {}",
                request.hashes.len(),
                expected_chunks
            ),
        ));
    }

    let wark = compute_wark(request.filesize, &request.hashes);
    println!(
        "server: handshake filename={} size={} chunk_size={} chunks={} wark={}",
        request.filename,
        request.filesize,
        request.chunk_size,
        expected_chunks,
        short_wark(&wark)
    );

    let (session, created) = {
        let mut sessions = state.sessions.write().await;
        if let Some(existing) = sessions.get(&wark) {
            (Arc::clone(existing), false)
        } else {
            let session = Arc::new(
                create_session(
                    &state.upload_root,
                    &wark,
                    &request.filename,
                    request.filesize,
                    request.chunk_size,
                    request.hashes.clone(),
                )
                .map_err(internal_error)?,
            );
            sessions.insert(wark.clone(), Arc::clone(&session));
            (session, true)
        }
    };

    let missing_chunks = session.missing_chunks().await;
    let missing_bytes = chunk_indexes_len(session.filesize, session.chunk_size, &missing_chunks);
    let complete_bytes = session.filesize.saturating_sub(missing_bytes);
    if created {
        println!(
            "server: created session {} path={} missing={}/{} progress={} bytes={}/{}",
            short_wark(&session.wark),
            session.file_path.display(),
            missing_chunks.len(),
            session.expected_hashes.len(),
            format_percent(complete_bytes, session.filesize),
            format_bytes(complete_bytes),
            format_bytes(session.filesize)
        );
    } else if missing_chunks.is_empty() {
        println!(
            "server: existing upload already complete {} filename={} progress={} bytes={}/{} avg_write_rate={}",
            short_wark(&session.wark),
            session.filename,
            format_percent(complete_bytes, session.filesize),
            format_bytes(complete_bytes),
            format_bytes(session.filesize),
            format_rate(complete_bytes, session.created_at.elapsed())
        );
    } else {
        println!(
            "server: resuming existing upload {} filename={} missing={}/{} progress={} bytes={}/{} avg_write_rate={}",
            short_wark(&session.wark),
            session.filename,
            missing_chunks.len(),
            session.expected_hashes.len(),
            format_percent(complete_bytes, session.filesize),
            format_bytes(complete_bytes),
            format_bytes(session.filesize),
            format_rate(complete_bytes, session.created_at.elapsed())
        );
    }

    Ok(Json(UploadSessionResponse { wark, missing_chunks }))
}

async fn upload_chunk(
    State(state): State<AppState>,
    Json(request): Json<ChunkUpload>,
) -> ApiResult<ChunkUploadResponse> {
    let session = {
        let sessions = state.sessions.read().await;
        sessions
            .get(&request.wark)
            .cloned()
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "upload session not found"))?
    };

    let index = request.index as usize;
    if index >= session.expected_hashes.len() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("chunk index {} out of range", request.index),
        ));
    }

    let expected_len = chunk_len(session.filesize, session.chunk_size, request.index)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid chunk index"))?;
    if request.data.len() as u64 != expected_len {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!(
                "chunk {} has {} bytes, expected {}",
                request.index,
                request.data.len(),
                expected_len
            ),
        ));
    }

    let actual_hash = sha256_bytes(&request.data);
    let expected_hash = session.expected_hashes[index];
    if actual_hash != expected_hash {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("chunk {} failed hash verification", request.index),
        ));
    }

    {
        let received = session.received_chunks.lock().await;
        if received.get(index).map(|bit| *bit).unwrap_or(false) {
            println!(
                "server: dedup chunk {} ignored for {}",
                request.index,
                short_wark(&session.wark)
            );
            return Ok(Json(ChunkUploadResponse {
                stored: false,
                duplicate: true,
            }));
        }
    }

    let offset = u64::from(request.index) * session.chunk_size;
    session
        .file
        .write_all_at(&request.data, offset)
        .map_err(internal_error)?;

    let mut received = session.received_chunks.lock().await;
    received.set(index, true);
    let remaining = received.iter().by_vals().filter(|present| !present).count();
    let received_count = received.len().saturating_sub(remaining);
    let completed_bytes = completed_bytes_from_bits(&received, session.chunk_size, session.filesize);
    println!(
        "server: stored chunk {} for {} ({}/{} complete, remaining={}) progress={} bytes={}/{} avg_write_rate={}",
        request.index,
        short_wark(&session.wark),
        received_count,
        received.len(),
        remaining,
        format_percent(completed_bytes, session.filesize),
        format_bytes(completed_bytes),
        format_bytes(session.filesize),
        format_rate(completed_bytes, session.created_at.elapsed())
    );

    Ok(Json(ChunkUploadResponse {
        stored: true,
        duplicate: false,
    }))
}

async fn finalize_upload(
    State(state): State<AppState>,
    Json(request): Json<FinalizeUpload>,
) -> ApiResult<FinalizeResponse> {
    let session = {
        let sessions = state.sessions.read().await;
        sessions
            .get(&request.wark)
            .cloned()
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "upload session not found"))?
    };

    let missing_chunks = session.missing_chunks().await;
    let missing_bytes = chunk_indexes_len(session.filesize, session.chunk_size, &missing_chunks);
    let complete_bytes = session.filesize.saturating_sub(missing_bytes);
    if missing_chunks.is_empty() {
        println!(
            "server: finalize complete for {} filename={} progress={} bytes={}/{} elapsed={} avg_write_rate={}",
            short_wark(&session.wark),
            session.filename,
            format_percent(complete_bytes, session.filesize),
            format_bytes(complete_bytes),
            format_bytes(session.filesize),
            format_duration(session.created_at.elapsed()),
            format_rate(complete_bytes, session.created_at.elapsed())
        );
    } else {
        println!(
            "server: finalize incomplete for {} missing={:?} progress={} bytes={}/{}",
            short_wark(&session.wark),
            missing_chunks,
            format_percent(complete_bytes, session.filesize),
            format_bytes(complete_bytes),
            format_bytes(session.filesize)
        );
    }
    Ok(Json(FinalizeResponse {
        complete: missing_chunks.is_empty(),
        missing_chunks,
    }))
}

async fn upload_status(
    State(state): State<AppState>,
    AxumPath(wark): AxumPath<String>,
) -> ApiResult<UploadSessionResponse> {
    let wark = wark.trim_start_matches('/').to_owned();
    let session = {
        let sessions = state.sessions.read().await;
        sessions
            .get(&wark)
            .cloned()
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "upload session not found"))?
    };

    let missing_chunks = session.missing_chunks().await;
    let missing_bytes = chunk_indexes_len(session.filesize, session.chunk_size, &missing_chunks);
    let complete_bytes = session.filesize.saturating_sub(missing_bytes);
    println!(
        "server: status {} missing={}/{} progress={} bytes={}/{} avg_write_rate={}",
        short_wark(&wark),
        missing_chunks.len(),
        session.expected_hashes.len(),
        format_percent(complete_bytes, session.filesize),
        format_bytes(complete_bytes),
        format_bytes(session.filesize),
        format_rate(complete_bytes, session.created_at.elapsed())
    );
    Ok(Json(UploadSessionResponse { wark, missing_chunks }))
}

fn create_session(
    upload_root: &Path,
    wark: &str,
    filename: &str,
    filesize: u64,
    chunk_size: u64,
    expected_hashes: Vec<[u8; 32]>,
) -> std::io::Result<UploadSession> {
    let file_key = safe_file_key(wark);
    let file_path = upload_root.join(format!("{file_key}.part"));
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&file_path)?;
    file.set_len(filesize)?;

    Ok(UploadSession {
        wark: wark.to_owned(),
        filename: filename.to_owned(),
        filesize,
        chunk_size,
        created_at: Instant::now(),
        received_chunks: Mutex::new(BitVec::repeat(false, expected_hashes.len())),
        file_path,
        expected_hashes,
        file,
    })
}

fn safe_file_key(wark: &str) -> String {
    let digest = Sha256::digest(wark.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn internal_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn short_wark(wark: &str) -> &str {
    let end = wark.len().min(12);
    &wark[..end]
}

fn chunk_indexes_len(filesize: u64, chunk_size: u64, indexes: &[u32]) -> u64 {
    indexes
        .iter()
        .filter_map(|&index| chunk_len(filesize, chunk_size, index))
        .sum()
}

fn completed_bytes_from_bits(received: &BitVec, chunk_size: u64, filesize: u64) -> u64 {
    received
        .iter()
        .by_vals()
        .enumerate()
        .filter_map(|(index, present)| {
            present.then(|| chunk_len(filesize, chunk_size, index as u32)).flatten()
        })
        .sum()
}

fn format_percent(done: u64, total: u64) -> String {
    if total == 0 {
        return "100.0%".to_owned();
    }

    format!("{:.1}%", (done as f64 / total as f64) * 100.0)
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs_f64() >= 1.0 {
        format!("{:.2}s", duration.as_secs_f64())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

fn format_rate(bytes: u64, elapsed: Duration) -> String {
    let seconds = elapsed.as_secs_f64();
    if bytes == 0 || seconds <= f64::EPSILON {
        return "n/a".to_owned();
    }

    format!("{}/s", format_bytes((bytes as f64 / seconds) as u64))
}

impl UploadSession {
    async fn missing_chunks(&self) -> Vec<u32> {
        let received = self.received_chunks.lock().await;
        received
            .iter()
            .by_vals()
            .enumerate()
            .filter_map(|(index, present)| (!present).then_some(index as u32))
            .collect()
    }
}
