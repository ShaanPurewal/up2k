use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::net::SocketAddr;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

#[allow(dead_code)]
struct UploadSession {
    wark: String,
    filename: String,
    filesize: u64,
    chunk_size: u64,
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
    println!("listening on http://{addr}");
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

    let session = {
        let mut sessions = state.sessions.write().await;
        if let Some(existing) = sessions.get(&wark) {
            Arc::clone(existing)
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
            session
        }
    };

    let missing_chunks = session.missing_chunks().await;
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
