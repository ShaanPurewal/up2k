use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use bitvec::{bitvec, prelude::BitVec};
use protocol::{
    ChunkHash, FinalizeUpload, UploadHandshake, UploadSessionResponse, compute_wark, hash_chunk,
};
use serde::Deserialize;

const STORAGE_DIR: &str = "uploads";
const SALT: &str = "test_salt";

type SharedState = Arc<Mutex<ServerState>>;
type HandlerResult<T> = Result<T, (StatusCode, String)>;

#[derive(Debug, Clone)]
struct UploadSession {
    wark: String,
    #[allow(dead_code)]
    filename: String,
    filesize: u64,
    chunk_size: u64,
    hashes: Vec<ChunkHash>,
    received: BitVec,
    file_path: PathBuf,
}

#[derive(Debug, Default)]
struct ServerState {
    sessions: HashMap<String, UploadSession>,
}

#[derive(Debug, Deserialize)]
struct ChunkQuery {
    wark: String,
    index: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fs::create_dir_all(STORAGE_DIR)?;

    let state = Arc::new(Mutex::new(ServerState::default()));
    let app = Router::new()
        .route("/upload/handshake", post(upload_handshake))
        .route(
            "/upload/chunk",
            post(upload_chunk).layer(DefaultBodyLimit::disable()),
        )
        .route("/upload/finalize", post(finalize_upload))
        .route("/upload/status/{wark}", get(upload_status))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await?;

    Ok(())
}

fn chunk_count(filesize: u64, chunk_size: u64) -> u32 {
    if chunk_size == 0 {
        return 0;
    }

    let total = (filesize / chunk_size) + u64::from(!filesize.is_multiple_of(chunk_size));
    u32::try_from(total).unwrap_or(u32::MAX)
}

fn chunk_offset(index: u32, chunk_size: u64) -> u64 {
    u64::from(index).saturating_mul(chunk_size)
}

fn missing_chunks(received: &BitVec) -> Vec<u32> {
    received
        .iter()
        .by_vals()
        .enumerate()
        .filter_map(|(index, done)| (!done).then_some(index as u32))
        .collect()
}

async fn upload_handshake(
    State(state): State<SharedState>,
    Json(req): Json<UploadHandshake>,
) -> HandlerResult<Json<UploadSessionResponse>> {
    if req.chunk_size == 0 {
        return Err((StatusCode::BAD_REQUEST, "chunk_size must be > 0".to_owned()));
    }

    let expected_chunks = chunk_count(req.filesize, req.chunk_size) as usize;
    if req.hashes.len() != expected_chunks {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "hash count mismatch: expected {}, got {}",
                expected_chunks,
                req.hashes.len()
            ),
        ));
    }

    let wark = compute_wark(SALT, req.filesize, &req.hashes);
    {
        let state = state.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "state lock poisoned".to_owned(),
            )
        })?;
        if let Some(session) = state.sessions.get(&wark) {
            return Ok(Json(UploadSessionResponse {
                wark: session.wark.clone(),
                missing_chunks: missing_chunks(&session.received),
            }));
        }
    }

    let safe_wark: String = wark
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    let file_path = PathBuf::from(STORAGE_DIR).join(format!("{safe_wark}.upload"));
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&file_path)
        .map_err(internal_error)?;
    file.set_len(req.filesize).map_err(internal_error)?;

    let session = UploadSession {
        wark: wark.clone(),
        filename: req.filename,
        filesize: req.filesize,
        chunk_size: req.chunk_size,
        hashes: req.hashes,
        received: bitvec![0; expected_chunks],
        file_path,
    };

    let mut state = state.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "state lock poisoned".to_owned(),
        )
    })?;
    let response = if let Some(existing) = state.sessions.get(&wark) {
        UploadSessionResponse {
            wark: existing.wark.clone(),
            missing_chunks: missing_chunks(&existing.received),
        }
    } else {
        let response = UploadSessionResponse {
            wark: wark.clone(),
            missing_chunks: missing_chunks(&session.received),
        };
        state.sessions.insert(wark, session);
        response
    };

    Ok(Json(response))
}

async fn upload_chunk(
    State(state): State<SharedState>,
    Query(query): Query<ChunkQuery>,
    body: Bytes,
) -> HandlerResult<impl IntoResponse> {
    let (file_path, chunk_size, filesize, expected_hash) = {
        let state = state.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "state lock poisoned".to_owned(),
            )
        })?;
        let session = state
            .sessions
            .get(&query.wark)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "unknown wark".to_owned()))?;

        let total_chunks = chunk_count(session.filesize, session.chunk_size);
        if query.index >= total_chunks {
            return Err((StatusCode::BAD_REQUEST, "invalid chunk index".to_owned()));
        }

        if session.received[query.index as usize] {
            return Ok(StatusCode::OK);
        }

        (
            session.file_path.clone(),
            session.chunk_size,
            session.filesize,
            session.hashes[query.index as usize],
        )
    };

    let offset = chunk_offset(query.index, chunk_size);
    let expected_size = filesize.saturating_sub(offset).min(chunk_size);
    if body.len() as u64 > expected_size {
        return Err((
            StatusCode::BAD_REQUEST,
            "chunk larger than expected".to_owned(),
        ));
    }

    if hash_chunk(&body) != expected_hash {
        return Err((StatusCode::BAD_REQUEST, "chunk hash mismatch".to_owned()));
    }

    let write_body = body;
    tokio::task::spawn_blocking(move || -> io::Result<()> {
        let mut file = OpenOptions::new().write(true).open(&file_path)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&write_body)?;
        file.flush()?;
        Ok(())
    })
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?
    .map_err(internal_error)?;

    let mut state = state.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "state lock poisoned".to_owned(),
        )
    })?;
    let session = state
        .sessions
        .get_mut(&query.wark)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "unknown wark".to_owned()))?;
    session.received.set(query.index as usize, true);

    Ok(StatusCode::OK)
}

async fn finalize_upload(
    State(state): State<SharedState>,
    Json(req): Json<FinalizeUpload>,
) -> HandlerResult<Json<UploadSessionResponse>> {
    let state = state.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "state lock poisoned".to_owned(),
        )
    })?;
    let session = state
        .sessions
        .get(&req.wark)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "unknown wark".to_owned()))?;

    Ok(Json(UploadSessionResponse {
        wark: session.wark.clone(),
        missing_chunks: missing_chunks(&session.received),
    }))
}

async fn upload_status(
    State(state): State<SharedState>,
    Path(wark): Path<String>,
) -> HandlerResult<Json<UploadSessionResponse>> {
    let state = state.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "state lock poisoned".to_owned(),
        )
    })?;
    let session = state
        .sessions
        .get(&wark)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "unknown wark".to_owned()))?;

    Ok(Json(UploadSessionResponse {
        wark: session.wark.clone(),
        missing_chunks: missing_chunks(&session.received),
    }))
}

fn internal_error(error: io::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}
