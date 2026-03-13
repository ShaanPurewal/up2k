use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Query, Request, State},
    http::StatusCode,
    routing::{get, post},
};
use bitvec::{bitvec, prelude::BitVec};
mod metrics;
use metrics::{ChunkRequestStats, ControlRouteStats, ServerMetrics};
use protocol::{
    ChunkHash, ChunkUploadProgress, FinalizeUpload, UploadHandshake, UploadSessionResponse,
    compute_wark, hash_chunk,
};
use serde::Deserialize;

const STORAGE_DIR: &str = "uploads";
const SALT: &str = "test_salt";

type SharedState = Arc<Mutex<ServerState>>;
type HandlerResult<T> = Result<T, (StatusCode, String)>;

#[derive(Clone)]
struct AppState {
    state: SharedState,
    metrics: ServerMetrics,
}

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
    started_at: Instant,
    uploaded_bytes: u64,
    uploaded_chunks: u32,
    last_completed_index: Option<u32>,
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

#[derive(Debug, Deserialize)]
struct StatusQuery {
    wark: String,
}

#[derive(Debug, Clone, Copy, Default)]
struct WriteTimings {
    queue_delay: Duration,
    open: Duration,
    seek: Duration,
    write: Duration,
    flush: Duration,
    total: Duration,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fs::create_dir_all(STORAGE_DIR)?;

    let app_state = AppState {
        state: Arc::new(Mutex::new(ServerState::default())),
        metrics: ServerMetrics::new(),
    };
    let app = Router::new()
        .route("/upload/handshake", post(upload_handshake))
        .route("/upload/chunk", post(upload_chunk))
        .route("/upload/finalize", post(finalize_upload))
        .route("/upload/status", get(upload_status))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("listening on http://0.0.0.0:3000");
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

fn wark_file_name(wark: &str) -> String {
    let mut file_name = String::with_capacity((wark.len() * 2) + ".upload".len());
    for byte in wark.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut file_name, "{byte:02x}");
    }
    file_name.push_str(".upload");
    file_name
}

fn chunk_progress(session: &UploadSession, index: u32) -> ChunkUploadProgress {
    let total_chunks = chunk_count(session.filesize, session.chunk_size);
    let elapsed_secs = session.started_at.elapsed().as_secs_f64();
    let percent_complete = if session.filesize == 0 {
        100.0
    } else {
        (session.uploaded_bytes as f64 / session.filesize as f64) * 100.0
    };
    let throughput_bytes_per_sec = if elapsed_secs > 0.0 {
        session.uploaded_bytes as f64 / elapsed_secs
    } else {
        0.0
    };
    let remaining_bytes = session.filesize.saturating_sub(session.uploaded_bytes);
    let eta_seconds = if remaining_bytes == 0 {
        0.0
    } else if throughput_bytes_per_sec > 0.0 {
        remaining_bytes as f64 / throughput_bytes_per_sec
    } else {
        0.0
    };

    ChunkUploadProgress {
        wark: session.wark.clone(),
        index,
        uploaded_chunks: session.uploaded_chunks,
        total_chunks,
        uploaded_bytes: session.uploaded_bytes,
        total_bytes: session.filesize,
        percent_complete,
        throughput_bytes_per_sec,
        eta_seconds,
    }
}

async fn upload_handshake(
    State(app): State<AppState>,
    Json(req): Json<UploadHandshake>,
) -> HandlerResult<Json<UploadSessionResponse>> {
    let started = Instant::now();
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
        let state = app.state.lock().map_err(|_| state_lock_error())?;
        if let Some(session) = state.sessions.get(&wark) {
            let response = UploadSessionResponse {
                wark: session.wark.clone(),
                missing_chunks: missing_chunks(&session.received),
            };
            app.metrics.record_control_route(ControlRouteStats {
                route: "handshake",
                elapsed: started.elapsed(),
            });
            return Ok(Json(response));
        }
    }

    let file_path = PathBuf::from(STORAGE_DIR).join(wark_file_name(&wark));
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
        started_at: Instant::now(),
        uploaded_bytes: 0,
        uploaded_chunks: 0,
        last_completed_index: None,
    };

    let mut state = app.state.lock().map_err(|_| state_lock_error())?;
    let mut created = false;
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
        created = true;
        response
    };
    drop(state);

    if created {
        app.metrics.record_session_created();
    }
    app.metrics.record_control_route(ControlRouteStats {
        route: "handshake",
        elapsed: started.elapsed(),
    });

    Ok(Json(response))
}

async fn upload_chunk(
    State(app): State<AppState>,
    Query(query): Query<ChunkQuery>,
    request: Request,
) -> HandlerResult<Json<ChunkUploadProgress>> {
    let handler_started = Instant::now();
    let mut lock_wait_total = Duration::ZERO;
    let mut lock_hold_total = Duration::ZERO;
    let mut body_read_elapsed = Duration::ZERO;
    let mut hash_verify_elapsed = Duration::ZERO;
    let mut write_timings = WriteTimings::default();

    let first_lock_wait_started = Instant::now();
    let (
        file_path,
        chunk_size,
        filesize,
        expected_hash,
        duplicate_progress,
        first_lock_wait,
        first_lock_hold,
    ) = {
        let state = app.state.lock().map_err(|_| state_lock_error())?;
        let first_lock_wait = first_lock_wait_started.elapsed();
        let hold_started = Instant::now();
        let session = state
            .sessions
            .get(&query.wark)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "unknown wark".to_owned()))?;

        let total_chunks = chunk_count(session.filesize, session.chunk_size);
        if query.index >= total_chunks {
            return Err((StatusCode::BAD_REQUEST, "invalid chunk index".to_owned()));
        }

        let duplicate_progress = session
            .received
            .get(query.index as usize)
            .as_deref()
            .copied()
            .unwrap_or(false)
            .then(|| chunk_progress(session, query.index));

        (
            session.file_path.clone(),
            session.chunk_size,
            session.filesize,
            session.hashes[query.index as usize],
            duplicate_progress,
            first_lock_wait,
            hold_started.elapsed(),
        )
    };
    lock_wait_total += first_lock_wait;
    lock_hold_total += first_lock_hold;

    let offset = chunk_offset(query.index, chunk_size);
    let expected_size = filesize.saturating_sub(offset).min(chunk_size);
    if let Some(progress) = duplicate_progress {
        app.metrics.record_chunk(ChunkRequestStats {
            index: query.index,
            chunk_size: expected_size,
            lock_wait: lock_wait_total,
            lock_hold: lock_hold_total,
            body_read: body_read_elapsed,
            hash_verify: hash_verify_elapsed,
            queue_delay: write_timings.queue_delay,
            open: write_timings.open,
            seek: write_timings.seek,
            write: write_timings.write,
            flush: write_timings.flush,
            storage_total: write_timings.total,
            handler_total: handler_started.elapsed(),
            duplicate: true,
            sequential: None,
            stored: false,
            error: false,
        });
        return Ok(Json(progress));
    }

    let body_limit = usize::try_from(expected_size).map_err(|_| {
        app.metrics.record_chunk(ChunkRequestStats {
            index: query.index,
            chunk_size: expected_size,
            lock_wait: lock_wait_total,
            lock_hold: lock_hold_total,
            body_read: body_read_elapsed,
            hash_verify: hash_verify_elapsed,
            queue_delay: write_timings.queue_delay,
            open: write_timings.open,
            seek: write_timings.seek,
            write: write_timings.write,
            flush: write_timings.flush,
            storage_total: write_timings.total,
            handler_total: handler_started.elapsed(),
            duplicate: false,
            sequential: None,
            stored: false,
            error: true,
        });
        (StatusCode::PAYLOAD_TOO_LARGE, "chunk too large".to_owned())
    })?;
    let body_read_started = Instant::now();
    let body = to_bytes(request.into_body(), body_limit)
        .await
        .map_err(|_| {
            body_read_elapsed = body_read_started.elapsed();
            app.metrics.record_chunk(ChunkRequestStats {
                index: query.index,
                chunk_size: expected_size,
                lock_wait: lock_wait_total,
                lock_hold: lock_hold_total,
                body_read: body_read_elapsed,
                hash_verify: hash_verify_elapsed,
                queue_delay: write_timings.queue_delay,
                open: write_timings.open,
                seek: write_timings.seek,
                write: write_timings.write,
                flush: write_timings.flush,
                storage_total: write_timings.total,
                handler_total: handler_started.elapsed(),
                duplicate: false,
                sequential: None,
                stored: false,
                error: true,
            });
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                "chunk larger than expected".to_owned(),
            )
        })?;
    body_read_elapsed = body_read_started.elapsed();

    if body.len() as u64 != expected_size {
        app.metrics.record_chunk(ChunkRequestStats {
            index: query.index,
            chunk_size: expected_size,
            lock_wait: lock_wait_total,
            lock_hold: lock_hold_total,
            body_read: body_read_elapsed,
            hash_verify: hash_verify_elapsed,
            queue_delay: write_timings.queue_delay,
            open: write_timings.open,
            seek: write_timings.seek,
            write: write_timings.write,
            flush: write_timings.flush,
            storage_total: write_timings.total,
            handler_total: handler_started.elapsed(),
            duplicate: false,
            sequential: None,
            stored: false,
            error: true,
        });
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "chunk size mismatch: expected {}, got {}",
                expected_size,
                body.len()
            ),
        ));
    }

    let hash_started = Instant::now();
    let actual_hash = hash_chunk(&body);
    hash_verify_elapsed = hash_started.elapsed();
    if actual_hash != expected_hash {
        app.metrics.record_chunk(ChunkRequestStats {
            index: query.index,
            chunk_size: expected_size,
            lock_wait: lock_wait_total,
            lock_hold: lock_hold_total,
            body_read: body_read_elapsed,
            hash_verify: hash_verify_elapsed,
            queue_delay: write_timings.queue_delay,
            open: write_timings.open,
            seek: write_timings.seek,
            write: write_timings.write,
            flush: write_timings.flush,
            storage_total: write_timings.total,
            handler_total: handler_started.elapsed(),
            duplicate: false,
            sequential: None,
            stored: false,
            error: true,
        });
        return Err((StatusCode::BAD_REQUEST, "chunk hash mismatch".to_owned()));
    }

    let uploaded_len = body.len() as u64;
    let write_body = body;
    let queued_at = Instant::now();
    let metrics = app.metrics.clone();
    write_timings = match tokio::task::spawn_blocking(move || -> io::Result<WriteTimings> {
        let _guard = metrics.blocking_write_guard();
        let queue_delay = queued_at.elapsed();

        let open_started = Instant::now();
        let mut file = OpenOptions::new().write(true).open(&file_path)?;
        let open = open_started.elapsed();

        let seek_started = Instant::now();
        file.seek(SeekFrom::Start(offset))?;
        let seek = seek_started.elapsed();

        let write_started = Instant::now();
        file.write_all(&write_body)?;
        let write = write_started.elapsed();

        let flush_started = Instant::now();
        file.flush()?;
        let flush = flush_started.elapsed();

        Ok(WriteTimings {
            queue_delay,
            open,
            seek,
            write,
            flush,
            total: queue_delay + open + seek + write + flush,
        })
    })
    .await
    {
        Ok(Ok(timings)) => timings,
        Ok(Err(error)) => {
            app.metrics.record_chunk(ChunkRequestStats {
                index: query.index,
                chunk_size: expected_size,
                lock_wait: lock_wait_total,
                lock_hold: lock_hold_total,
                body_read: body_read_elapsed,
                hash_verify: hash_verify_elapsed,
                queue_delay: write_timings.queue_delay,
                open: write_timings.open,
                seek: write_timings.seek,
                write: write_timings.write,
                flush: write_timings.flush,
                storage_total: queued_at.elapsed(),
                handler_total: handler_started.elapsed(),
                duplicate: false,
                sequential: None,
                stored: false,
                error: true,
            });
            return Err(internal_error(error));
        }
        Err(error) => {
            app.metrics.record_chunk(ChunkRequestStats {
                index: query.index,
                chunk_size: expected_size,
                lock_wait: lock_wait_total,
                lock_hold: lock_hold_total,
                body_read: body_read_elapsed,
                hash_verify: hash_verify_elapsed,
                queue_delay: write_timings.queue_delay,
                open: write_timings.open,
                seek: write_timings.seek,
                write: write_timings.write,
                flush: write_timings.flush,
                storage_total: queued_at.elapsed(),
                handler_total: handler_started.elapsed(),
                duplicate: false,
                sequential: None,
                stored: false,
                error: true,
            });
            return Err((StatusCode::INTERNAL_SERVER_ERROR, error.to_string()));
        }
    };

    let second_lock_wait_started = Instant::now();
    let mut state = app.state.lock().map_err(|_| state_lock_error())?;
    let second_lock_wait = second_lock_wait_started.elapsed();
    let second_lock_hold_started = Instant::now();
    let session = state
        .sessions
        .get_mut(&query.wark)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "unknown wark".to_owned()))?;
    let mut stored = false;
    let mut duplicate = false;
    let mut sequential = None;
    if !session.received[query.index as usize] {
        stored = true;
        session.received.set(query.index as usize, true);
        session.uploaded_bytes = session.uploaded_bytes.saturating_add(uploaded_len);
        session.uploaded_chunks = session.uploaded_chunks.saturating_add(1);
        sequential = Some(
            session
                .last_completed_index
                .map(|last| query.index == last.saturating_add(1))
                .unwrap_or(query.index == 0),
        );
        session.last_completed_index = Some(query.index);
    } else {
        duplicate = true;
    }
    let progress = chunk_progress(session, query.index);
    let second_lock_hold = second_lock_hold_started.elapsed();
    drop(state);

    lock_wait_total += second_lock_wait;
    lock_hold_total += second_lock_hold;
    app.metrics.record_chunk(ChunkRequestStats {
        index: query.index,
        chunk_size: uploaded_len,
        lock_wait: lock_wait_total,
        lock_hold: lock_hold_total,
        body_read: body_read_elapsed,
        hash_verify: hash_verify_elapsed,
        queue_delay: write_timings.queue_delay,
        open: write_timings.open,
        seek: write_timings.seek,
        write: write_timings.write,
        flush: write_timings.flush,
        storage_total: write_timings.total,
        handler_total: handler_started.elapsed(),
        duplicate,
        sequential,
        stored,
        error: false,
    });

    Ok(Json(progress))
}

async fn finalize_upload(
    State(app): State<AppState>,
    Json(req): Json<FinalizeUpload>,
) -> HandlerResult<Json<UploadSessionResponse>> {
    let started = Instant::now();
    let state = app.state.lock().map_err(|_| state_lock_error())?;
    let session = state
        .sessions
        .get(&req.wark)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "unknown wark".to_owned()))?;
    let response = UploadSessionResponse {
        wark: session.wark.clone(),
        missing_chunks: missing_chunks(&session.received),
    };
    drop(state);
    app.metrics.record_control_route(ControlRouteStats {
        route: "finalize",
        elapsed: started.elapsed(),
    });

    Ok(Json(response))
}

async fn upload_status(
    State(app): State<AppState>,
    Query(query): Query<StatusQuery>,
) -> HandlerResult<Json<UploadSessionResponse>> {
    let started = Instant::now();
    let state = app.state.lock().map_err(|_| state_lock_error())?;
    let session = state
        .sessions
        .get(&query.wark)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "unknown wark".to_owned()))?;
    let response = UploadSessionResponse {
        wark: session.wark.clone(),
        missing_chunks: missing_chunks(&session.received),
    };
    drop(state);
    app.metrics.record_control_route(ControlRouteStats {
        route: "status",
        elapsed: started.elapsed(),
    });

    Ok(Json(response))
}

fn internal_error(error: io::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn state_lock_error() -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "state lock poisoned".to_owned(),
    )
}
