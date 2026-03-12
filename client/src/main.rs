use std::error::Error;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use memmap2::Mmap;
use protocol::{
    chunk_count, chunk_range, compute_wark, sha256_bytes, ChunkUpload, ChunkUploadResponse,
    FinalizeResponse, FinalizeUpload, UploadHandshake, UploadSessionResponse,
};
use reqwest::Client;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Upload {
        path: PathBuf,
        server: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Upload { path, server } => upload_file(&path, &server).await?,
    }

    Ok(())
}

async fn upload_file(path: &Path, server: &str) -> Result<(), Box<dyn Error>> {
    let overall_start = Instant::now();
    println!("client: opening {}", path.display());
    let file = File::open(path)?;
    let filesize = file.metadata()?.len();
    let chunk_size = protocol::select_chunk_size(filesize);
    let total_chunks = chunk_count(filesize, chunk_size);
    println!(
        "client: file size={} bytes chunk_size={} bytes chunks={}",
        filesize, chunk_size, total_chunks
    );

    println!("client: hashing chunks");
    let hash_start = Instant::now();
    let mmap = unsafe { Mmap::map(&file)? };
    let hashes = hash_chunks(&mmap, filesize, chunk_size);
    let local_wark = compute_wark(filesize, &hashes);
    let hash_elapsed = hash_start.elapsed();
    println!(
        "client: hashing complete wark={} chunks={} elapsed={} avg_hash_rate={}",
        short_wark(&local_wark),
        hashes.len(),
        format_duration(hash_elapsed),
        format_rate(filesize, hash_elapsed)
    );

    let handshake = UploadHandshake {
        filename: file_name(path),
        filesize,
        chunk_size,
        hashes,
    };

    let client = Client::new();
    let base_url = server.trim_end_matches('/');
    println!("client: sending handshake to {base_url}");
    let handshake_start = Instant::now();
    let session = post_json::<_, UploadSessionResponse>(
        &client,
        &format!("{base_url}/upload/handshake"),
        &handshake,
    )
    .await?;
    println!(
        "client: handshake complete wark={} elapsed={}",
        short_wark(&session.wark),
        format_duration(handshake_start.elapsed())
    );

    if session.wark != local_wark {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "server returned unexpected wark: expected {}, got {}",
                local_wark, session.wark
            ),
        )
        .into());
    }

    let missing_bytes = chunk_indexes_len(filesize, chunk_size, &session.missing_chunks);
    let present_bytes = filesize.saturating_sub(missing_bytes);
    let present_percent = format_percent(present_bytes, filesize);
    if session.missing_chunks.is_empty() {
        println!(
            "client: upload already complete on server, progress={} complete_bytes={}/{}",
            present_percent,
            format_bytes(present_bytes),
            format_bytes(filesize)
        );
    } else if session.missing_chunks.len() as u32 == total_chunks {
        println!(
            "client: starting fresh upload, {} chunks need upload progress={} uploaded={}/{}",
            session.missing_chunks.len(),
            present_percent,
            format_bytes(present_bytes),
            format_bytes(filesize)
        );
    } else {
        println!(
            "client: resuming upload, {} of {} chunks still missing progress={} uploaded={}/{}",
            session.missing_chunks.len(),
            total_chunks,
            present_percent,
            format_bytes(present_bytes),
            format_bytes(filesize)
        );
    }

    upload_missing_chunks(
        &client,
        base_url,
        &session.wark,
        chunk_size,
        filesize,
        &mmap,
        total_chunks,
        session.missing_chunks,
    )
    .await?;

    println!("client: sending finalize for {}", short_wark(&session.wark));
    let finalize = post_json::<_, FinalizeResponse>(
        &client,
        &format!("{base_url}/upload/finalize"),
        &FinalizeUpload {
            wark: session.wark.clone(),
        },
    )
    .await?;

    if !finalize.complete {
        eprintln!(
            "client: finalize incomplete, still missing {:?}",
            finalize.missing_chunks
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "upload incomplete, missing chunks: {:?}",
                finalize.missing_chunks
            ),
        )
        .into());
    }

    let overall_elapsed = overall_start.elapsed();
    println!(
        "client: finalize complete, upload finished for {} as {} total_elapsed={} effective_rate={}",
        path.display(),
        session.wark,
        format_duration(overall_elapsed),
        format_rate(filesize, overall_elapsed)
    );
    Ok(())
}

async fn upload_missing_chunks(
    client: &Client,
    base_url: &str,
    wark: &str,
    chunk_size: u64,
    filesize: u64,
    mmap: &Mmap,
    total_chunks: u32,
    missing_chunks: Vec<u32>,
) -> Result<(), Box<dyn Error>> {
    if missing_chunks.is_empty() {
        println!("client: skipping chunk upload stage");
        return Ok(());
    }

    let semaphore = Arc::new(Semaphore::new(8));
    let mut uploads = JoinSet::new();
    let upload_count = missing_chunks.len();
    let planned_bytes = chunk_indexes_len(filesize, chunk_size, &missing_chunks);
    let already_present_bytes = filesize.saturating_sub(planned_bytes);
    let upload_start = Instant::now();

    for index in missing_chunks {
        let permit = semaphore.clone().acquire_owned().await?;
        let (start, end) = chunk_range(filesize, chunk_size, index).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("chunk index {index} is out of range"),
            )
        })?;
        let data = mmap[start..end].to_vec();
        let chunk_len = data.len() as u64;
        let url = format!("{base_url}/upload/chunk");
        let client = client.clone();
        let wark = wark.to_owned();

        uploads.spawn(async move {
            let _permit = permit;
            let request = ChunkUpload { wark, index, data };
            let response = client.post(&url).json(&request).send().await.map_err(to_io)?;
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_else(|_| String::new());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("chunk {index} failed with {status}: {body}"),
                ));
            }
            let body = response
                .json::<ChunkUploadResponse>()
                .await
                .map_err(to_io)?;
            Ok::<(u32, u64, ChunkUploadResponse), std::io::Error>((index, chunk_len, body))
        });
    }

    println!(
        "client: uploading {} missing chunks with concurrency=8 remaining={} already_present={}",
        upload_count,
        format_bytes(planned_bytes),
        format_bytes(already_present_bytes)
    );
    let mut completed = 0_usize;
    let mut completed_bytes = 0_u64;
    let mut duplicate_chunks = 0_usize;
    while let Some(result) = uploads.join_next().await {
        let (index, chunk_len, response) = result.map_err(to_io)??;
        completed += 1;
        completed_bytes += chunk_len;
        if response.duplicate {
            duplicate_chunks += 1;
        }
        let elapsed = upload_start.elapsed();
        let total_completed_bytes = already_present_bytes.saturating_add(completed_bytes);
        let avg_rate = format_rate(completed_bytes, elapsed);
        let percent = format_percent(total_completed_bytes, filesize);
        let eta = format_eta(
            planned_bytes.saturating_sub(completed_bytes),
            completed_bytes,
            elapsed,
        );
        if response.duplicate {
            println!(
                "client: chunk {index} already present progress={} bytes={}/{} uploaded_chunks={}/{} avg_rate={} eta={}",
                percent,
                format_bytes(total_completed_bytes),
                format_bytes(filesize),
                completed,
                upload_count,
                avg_rate,
                eta
            );
        } else {
            println!(
                "client: chunk {index} uploaded progress={} bytes={}/{} uploaded_chunks={}/{} total_chunks={} avg_rate={} eta={}",
                percent,
                format_bytes(total_completed_bytes),
                format_bytes(filesize),
                completed,
                upload_count,
                total_chunks,
                avg_rate,
                eta
            );
        }
    }

    let upload_elapsed = upload_start.elapsed();
    println!(
        "client: chunk upload stage complete elapsed={} avg_rate={} duplicate_chunks={} transferred={}",
        format_duration(upload_elapsed),
        format_rate(planned_bytes, upload_elapsed),
        duplicate_chunks,
        format_bytes(planned_bytes)
    );
    Ok(())
}

async fn post_json<T, R>(client: &Client, url: &str, body: &T) -> Result<R, Box<dyn Error>>
where
    T: serde::Serialize + ?Sized,
    R: serde::de::DeserializeOwned,
{
    let response = client.post(url).json(body).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_else(|_| String::new());
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("request to {url} failed with {status}: {text}"),
        )
        .into());
    }

    Ok(response.json::<R>().await?)
}

fn hash_chunks(mmap: &Mmap, filesize: u64, chunk_size: u64) -> Vec<[u8; 32]> {
    let mut hashes = Vec::new();
    let mut index = 0_u32;

    while let Some((start, end)) = chunk_range(filesize, chunk_size, index) {
        hashes.push(sha256_bytes(&mmap[start..end]));
        index += 1;
    }

    hashes
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn chunk_indexes_len(filesize: u64, chunk_size: u64, indexes: &[u32]) -> u64 {
    indexes
        .iter()
        .filter_map(|&index| protocol::chunk_len(filesize, chunk_size, index))
        .sum()
}

fn short_wark(wark: &str) -> &str {
    let end = wark.len().min(12);
    &wark[..end]
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

fn format_eta(remaining_bytes: u64, completed_bytes: u64, elapsed: Duration) -> String {
    let seconds = elapsed.as_secs_f64();
    if remaining_bytes == 0 {
        return "0.00s".to_owned();
    }
    if completed_bytes == 0 || seconds <= f64::EPSILON {
        return "n/a".to_owned();
    }

    let bytes_per_second = completed_bytes as f64 / seconds;
    if bytes_per_second <= f64::EPSILON {
        return "n/a".to_owned();
    }

    format_duration(Duration::from_secs_f64(
        remaining_bytes as f64 / bytes_per_second,
    ))
}

fn to_io<E>(error: E) -> std::io::Error
where
    E: Error + Send + Sync + 'static,
{
    std::io::Error::new(std::io::ErrorKind::Other, error)
}
