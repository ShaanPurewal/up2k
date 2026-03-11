use std::error::Error;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use memmap2::Mmap;
use protocol::{
    chunk_range, compute_wark, sha256_bytes, ChunkUpload, FinalizeResponse, FinalizeUpload,
    UploadHandshake, UploadSessionResponse,
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
    let file = File::open(path)?;
    let filesize = file.metadata()?.len();
    let chunk_size = protocol::select_chunk_size(filesize);
    let mmap = unsafe { Mmap::map(&file)? };
    let hashes = hash_chunks(&mmap, filesize, chunk_size);
    let local_wark = compute_wark(filesize, &hashes);

    let handshake = UploadHandshake {
        filename: file_name(path),
        filesize,
        chunk_size,
        hashes,
    };

    let client = Client::new();
    let base_url = server.trim_end_matches('/');
    let session = post_json::<_, UploadSessionResponse>(
        &client,
        &format!("{base_url}/upload/handshake"),
        &handshake,
    )
    .await?;

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

    upload_missing_chunks(
        &client,
        base_url,
        &session.wark,
        chunk_size,
        filesize,
        &mmap,
        session.missing_chunks,
    )
    .await?;

    let finalize = post_json::<_, FinalizeResponse>(
        &client,
        &format!("{base_url}/upload/finalize"),
        &FinalizeUpload {
            wark: session.wark.clone(),
        },
    )
    .await?;

    if !finalize.complete {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "upload incomplete, missing chunks: {:?}",
                finalize.missing_chunks
            ),
        )
        .into());
    }

    println!("uploaded {} as {}", path.display(), session.wark);
    Ok(())
}

async fn upload_missing_chunks(
    client: &Client,
    base_url: &str,
    wark: &str,
    chunk_size: u64,
    filesize: u64,
    mmap: &Mmap,
    missing_chunks: Vec<u32>,
) -> Result<(), Box<dyn Error>> {
    let semaphore = Arc::new(Semaphore::new(8));
    let mut uploads = JoinSet::new();

    for index in missing_chunks {
        let permit = semaphore.clone().acquire_owned().await?;
        let (start, end) = chunk_range(filesize, chunk_size, index).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("chunk index {index} is out of range"),
            )
        })?;
        let data = mmap[start..end].to_vec();
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
            Ok::<(), std::io::Error>(())
        });
    }

    while let Some(result) = uploads.join_next().await {
        result.map_err(to_io)??;
    }

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

fn to_io<E>(error: E) -> std::io::Error
where
    E: Error + Send + Sync + 'static,
{
    std::io::Error::new(std::io::ErrorKind::Other, error)
}
