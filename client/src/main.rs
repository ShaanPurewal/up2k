use std::{
    env,
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use memmap2::{Mmap, MmapOptions};
use protocol::{
    FinalizeUpload, UploadHandshake, UploadSessionResponse, compute_chunk_size, compute_wark,
    hash_chunk,
};
use rayon::prelude::*;
use reqwest::Client;
use tokio::task::JoinSet;

const SERVER_URL: &str = "http://127.0.0.1:3000";
const SALT: &str = "test_salt";

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, BoxError>;

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

fn build_metadata(path: &Path) -> Result<(UploadHandshake, String)> {
    let file = File::open(path)?;
    let filesize = file.metadata()?.len();
    let chunk_size = compute_chunk_size(filesize);
    let filename = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no filename"))?
        .to_string_lossy()
        .into_owned();

    let hashes = if filesize == 0 {
        Vec::new()
    } else {
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        mmap.par_chunks(chunk_size as usize)
            .map(hash_chunk)
            .collect()
    };

    let wark = compute_wark(SALT, filesize, &hashes);
    let handshake = UploadHandshake {
        filename,
        filesize,
        chunk_size,
        hashes,
    };

    Ok((handshake, wark))
}

async fn handshake(
    client: &Client,
    handshake: &UploadHandshake,
    wark: &str,
) -> Result<UploadSessionResponse> {
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

    Ok(session)
}

async fn upload_chunk(
    client: &Client,
    handshake: &UploadHandshake,
    wark: &str,
    mmap: &Mmap,
    index: u32,
) -> Result<()> {
    let chunk_count = u32::try_from(handshake.hashes.len())
        .map_err(|_| io::Error::other("chunk count exceeds u32"))?;
    if index >= chunk_count {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid chunk index").into());
    }

    let offset = u64::from(index)
        .checked_mul(handshake.chunk_size)
        .ok_or_else(|| io::Error::other("chunk offset overflow"))?;
    let chunk_end = offset
        .saturating_add(handshake.chunk_size)
        .min(handshake.filesize);
    let start = usize::try_from(offset).map_err(|_| io::Error::other("offset too large"))?;
    let end = usize::try_from(chunk_end).map_err(|_| io::Error::other("chunk end too large"))?;
    let chunk = &mmap[start..end];
    let index_text = index.to_string();

    client
        .post(endpoint("/upload/chunk"))
        .query(&[("wark", wark), ("index", index_text.as_str())])
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(chunk.to_vec())
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

async fn upload_chunks(
    client: &Client,
    handshake: &UploadHandshake,
    wark: &str,
    mmap: Arc<Mmap>,
    missing_chunks: Vec<u32>,
) -> Result<()> {
    if missing_chunks.is_empty() {
        return Ok(());
    }

    let mut tasks = JoinSet::new();
    for index in missing_chunks {
        let client = client.clone();
        let handshake = handshake.to_owned();
        let wark = wark.to_owned();
        let mmap = Arc::clone(&mmap);

        tasks.spawn(async move { upload_chunk(&client, &handshake, &wark, &mmap, index).await });
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                eprintln!("chunk upload failed: {error}");
            }
            Err(error) => {
                eprintln!("chunk upload task failed: {error}");
            }
        }
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
    let (handshake_request, wark) = build_metadata(&path)?;
    let client = Client::new();
    let mut missing_chunks = handshake(&client, &handshake_request, &wark)
        .await?
        .missing_chunks;
    let mut previous_missing_count = usize::MAX;
    let mmap = if handshake_request.filesize == 0 {
        None
    } else {
        let file = File::open(&path)?;
        Some(Arc::new(unsafe { MmapOptions::new().map(&file)? }))
    };

    loop {
        if !missing_chunks.is_empty() {
            let mmap = mmap
                .as_ref()
                .ok_or_else(|| io::Error::other("server reported missing chunks for empty file"))?;
            upload_chunks(
                &client,
                &handshake_request,
                &wark,
                Arc::clone(mmap),
                missing_chunks,
            )
            .await?;
        }

        let session = finalize_upload(&client, &wark).await?;
        if session.missing_chunks.is_empty() {
            println!("upload complete: {wark}");
            return Ok(());
        }

        if session.missing_chunks.len() >= previous_missing_count {
            return Err(io::Error::other(format!(
                "upload stopped making progress, still missing chunks: {:?}",
                session.missing_chunks
            ))
            .into());
        }

        eprintln!(
            "finalize reported {} missing chunks, retrying because progress was made",
            session.missing_chunks.len(),
        );
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
