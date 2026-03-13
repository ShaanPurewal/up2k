use std::array::from_fn;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::thread;
use std::time::Duration;

const DETAIL_CHANNEL_CAPACITY: usize = 256;
const DEFAULT_INTERVAL_MS: u64 = 1_000;
const DEFAULT_TRACE_EVERY_N: u64 = 64;
const HISTOGRAM_BOUNDS_US: [u64; 17] = [
    50, 100, 250, 500, 1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 200_000, 500_000,
    1_000_000, 2_000_000, 5_000_000, 10_000_000,
];
const HISTOGRAM_BUCKETS: usize = HISTOGRAM_BOUNDS_US.len() + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstrumentationMode {
    Off,
    Summary,
    Sampled,
}

impl InstrumentationMode {
    fn from_env() -> Self {
        match env::var("UP2K_INSTRUMENTATION")
            .unwrap_or_else(|_| "summary".to_owned())
            .to_ascii_lowercase()
            .as_str()
        {
            "off" => Self::Off,
            "sampled" => Self::Sampled,
            _ => Self::Summary,
        }
    }

    fn summaries_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    fn traces_enabled(self) -> bool {
        matches!(self, Self::Sampled)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MetadataStats {
    pub file_open: Duration,
    pub hash: Duration,
    pub wark: Duration,
    pub filesize: u64,
    pub chunk_size: u64,
    pub chunk_count: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct HandshakeStats {
    pub elapsed: Duration,
    pub missing_chunks: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct FinalizeStats {
    pub elapsed: Duration,
    pub missing_chunks: usize,
    pub completed: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ClientChunkStats {
    pub index: u32,
    pub chunk_size: usize,
    pub inflight_at_start: u64,
    pub prep: Duration,
    pub body_copy: Duration,
    pub send_wait: Duration,
    pub response_decode: Duration,
    pub total: Duration,
    pub success: bool,
}

#[derive(Clone)]
pub struct UploadMetrics {
    inner: Arc<Inner>,
}

pub struct InflightGuard {
    inner: Arc<Inner>,
    inflight_at_start: u64,
}

impl InflightGuard {
    pub fn inflight_at_start(&self) -> u64 {
        self.inflight_at_start
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.inner.current_inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl UploadMetrics {
    pub fn new() -> Self {
        let mode = InstrumentationMode::from_env();
        let interval = Duration::from_millis(
            env::var("UP2K_METRICS_INTERVAL_MS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(DEFAULT_INTERVAL_MS),
        );
        let trace_every_n = env::var("UP2K_TRACE_EVERY_N")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_TRACE_EVERY_N);
        let detail_tx = if mode.traces_enabled() {
            let (tx, rx) = sync_channel::<String>(DETAIL_CHANNEL_CAPACITY);
            thread::spawn(move || {
                while let Ok(line) = rx.recv() {
                    eprintln!("{line}");
                }
            });
            Some(tx)
        } else {
            None
        };

        let metrics = Self {
            inner: Arc::new(Inner {
                mode,
                interval,
                trace_every_n,
                detail_tx,
                trace_sequence: AtomicU64::new(0),
                bytes_uploaded_window: AtomicU64::new(0),
                chunks_uploaded_window: AtomicU64::new(0),
                failures_window: AtomicU64::new(0),
                retries_window: AtomicU64::new(0),
                dropped_traces_window: AtomicU64::new(0),
                current_inflight: AtomicU64::new(0),
                max_inflight_window: AtomicU64::new(0),
                chunk_total: Histogram::new(),
                chunk_prep: Histogram::new(),
                chunk_body_copy: Histogram::new(),
                chunk_send_wait: Histogram::new(),
                chunk_decode: Histogram::new(),
            }),
        };

        metrics.spawn_summary_thread();
        metrics
    }

    pub fn inflight_guard(&self) -> InflightGuard {
        let inflight_at_start = self.inner.current_inflight.fetch_add(1, Ordering::Relaxed) + 1;
        self.inner
            .max_inflight_window
            .fetch_max(inflight_at_start, Ordering::Relaxed);
        InflightGuard {
            inner: Arc::clone(&self.inner),
            inflight_at_start,
        }
    }

    pub fn record_metadata(&self, stats: MetadataStats) {
        if !self.inner.mode.summaries_enabled() {
            return;
        }

        eprintln!("[client-setup]");
        eprintln!(
            "  file: {}, chunk size {}, chunks {}",
            fmt_bytes(stats.filesize),
            fmt_bytes(stats.chunk_size),
            stats.chunk_count
        );
        eprintln!(
            "  metadata: open {}, hash {}, wark {}",
            fmt_duration(stats.file_open),
            fmt_duration(stats.hash),
            fmt_duration(stats.wark)
        );
        if stats.hash.as_micros() > 0 && stats.filesize > 0 {
            let hash_rate = stats.filesize as f64 / stats.hash.as_secs_f64();
            eprintln!("  hash rate: {}/s", fmt_bytes_f64(hash_rate));
        }
    }

    pub fn record_handshake(&self, stats: HandshakeStats) {
        if !self.inner.mode.summaries_enabled() {
            return;
        }

        eprintln!(
            "[client-handshake] took {}, missing chunks {}",
            fmt_duration(stats.elapsed),
            stats.missing_chunks
        );
    }

    pub fn record_finalize(&self, stats: FinalizeStats) {
        if !self.inner.mode.summaries_enabled() {
            return;
        }

        eprintln!(
            "[client-finalize] took {}, missing chunks {}, completed {}",
            fmt_duration(stats.elapsed),
            stats.missing_chunks,
            yes_no(stats.completed)
        );
    }

    pub fn record_retry_pass(&self) {
        if self.inner.mode == InstrumentationMode::Off {
            return;
        }

        self.inner.retries_window.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_chunk(&self, stats: ClientChunkStats) {
        if self.inner.mode == InstrumentationMode::Off {
            return;
        }

        self.inner.chunk_total.record(stats.total);
        self.inner.chunk_prep.record(stats.prep);
        self.inner.chunk_body_copy.record(stats.body_copy);
        self.inner.chunk_send_wait.record(stats.send_wait);
        self.inner.chunk_decode.record(stats.response_decode);

        if stats.success {
            self.inner
                .bytes_uploaded_window
                .fetch_add(stats.chunk_size as u64, Ordering::Relaxed);
            self.inner
                .chunks_uploaded_window
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.failures_window.fetch_add(1, Ordering::Relaxed);
        }

        self.emit_trace(stats);
    }

    pub fn record_upload_complete(&self, elapsed: Duration, wark: &str) {
        if !self.inner.mode.summaries_enabled() {
            return;
        }

        eprintln!(
            "[client-complete] wark {}, total elapsed {}",
            wark,
            fmt_duration(elapsed)
        );
    }

    fn emit_trace(&self, stats: ClientChunkStats) {
        if !self.inner.mode.traces_enabled() {
            return;
        }

        let sequence = self.inner.trace_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        if !sequence.is_multiple_of(self.inner.trace_every_n) {
            return;
        }

        let Some(tx) = &self.inner.detail_tx else {
            return;
        };

        let line = format!(
            "[client-trace] chunk={} size={} inflight={} total={} prep={} copy={} send={} decode={} status={}",
            stats.index,
            fmt_bytes(stats.chunk_size as u64),
            stats.inflight_at_start,
            fmt_duration(stats.total),
            fmt_duration(stats.prep),
            fmt_duration(stats.body_copy),
            fmt_duration(stats.send_wait),
            fmt_duration(stats.response_decode),
            if stats.success { "ok" } else { "err" }
        );

        match tx.try_send(line) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.inner
                    .dropped_traces_window
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    fn spawn_summary_thread(&self) {
        if !self.inner.mode.summaries_enabled() {
            return;
        }

        let inner = Arc::clone(&self.inner);
        thread::spawn(move || {
            loop {
                thread::sleep(inner.interval);
                inner.print_summary();
            }
        });
    }
}

struct Inner {
    mode: InstrumentationMode,
    interval: Duration,
    trace_every_n: u64,
    detail_tx: Option<SyncSender<String>>,
    trace_sequence: AtomicU64,
    bytes_uploaded_window: AtomicU64,
    chunks_uploaded_window: AtomicU64,
    failures_window: AtomicU64,
    retries_window: AtomicU64,
    dropped_traces_window: AtomicU64,
    current_inflight: AtomicU64,
    max_inflight_window: AtomicU64,
    chunk_total: Histogram,
    chunk_prep: Histogram,
    chunk_body_copy: Histogram,
    chunk_send_wait: Histogram,
    chunk_decode: Histogram,
}

impl Inner {
    fn print_summary(&self) {
        let bytes = self.bytes_uploaded_window.swap(0, Ordering::Relaxed);
        let chunks = self.chunks_uploaded_window.swap(0, Ordering::Relaxed);
        let failures = self.failures_window.swap(0, Ordering::Relaxed);
        let retries = self.retries_window.swap(0, Ordering::Relaxed);
        let dropped_traces = self.dropped_traces_window.swap(0, Ordering::Relaxed);
        if bytes == 0 && chunks == 0 && failures == 0 && retries == 0 && dropped_traces == 0 {
            return;
        }

        let current_inflight = self.current_inflight.load(Ordering::Relaxed);
        let max_inflight = self.max_inflight_window.swap(0, Ordering::Relaxed);
        let rate = bytes as f64 / self.interval.as_secs_f64();
        let total = self.chunk_total.snapshot_and_reset();
        let prep = self.chunk_prep.snapshot_and_reset();
        let body_copy = self.chunk_body_copy.snapshot_and_reset();
        let send = self.chunk_send_wait.snapshot_and_reset();
        let decode = self.chunk_decode.snapshot_and_reset();

        eprintln!("[client] {:.1}s window", self.interval.as_secs_f64());
        eprintln!(
            "  throughput: {} chunks, {}, {}/s, inflight {}/{}, failures {}, retries {}, dropped traces {}",
            chunks,
            fmt_bytes(bytes),
            fmt_bytes_f64(rate),
            current_inflight,
            max_inflight,
            failures,
            retries,
            dropped_traces
        );
        print_stage_line("  chunk total", &total);
        eprintln!(
            "  prep/copy: prep {}, copy {}",
            prep.render(),
            body_copy.render()
        );
        eprintln!(
            "  send/decode: send {}, decode {}",
            send.render(),
            decode.render()
        );
    }
}

struct Histogram {
    count: AtomicU64,
    total_us: AtomicU64,
    buckets: [AtomicU64; HISTOGRAM_BUCKETS],
}

impl Histogram {
    fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            total_us: AtomicU64::new(0),
            buckets: from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn record(&self, duration: Duration) {
        let micros = duration.as_micros().min(u128::from(u64::MAX)) as u64;
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total_us.fetch_add(micros, Ordering::Relaxed);

        let index = HISTOGRAM_BOUNDS_US
            .iter()
            .position(|bound| micros <= *bound)
            .unwrap_or(HISTOGRAM_BUCKETS - 1);
        self.buckets[index].fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot_and_reset(&self) -> HistogramSnapshot {
        let count = self.count.swap(0, Ordering::Relaxed);
        let total_us = self.total_us.swap(0, Ordering::Relaxed);
        let buckets = from_fn(|index| self.buckets[index].swap(0, Ordering::Relaxed));
        HistogramSnapshot {
            count,
            total_us,
            buckets,
        }
    }
}

#[derive(Clone, Copy)]
struct HistogramSnapshot {
    count: u64,
    total_us: u64,
    buckets: [u64; HISTOGRAM_BUCKETS],
}

impl HistogramSnapshot {
    fn avg_us(self) -> Option<u64> {
        (self.count > 0).then_some(self.total_us / self.count)
    }

    fn p95_us(self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }

        let target = self.count.saturating_mul(95).div_ceil(100);
        let mut seen = 0_u64;
        for (index, bucket) in self.buckets.iter().enumerate() {
            seen = seen.saturating_add(*bucket);
            if seen >= target {
                return Some(if index < HISTOGRAM_BOUNDS_US.len() {
                    HISTOGRAM_BOUNDS_US[index]
                } else {
                    HISTOGRAM_BOUNDS_US[HISTOGRAM_BOUNDS_US.len() - 1]
                });
            }
        }

        Some(HISTOGRAM_BOUNDS_US[HISTOGRAM_BOUNDS_US.len() - 1])
    }

    fn render(self) -> String {
        match (self.avg_us(), self.p95_us()) {
            (Some(avg), Some(p95)) => format!("avg {}, p95 {}", fmt_micros(avg), fmt_micros(p95)),
            _ => "n/a".to_owned(),
        }
    }
}

fn print_stage_line(label: &str, snapshot: &HistogramSnapshot) {
    eprintln!("{label}: {}", snapshot.render());
}

fn fmt_duration(duration: Duration) -> String {
    fmt_micros(duration.as_micros().min(u128::from(u64::MAX)) as u64)
}

fn fmt_micros(micros: u64) -> String {
    if micros < 1_000 {
        format!("{micros} us")
    } else if micros < 1_000_000 {
        format!("{:.1} ms", micros as f64 / 1_000.0)
    } else {
        format!("{:.2} s", micros as f64 / 1_000_000.0)
    }
}

fn fmt_bytes(bytes: u64) -> String {
    fmt_bytes_f64(bytes as f64)
}

fn fmt_bytes_f64(bytes: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    if bytes >= GIB {
        format!("{:.2} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{bytes:.0} B")
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
