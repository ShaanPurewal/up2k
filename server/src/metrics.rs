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

#[derive(Clone)]
pub struct ServerMetrics {
    inner: Arc<Inner>,
}

pub struct BlockingWriteGuard {
    inner: Arc<Inner>,
}

impl Drop for BlockingWriteGuard {
    fn drop(&mut self) {
        self.inner
            .current_blocking_writes
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ControlRouteStats {
    pub route: &'static str,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct ChunkRequestStats {
    pub index: u32,
    pub chunk_size: u64,
    pub lock_wait: Duration,
    pub lock_hold: Duration,
    pub body_read: Duration,
    pub hash_verify: Duration,
    pub queue_delay: Duration,
    pub open: Duration,
    pub seek: Duration,
    pub write: Duration,
    pub flush: Duration,
    pub storage_total: Duration,
    pub handler_total: Duration,
    pub duplicate: bool,
    pub sequential: Option<bool>,
    pub stored: bool,
    pub error: bool,
}

impl ServerMetrics {
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
                active_sessions: AtomicU64::new(0),
                bytes_written_window: AtomicU64::new(0),
                chunks_written_window: AtomicU64::new(0),
                failures_window: AtomicU64::new(0),
                duplicates_window: AtomicU64::new(0),
                sequential_window: AtomicU64::new(0),
                out_of_order_window: AtomicU64::new(0),
                dropped_traces_window: AtomicU64::new(0),
                current_blocking_writes: AtomicU64::new(0),
                max_blocking_writes_window: AtomicU64::new(0),
                handler_total: Histogram::new(),
                lock_wait: Histogram::new(),
                lock_hold: Histogram::new(),
                body_read: Histogram::new(),
                hash_verify: Histogram::new(),
                queue_delay: Histogram::new(),
                storage_total: Histogram::new(),
                open: Histogram::new(),
                seek: Histogram::new(),
                write: Histogram::new(),
                flush: Histogram::new(),
            }),
        };

        metrics.spawn_summary_thread();
        metrics
    }

    pub fn record_session_created(&self) {
        if self.inner.mode == InstrumentationMode::Off {
            return;
        }

        self.inner.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_control_route(&self, stats: ControlRouteStats) {
        if !self.inner.mode.summaries_enabled() {
            return;
        }

        eprintln!(
            "[server-{}] took {}",
            stats.route,
            fmt_duration(stats.elapsed)
        );
    }

    pub fn blocking_write_guard(&self) -> BlockingWriteGuard {
        let running = self
            .inner
            .current_blocking_writes
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        self.inner
            .max_blocking_writes_window
            .fetch_max(running, Ordering::Relaxed);
        BlockingWriteGuard {
            inner: Arc::clone(&self.inner),
        }
    }

    pub fn record_chunk(&self, stats: ChunkRequestStats) {
        if self.inner.mode == InstrumentationMode::Off {
            return;
        }

        self.inner.handler_total.record(stats.handler_total);
        self.inner.lock_wait.record(stats.lock_wait);
        self.inner.lock_hold.record(stats.lock_hold);
        self.inner.body_read.record(stats.body_read);
        self.inner.hash_verify.record(stats.hash_verify);
        self.inner.queue_delay.record(stats.queue_delay);
        self.inner.storage_total.record(stats.storage_total);
        self.inner.open.record(stats.open);
        self.inner.seek.record(stats.seek);
        self.inner.write.record(stats.write);
        self.inner.flush.record(stats.flush);

        if stats.stored {
            self.inner
                .bytes_written_window
                .fetch_add(stats.chunk_size, Ordering::Relaxed);
            self.inner
                .chunks_written_window
                .fetch_add(1, Ordering::Relaxed);
        }

        if stats.error {
            self.inner.failures_window.fetch_add(1, Ordering::Relaxed);
        }

        if stats.duplicate {
            self.inner.duplicates_window.fetch_add(1, Ordering::Relaxed);
        }

        if let Some(sequential) = stats.sequential {
            if sequential {
                self.inner.sequential_window.fetch_add(1, Ordering::Relaxed);
            } else {
                self.inner
                    .out_of_order_window
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        self.emit_trace(stats);
    }

    fn emit_trace(&self, stats: ChunkRequestStats) {
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
            "[server-trace] chunk={} size={} total={} lock(wait/hold)={}/{} body={} hash={} queue={} storage={} open={} seek={} write={} flush={} dup={} seq={}",
            stats.index,
            fmt_bytes(stats.chunk_size),
            fmt_duration(stats.handler_total),
            fmt_duration(stats.lock_wait),
            fmt_duration(stats.lock_hold),
            fmt_duration(stats.body_read),
            fmt_duration(stats.hash_verify),
            fmt_duration(stats.queue_delay),
            fmt_duration(stats.storage_total),
            fmt_duration(stats.open),
            fmt_duration(stats.seek),
            fmt_duration(stats.write),
            fmt_duration(stats.flush),
            yes_no(stats.duplicate),
            stats.sequential.map(yes_no).unwrap_or("n/a")
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
    active_sessions: AtomicU64,
    bytes_written_window: AtomicU64,
    chunks_written_window: AtomicU64,
    failures_window: AtomicU64,
    duplicates_window: AtomicU64,
    sequential_window: AtomicU64,
    out_of_order_window: AtomicU64,
    dropped_traces_window: AtomicU64,
    current_blocking_writes: AtomicU64,
    max_blocking_writes_window: AtomicU64,
    handler_total: Histogram,
    lock_wait: Histogram,
    lock_hold: Histogram,
    body_read: Histogram,
    hash_verify: Histogram,
    queue_delay: Histogram,
    storage_total: Histogram,
    open: Histogram,
    seek: Histogram,
    write: Histogram,
    flush: Histogram,
}

impl Inner {
    fn print_summary(&self) {
        let bytes = self.bytes_written_window.swap(0, Ordering::Relaxed);
        let chunks = self.chunks_written_window.swap(0, Ordering::Relaxed);
        let failures = self.failures_window.swap(0, Ordering::Relaxed);
        let duplicates = self.duplicates_window.swap(0, Ordering::Relaxed);
        let sequential = self.sequential_window.swap(0, Ordering::Relaxed);
        let out_of_order = self.out_of_order_window.swap(0, Ordering::Relaxed);
        let dropped_traces = self.dropped_traces_window.swap(0, Ordering::Relaxed);
        if bytes == 0
            && chunks == 0
            && failures == 0
            && duplicates == 0
            && sequential == 0
            && out_of_order == 0
            && dropped_traces == 0
        {
            return;
        }

        let rate = bytes as f64 / self.interval.as_secs_f64();
        let active_sessions = self.active_sessions.load(Ordering::Relaxed);
        let blocking_writes = self.current_blocking_writes.load(Ordering::Relaxed);
        let max_blocking_writes = self.max_blocking_writes_window.swap(0, Ordering::Relaxed);

        let handler_total = self.handler_total.snapshot_and_reset();
        let lock_wait = self.lock_wait.snapshot_and_reset();
        let lock_hold = self.lock_hold.snapshot_and_reset();
        let body_read = self.body_read.snapshot_and_reset();
        let hash_verify = self.hash_verify.snapshot_and_reset();
        let queue_delay = self.queue_delay.snapshot_and_reset();
        let storage_total = self.storage_total.snapshot_and_reset();
        let open = self.open.snapshot_and_reset();
        let seek = self.seek.snapshot_and_reset();
        let write = self.write.snapshot_and_reset();
        let flush = self.flush.snapshot_and_reset();

        eprintln!("[server] {:.1}s window", self.interval.as_secs_f64());
        eprintln!(
            "  throughput: {} chunks, {}, {}/s, failures {}, duplicates {}, active sessions {}, blocking writes {}/{}, dropped traces {}",
            chunks,
            fmt_bytes(bytes),
            fmt_bytes_f64(rate),
            failures,
            duplicates,
            active_sessions,
            blocking_writes,
            max_blocking_writes,
            dropped_traces
        );
        print_stage_line("  handler total", &handler_total);
        eprintln!(
            "  body/hash/queue: body {}, hash {}, queue {}",
            body_read.render(),
            hash_verify.render(),
            queue_delay.render()
        );
        print_stage_line("  storage total", &storage_total);
        eprintln!(
            "  write path: open {}, seek {}, write {}, flush {}",
            open.render_short(),
            seek.render_short(),
            write.render_short(),
            flush.render_short()
        );
        eprintln!(
            "  contention/order: lock wait {}, lock hold {}, sequential {}, out-of-order {}",
            lock_wait.render(),
            lock_hold.render(),
            sequential,
            out_of_order
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

    fn render_short(self) -> String {
        match (self.avg_us(), self.p95_us()) {
            (Some(avg), Some(p95)) => format!("{}/{}", fmt_micros(avg), fmt_micros(p95)),
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
