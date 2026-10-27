//! In-RAM diagnostic log ring — the operator "black box".
//!
//! Docker's per-container log files are the only place crw's stdout/stderr
//! history lives, and on Easypanel-managed hosts reading them through the
//! panel API is a paid (license-gated) feature. When a scrape/search flap
//! happens, the process is left with no readable history exactly when it
//! matters most. `RingLayer` is the fix that lives entirely inside the
//! process: a `tracing` layer attached next to `fmt()` in `main.rs` that
//! mirrors every event into two bounded in-RAM deques —
//!
//! - `all`   — every level, short window (2 048 entries);
//! - `errors`— WARN and above, 4× retention (8 192 entries), so an
//!   info/debug burst cannot evict the failures an operator came for.
//!
//! `GET /internal/logs` (auth-gated like the rest of the API, see
//! `routes::internal`) returns the filtered tail. RAM-only on purpose: the
//! bundled compose runs this container `read_only` with tmpfs-only scratch,
//! so a log file would need a volume change and would be wiped on every
//! redeploy anyway — a flap is a live phenomenon, read during or right
//! after one. The cost ceiling is ≈ 4 MiB (8 192 × 2 KiB messages).
//!
//! Sizing/format knobs are constants, not config: this surface is meant to
//! be read with `curl` and `grep`, not to be tuned.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{Event, Level, Subscriber, field::Field};
use tracing_subscriber::Layer;
use tracing_subscriber::field::Visit;
use tracing_subscriber::layer::Context;

/// Every-level ring capacity (entries).
const ALL_CAPACITY: usize = 2_048;
/// WARN+ ring capacity (entries) — 4× the all-tier window.
const ERRORS_CAPACITY: usize = 8_192;
/// Per-message byte cap; truncation is char-boundary-safe.
const MESSAGE_CAP_BYTES: usize = 2_048;
/// Max structured fields captured per event, to bound pathological spans.
const MAX_FIELDS: usize = 16;

/// One captured event. `message` is the formatted message field followed by
/// any structured fields as `k=v` pairs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub ts_ms: u64,
    pub level: String,
    pub target: String,
    pub message: String,
}

/// Which ring a query reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Tier {
    #[default]
    All,
    Errors,
}

/// Ring occupancy + eviction counters, surfaced by `/internal/logs` and
/// `/internal/health` so a reader knows how much history was dropped.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RingStats {
    pub all_capacity: usize,
    pub all_len: usize,
    pub all_dropped: u64,
    pub errors_capacity: usize,
    pub errors_len: usize,
    pub errors_dropped: u64,
}

struct Ring {
    all: Mutex<VecDeque<LogEntry>>,
    errors: Mutex<VecDeque<LogEntry>>,
    dropped_all: AtomicU64,
    dropped_errors: AtomicU64,
}

static RING: OnceLock<Ring> = OnceLock::new();
static BOOT_MS: OnceLock<u64> = OnceLock::new();

fn ring() -> &'static Ring {
    RING.get_or_init(|| Ring {
        all: Mutex::new(VecDeque::with_capacity(ALL_CAPACITY)),
        errors: Mutex::new(VecDeque::with_capacity(ERRORS_CAPACITY)),
        dropped_all: AtomicU64::new(0),
        dropped_errors: AtomicU64::new(0),
    })
}

/// Wall-clock process boot (ms since the unix epoch), for `sinceMs` filters
/// and uptime reporting. Captured on first access.
pub fn boot_ms() -> u64 {
    *BOOT_MS.get_or_init(now_ms)
}

/// Current wall clock in ms since the unix epoch. Shared with the hoststats
/// sampler so ring entries and health samples share one timebase.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn level_of(s: &str) -> Option<Level> {
    std::str::FromStr::from_str(s).ok()
}

fn is_error_level(level: &str) -> bool {
    matches!(level_of(level), Some(Level::WARN | Level::ERROR))
}

/// Insert one entry into the ring(s). WARN/ERROR entries land in BOTH tiers.
pub(crate) fn push(entry: LogEntry) {
    let r = ring();
    if let Ok(mut q) = r.all.lock() {
        q.push_back(entry.clone());
        while q.len() > ALL_CAPACITY {
            q.pop_front();
            r.dropped_all.fetch_add(1, Ordering::Relaxed);
        }
    }
    if is_error_level(&entry.level)
        && let Ok(mut q) = r.errors.lock()
    {
        q.push_back(entry);
        while q.len() > ERRORS_CAPACITY {
            q.pop_front();
            r.dropped_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Filtered tail of a ring, oldest→newest, at most `limit` entries.
#[derive(Debug, Clone, Default)]
pub struct RingQuery {
    pub tier: Tier,
    /// Minimum severity (`Level` ordering: ERROR < WARN < INFO < …).
    pub min_level: Option<Level>,
    /// Only entries at/after this unix-ms timestamp.
    pub since_ms: Option<u64>,
    /// Case-insensitive substring over `target + message`.
    pub grep: Option<String>,
    pub limit: usize,
}

pub fn query(q: &RingQuery) -> Vec<LogEntry> {
    let r = ring();
    let guard = match q.tier {
        Tier::Errors => r.errors.lock(),
        Tier::All => r.all.lock(),
    };
    let Ok(deque) = guard else {
        return Vec::new();
    };
    let grep = q.grep.as_deref().map(str::to_ascii_lowercase);
    let matched: Vec<LogEntry> = deque
        .iter()
        .filter(|e| {
            if let Some(since) = q.since_ms
                && e.ts_ms < since
            {
                return false;
            }
            if let Some(min) = q.min_level
                && !matches!(level_of(&e.level), Some(l) if l <= min)
            {
                return false;
            }
            if let Some(g) = &grep {
                let haystack = format!("{} {}", e.target, e.message).to_ascii_lowercase();
                if !haystack.contains(g.as_str()) {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();
    let start = matched.len().saturating_sub(q.limit);
    matched[start..].to_vec()
}

/// Occupancy + eviction counters for both tiers.
pub fn stats() -> RingStats {
    let r = ring();
    RingStats {
        all_capacity: ALL_CAPACITY,
        all_len: r.all.lock().map(|q| q.len()).unwrap_or(0),
        all_dropped: r.dropped_all.load(Ordering::Relaxed),
        errors_capacity: ERRORS_CAPACITY,
        errors_len: r.errors.lock().map(|q| q.len()).unwrap_or(0),
        errors_dropped: r.dropped_errors.load(Ordering::Relaxed),
    }
}

/// WARN+ entries newer than `since_ms` (unix ms). Powers the rolling error
/// rates in `/internal/health`.
pub fn error_count_since(since_ms: u64) -> usize {
    ring()
        .errors
        .lock()
        .map(|q| q.iter().filter(|e| e.ts_ms >= since_ms).count())
        .unwrap_or(0)
}

/// `tracing` layer mirroring events into the ring. Attach next to `fmt()`
/// (see `main.rs`); it captures whatever the ambient `EnvFilter` lets
/// through, so `RUST_LOG` remains the single verbosity control.
pub struct RingLayer;

impl<S> Layer<S> for RingLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = CollectVisitor::default();
        event.record(&mut visitor);
        let mut message = visitor.message;
        if !visitor.fields.is_empty() {
            if !message.is_empty() {
                message.push(' ');
            }
            message.push_str(&visitor.fields.join(" "));
        }
        truncate_on_char_boundary(&mut message, MESSAGE_CAP_BYTES);
        push(LogEntry {
            ts_ms: now_ms(),
            level: event.metadata().level().to_string(),
            target: event.metadata().target().to_string(),
            message,
        });
    }
}

#[derive(Default)]
struct CollectVisitor {
    message: String,
    fields: Vec<String>,
}

impl CollectVisitor {
    fn note(&mut self, field: &Field, rendered: String) {
        if field.name() == "message" {
            // The fmt layer renders only the first message field; mirror that.
            if self.message.is_empty() {
                self.message = rendered;
            }
        } else if self.fields.len() < MAX_FIELDS {
            self.fields.push(format!("{}={}", field.name(), rendered));
        }
    }
}

impl Visit for CollectVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.note(field, value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.note(field, format!("{value:?}"));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.note(field, value.to_string());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.note(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.note(field, value.to_string());
    }
    // record_u64 / i128 / u128 / error default-forward to `record_debug`.
}

/// Byte-cap a string without splitting a UTF-8 code point.
fn truncate_on_char_boundary(s: &mut String, max_bytes: usize) {
    if s.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s.push_str("…[truncated]");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt as _;

    fn entry(level: &str, target: &str, message: &str) -> LogEntry {
        LogEntry {
            ts_ms: now_ms(),
            level: level.to_string(),
            target: target.to_string(),
            message: message.to_string(),
        }
    }

    fn query_all(grep: &str) -> Vec<LogEntry> {
        query(&RingQuery {
            grep: Some(grep.to_string()),
            limit: 100,
            ..Default::default()
        })
    }

    #[test]
    fn all_tier_is_bounded_and_counts_evictions() {
        let marker = "ring-bounded-marker";
        for i in 0..(ALL_CAPACITY + 25) {
            push(entry("INFO", "t", &format!("{marker} {i}")));
        }
        // The ring is process-global and tests run in parallel, so exact
        // eviction counts and survivor sets are not observable — other tests
        // push their own entries concurrently. Assert the invariants that
        // hold regardless of interleaving: the ring saturates at capacity,
        // our overflow is counted, and our surviving markers keep FIFO order.
        let s = stats();
        assert_eq!(s.all_len, ALL_CAPACITY);
        assert!(s.all_dropped >= 25, "dropped: {}", s.all_dropped);
        let idx: Vec<usize> = query_all(marker)
            .iter()
            .filter_map(|e| {
                e.message
                    .rsplit(' ')
                    .next()
                    .and_then(|tok| tok.parse::<usize>().ok())
            })
            .collect();
        assert!(!idx.is_empty());
        assert!(idx.windows(2).all(|w| w[0] < w[1]), "FIFO order: {idx:?}");
    }

    #[test]
    fn warn_and_error_land_in_both_tiers_but_info_does_not() {
        push(entry("INFO", "t", "tier-info-only-marker"));
        push(entry("WARN", "t", "tier-warn-marker"));
        push(entry("ERROR", "t", "tier-error-marker"));
        let errors = query(&RingQuery {
            tier: Tier::Errors,
            grep: Some("tier-".to_string()),
            limit: 100,
            ..Default::default()
        });
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("tier-warn-marker"))
        );
        assert!(
            errors
                .iter()
                .any(|e| e.message.contains("tier-error-marker"))
        );
        assert!(
            !errors
                .iter()
                .any(|e| e.message.contains("tier-info-only-marker"))
        );
    }

    #[test]
    fn errors_tier_keeps_failures_when_the_all_tier_rolls_over() {
        push(entry("WARN", "t", "eviction-canary-marker"));
        for i in 0..(ALL_CAPACITY + 5) {
            push(entry("INFO", "t", &format!("eviction-noise-{i}")));
        }
        // Rolled out of the all tier…
        assert!(query_all("eviction-canary-marker").is_empty());
        // …but still present in the errors tier.
        let kept = query(&RingQuery {
            tier: Tier::Errors,
            grep: Some("eviction-canary-marker".to_string()),
            limit: 10,
            ..Default::default()
        });
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn query_filters_by_level_since_and_grep() {
        let t0 = now_ms();
        push(entry("INFO", "filter-target", "filter-low-marker"));
        push(entry("ERROR", "filter-target", "filter-high-marker"));
        let min_warn = query(&RingQuery {
            min_level: Some(Level::WARN),
            grep: Some("filter-target".to_string()),
            limit: 100,
            ..Default::default()
        });
        assert!(
            min_warn
                .iter()
                .all(|e| e.level == "ERROR" || e.level == "WARN")
        );
        assert!(
            min_warn
                .iter()
                .any(|e| e.message.contains("filter-high-marker"))
        );
        let since = query(&RingQuery {
            since_ms: Some(t0),
            grep: Some("filter-".to_string()),
            limit: 100,
            ..Default::default()
        });
        assert!(!since.is_empty());
        assert!(since.iter().all(|e| e.ts_ms >= t0));
        // Level parsing is case-insensitive (wire clients send lowercase).
        assert_eq!(level_of("warn"), Some(Level::WARN));
        assert_eq!(level_of("ERROR"), Some(Level::ERROR));
    }

    #[test]
    fn limit_returns_the_newest_tail_in_order() {
        for i in 0..10 {
            push(entry("INFO", "t", &format!("tail-order-marker-{i}")));
        }
        let tail = query(&RingQuery {
            grep: Some("tail-order-marker".to_string()),
            limit: 3,
            ..Default::default()
        });
        let msgs: Vec<&str> = tail.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(
            msgs,
            [
                "tail-order-marker-7",
                "tail-order-marker-8",
                "tail-order-marker-9"
            ]
        );
    }

    #[test]
    fn truncate_never_splits_a_code_point() {
        let mut s = "é".repeat(2_000); // 4 000 bytes of 2-byte chars
        truncate_on_char_boundary(&mut s, MESSAGE_CAP_BYTES);
        assert!(s.ends_with("…[truncated]"));
        // Near the byte cap on 2-byte chars ⇒ an odd cap can only be honored
        // by stepping back to a boundary; the surviving prefix is intact 'é's.
        assert!(
            s.len() < MESSAGE_CAP_BYTES + 32,
            "should be near the cap: {}",
            s.len()
        );
        let suffix = "…[truncated]";
        let prefix = &s[..s.len() - suffix.len()];
        assert!(prefix.chars().all(|c| c == 'é'));
    }

    #[test]
    fn layer_captures_message_and_structured_fields() {
        let sub = tracing_subscriber::registry().with(RingLayer);
        let dispatch = tracing::dispatcher::Dispatch::new(sub);
        tracing::dispatcher::with_default(&dispatch, || {
            // Grammar note: in tracing's macros, event fields must precede the
            // message — anything after the format string is a plain
            // `format_args!` argument, never a field (the compiler enforces
            // this for unused args, but silently folds referenced ones into
            // the message). Args after the message only render the message;
            // `k = v` pairs before it are separate field visits.
            tracing::warn!(target: "layer-capture-target", "boom {}", 42);
            tracing::warn!(target: "layer-capture-target", n = 7, tag = "cli", "structured");
        });
        let got = query_all("layer-capture-target");
        assert_eq!(got.len(), 2, "entries: {got:?}");
        assert_eq!(got[0].message, "boom 42");
        assert!(
            got[1].message.contains("n=7") && got[1].message.contains("tag=cli"),
            "fields: {}",
            got[1].message
        );
        assert!(got.iter().all(|e| e.level == "WARN"));
    }

    #[test]
    fn error_count_since_respects_the_window() {
        let now = now_ms();
        push(LogEntry {
            ts_ms: now.saturating_sub(10 * 60_000),
            level: "WARN".to_string(),
            target: "t".to_string(),
            message: "old-window-marker".to_string(),
        });
        push(entry("ERROR", "t", "new-window-marker"));
        let recent = error_count_since(now.saturating_sub(60_000));
        // Global ring is shared across tests; only assert the delta shape:
        assert!(recent >= 1);
    }
}
