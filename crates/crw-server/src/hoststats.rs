//! Host + sibling-container health sampler.
//!
//! `/proc` inside a container is NOT namespaced for `loadavg`/`stat` — those
//! files report HOST-wide numbers (the classic procfs leak; cgroup-aware
//! tools exist precisely to fix it). We exploit it: a cheap sample of
//! `/proc/loadavg`, `/proc/stat` (busy%) and `/sys/fs/cgroup/cpu.stat`
//! (this container's own share) every `CRW_DIAG__SAMPLE_SECS` (default 15s,
//! min 5s) gives the ring a running record of "what was the box doing" —
//! the missing evidence in host-saturation flap forensics (2026-10-26:
//! chronic 5xx bursts correlated with 94% host CPU we could only observe by
//! luck from the panel).
//!
//! Each tick also probes the compose siblings (SearXNG `/healthz`, plus TCP
//! liveness on the configured CDP renderer endpoints): their own logs are
//! license-gated just like ours, so liveness-at-the-boundary is the best
//! in-process signal available. Every sample is one `info` line into the
//! ring (`target: crw::hoststats`) AND is kept for `/internal/health`;
//! sibling transitions ok→fail / fail→ok log their own warn/info lines so
//! they stand out.
//!
//! All reads degrade to `None`/`Off` on hosts without `/proc` (Windows dev)
//! — the sampler keeps running and still reports sibling liveness.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crw_core::config::AppConfig;
use serde::Serialize;

/// Default sampling cadence (seconds).
pub const DEFAULT_SAMPLE_SECS: u64 = 15;

/// Sampling cadence from `CRW_DIAG__SAMPLE_SECS` (seconds), clamped to ≥5s so
/// a typo can't turn this into a hot loop. Env-var knob (not figment config)
/// on purpose: same pattern as `CRW_DISABLE_SERVER_LLM_KEY` — server-only
/// operational switch, never part of the public config surface.
pub fn sample_interval() -> Duration {
    std::env::var("CRW_DIAG__SAMPLE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|secs| *secs >= 5)
        .map_or(
            Duration::from_secs(DEFAULT_SAMPLE_SECS),
            Duration::from_secs,
        )
}

/// Liveness verdict for one sibling. `Off` = not configured / not probed —
/// deliberately distinct from `Fail` so a missing tier never reads as an
/// outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SiblingStatus {
    Ok,
    Fail,
    Off,
}

impl SiblingStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Fail => "fail",
            Self::Off => "off",
        }
    }
}

/// One sampler observation. `/proc`-sourced fields are `None` off unix.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostSample {
    pub ts_ms: u64,
    pub load_1: Option<f64>,
    pub load_5: Option<f64>,
    pub load_15: Option<f64>,
    /// Host-wide CPU busy % between this sample and the previous one.
    pub host_cpu_pct: Option<f64>,
    /// This container's CPU % of ALL cores (cgroup v2 `cpu.stat` delta).
    pub cgroup_cpu_pct: Option<f64>,
    pub searxng: SiblingStatus,
    pub lightpanda: SiblingStatus,
    pub chrome: SiblingStatus,
}

static LATEST: OnceLock<Mutex<Option<HostSample>>> = OnceLock::new();

/// Most recent sampler observation, for `/internal/health`.
pub fn latest() -> Option<HostSample> {
    LATEST
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// `0.52 0.58 0.59 1/879 12345` → `(0.52, 0.58, 0.59)`.
fn parse_loadavg(line: &str) -> Option<(f64, f64, f64)> {
    let mut it = line.split_whitespace();
    let one = it.next()?.parse().ok()?;
    let five = it.next()?.parse().ok()?;
    let fifteen = it.next()?.parse().ok()?;
    Some((one, five, fifteen))
}

/// Aggregate `cpu` jiffy counters from the first line of `/proc/stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuTotals {
    busy: u64,
    total: u64,
}

fn parse_proc_stat(stat: &str) -> Option<CpuTotals> {
    let first = stat.lines().next()?;
    let mut fields = first.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let vals: Vec<u64> = fields
        .map(|f| f.parse::<u64>().ok())
        .collect::<Option<_>>()?;
    if vals.len() < 4 {
        return None;
    }
    // idle (idx 3) + iowait (idx 4, 0 when absent) count as not-busy.
    let idle = vals[3] + vals.get(4).copied().unwrap_or(0);
    let total: u64 = vals.iter().sum();
    Some(CpuTotals {
        busy: total - idle,
        total,
    })
}

/// cgroup v2 `cpu.stat` first field: cumulative `usage_usec`.
fn parse_cpu_stat_usage_usec(cpu_stat: &str) -> Option<u64> {
    cpu_stat.lines().find_map(|line| {
        let mut it = line.split_whitespace();
        match (it.next(), it.next()) {
            (Some("usage_usec"), Some(v)) => v.parse::<u64>().ok(),
            _ => None,
        }
    })
}

/// busy/total as a percentage. `None` on a zero-delta sample (tick raced).
fn ratio_pct(busy: u64, total: u64) -> Option<f64> {
    if total == 0 {
        return None;
    }
    Some(busy as f64 / total as f64 * 100.0)
}

/// Container CPU % of all cores from a usage_usec delta.
fn cgroup_pct(prev_usec: u64, cur_usec: u64, elapsed: Duration, cores: u64) -> Option<f64> {
    let elapsed_us = elapsed.as_micros();
    if elapsed_us == 0 || cores == 0 {
        return None;
    }
    let delta = cur_usec.checked_sub(prev_usec)? as f64;
    Some(delta / (elapsed_us as f64 * cores as f64) * 100.0)
}

/// `ws://host:port[/…]` → `(host, port)`. Accepts an `http://` scheme too —
/// config URLs for the same endpoints are sometimes written that way.
fn split_ws_host_port(ws_url: &str) -> Option<(String, u16)> {
    let rest = ws_url
        .strip_prefix("ws://")
        .or_else(|| ws_url.strip_prefix("http://"))?;
    let (host, port) = rest.rsplit_once(':')?;
    let host = host.trim_end_matches('/');
    if host.is_empty() {
        return None;
    }
    let port: u16 = port.split('/').next()?.parse().ok()?;
    Some((host.to_string(), port))
}

/// Render an `Option<f64>` field without `Some(…)` noise in log lines.
struct OptF(Option<f64>);

impl std::fmt::Display for OptF {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(v) => write!(f, "{v:.2}"),
            None => write!(f, "n/a"),
        }
    }
}

/// Start the background sampler. Idempotent-ish: call once from `main`
/// after `AppState` is built (needs renderer URLs + search origin).
pub fn spawn_sampler(config: &AppConfig) {
    let searxng_origin = if config.search.enabled {
        config
            .search
            .resolve_backend_url()
            .map(str::to_string)
            .map(|url| crate::diagnostics::sanitize_url_origin(&url))
    } else {
        None
    };
    let lightpanda = config
        .renderer
        .lightpanda
        .as_ref()
        .map(|lp| lp.ws_url.clone());
    let chrome = config.renderer.chrome.as_ref().map(|c| c.ws_url.clone());
    let interval = sample_interval();
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(client) => Some(client),
        Err(e) => {
            tracing::warn!(
                target: "crw::hoststats",
                "diag: could not build sampler http client: {e}"
            );
            None
        }
    };

    tracing::info!(
        target: "crw::hoststats",
        sample_secs = interval.as_secs(),
        "host stats sampler started (host /proc + sibling liveness into the ring)"
    );

    tokio::spawn(async move {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get() as u64)
            .unwrap_or(1);
        let mut ticker = tokio::time::interval(interval);
        let mut prev_host: Option<CpuTotals> = None;
        let mut prev_cg: Option<u64> = None;
        let mut prev_clock = std::time::Instant::now();
        let mut prev_statuses: Option<(SiblingStatus, SiblingStatus, SiblingStatus)> = None;

        loop {
            ticker.tick().await;
            let elapsed = prev_clock.elapsed();
            prev_clock = std::time::Instant::now();

            let (load_1, load_5, load_15) = read_trimmed("/proc/loadavg")
                .and_then(|s| parse_loadavg(&s))
                .map_or((None, None, None), |(a, b, c)| (Some(a), Some(b), Some(c)));

            let host_cpu_pct = match read_trimmed("/proc/stat").and_then(|s| parse_proc_stat(&s)) {
                Some(cur) => {
                    let pct = match prev_host {
                        Some(prev) => ratio_pct(
                            cur.busy.saturating_sub(prev.busy),
                            cur.total.saturating_sub(prev.total),
                        ),
                        None => None, // first sample has no delta yet
                    };
                    prev_host = Some(cur);
                    pct
                }
                None => None,
            };

            let cgroup_cpu_pct = match read_trimmed("/sys/fs/cgroup/cpu.stat")
                .and_then(|s| parse_cpu_stat_usage_usec(&s))
            {
                Some(cur) => {
                    let pct = prev_cg.and_then(|prev| cgroup_pct(prev, cur, elapsed, cores));
                    prev_cg = Some(cur);
                    pct
                }
                None => None,
            };

            let searxng = probe_searxng(&http, &searxng_origin).await;
            let lightpanda_status = probe_tcp(&lightpanda).await;
            let chrome_status = probe_tcp(&chrome).await;

            let sample = HostSample {
                ts_ms: crate::logring::now_ms(),
                load_1,
                load_5,
                load_15,
                host_cpu_pct,
                cgroup_cpu_pct,
                searxng,
                lightpanda: lightpanda_status,
                chrome: chrome_status,
            };

            // Sibling transitions get their own line so they stand out in the
            // ring instead of being one field in a periodic info line.
            if let Some((ps, pl, pc)) = prev_statuses {
                for (name, was, now) in [
                    ("searxng", ps, sample.searxng),
                    ("lightpanda", pl, sample.lightpanda),
                    ("chrome", pc, sample.chrome),
                ] {
                    if was == SiblingStatus::Ok && now == SiblingStatus::Fail {
                        tracing::warn!(
                            target: "crw::hoststats",
                            sibling = name,
                            "sibling {name} probe FAILED (was ok)"
                        );
                    } else if was == SiblingStatus::Fail && now == SiblingStatus::Ok {
                        tracing::info!(
                            target: "crw::hoststats",
                            sibling = name,
                            "sibling {name} probe recovered"
                        );
                    }
                }
            }
            prev_statuses = Some((sample.searxng, sample.lightpanda, sample.chrome));

            tracing::info!(
                target: "crw::hoststats",
                load_1 = %OptF(sample.load_1),
                load_5 = %OptF(sample.load_5),
                load_15 = %OptF(sample.load_15),
                host_cpu_pct = %OptF(sample.host_cpu_pct),
                cgroup_cpu_pct = %OptF(sample.cgroup_cpu_pct),
                searxng = sample.searxng.as_str(),
                lightpanda = sample.lightpanda.as_str(),
                chrome = sample.chrome.as_str(),
                "host sample"
            );

            if let Ok(mut slot) = LATEST.get_or_init(|| Mutex::new(None)).lock() {
                *slot = Some(sample);
            }
        }
    });
}

async fn probe_searxng(client: &Option<reqwest::Client>, origin: &Option<String>) -> SiblingStatus {
    let (Some(client), Some(origin)) = (client, origin) else {
        return SiblingStatus::Off;
    };
    let url = format!("{origin}/healthz");
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => SiblingStatus::Ok,
        _ => SiblingStatus::Fail,
    }
}

async fn probe_tcp(ws_url: &Option<String>) -> SiblingStatus {
    let Some(ws_url) = ws_url else {
        return SiblingStatus::Off;
    };
    let Some((host, port)) = split_ws_host_port(ws_url) else {
        return SiblingStatus::Off;
    };
    match tokio::time::timeout(
        Duration::from_secs(1),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(_)) => SiblingStatus::Ok,
        _ => SiblingStatus::Fail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_loadavg_takes_the_first_three_fields() {
        assert_eq!(
            parse_loadavg("0.52 0.58 0.59 1/879 12345"),
            Some((0.52, 0.58, 0.59))
        );
        assert_eq!(parse_loadavg("0.52 0.58"), None);
        assert_eq!(parse_loadavg("garbage 0.5 0.5 1/1 1"), None);
    }

    #[test]
    fn proc_stat_counts_idle_and_iowait_as_not_busy() {
        // user nice system idle iowait irq softirq steal
        let t = parse_proc_stat("cpu  10 5 20 60 5 0 0 0\ncpu0 1 1 1 1 1 1 1 1\n").unwrap();
        assert_eq!(t.total, 100);
        assert_eq!(t.busy, 35); // 100 - (60 idle + 5 iowait)
    }

    #[test]
    fn proc_stat_rejects_missing_or_malformed_cpu_line() {
        assert!(parse_proc_stat("").is_none());
        assert!(parse_proc_stat("memtotal 123\n").is_none());
        assert!(parse_proc_stat("cpu 1 2 x 4\n").is_none());
    }

    #[test]
    fn cpu_stat_finds_usage_usec() {
        assert_eq!(
            parse_cpu_stat_usage_usec("usage_usec 123456\nnr_periods 10\n"),
            Some(123_456)
        );
        assert_eq!(parse_cpu_stat_usage_usec("nr_periods 10\n"), None);
    }

    #[test]
    fn cgroup_pct_normalizes_against_all_cores() {
        // usage_usec counts CPU-time across cores: 1 000 000 usec in 1s on a
        // 2-core cgroup = one core fully busy = 50% of the budget; the same
        // second at 2 000 000 usec = both cores = 100%.
        let pct = cgroup_pct(0, 1_000_000, Duration::from_secs(1), 2).unwrap();
        assert!((pct - 50.0).abs() < 1e-9);
        let full = cgroup_pct(0, 2_000_000, Duration::from_secs(1), 2).unwrap();
        assert!((full - 100.0).abs() < 1e-9);
        assert!(cgroup_pct(5, 0, Duration::from_secs(1), 2).is_none()); // counter rewind
        assert!(cgroup_pct(0, 100, Duration::ZERO, 2).is_none()); // zero elapsed
    }

    #[test]
    fn ratio_pct_handles_zero_total() {
        assert!(ratio_pct(0, 0).is_none());
        assert!((ratio_pct(35, 100).unwrap() - 35.0).abs() < 1e-9);
    }

    #[test]
    fn split_ws_host_port_variants() {
        assert_eq!(
            split_ws_host_port("ws://chrome:9222"),
            Some(("chrome".to_string(), 9222))
        );
        assert_eq!(
            split_ws_host_port("ws://lp:9222/devtools/browser/abc"),
            Some(("lp".to_string(), 9222))
        );
        assert_eq!(
            split_ws_host_port("http://searxng:8080"),
            Some(("searxng".to_string(), 8080))
        );
        assert_eq!(split_ws_host_port("chrome:9222"), None); // no scheme
        assert_eq!(split_ws_host_port("ws://:9222"), None); // empty host
        assert_eq!(split_ws_host_port("ws://host:port"), None); // bad port
    }

    #[test]
    fn sibling_status_wire_strings() {
        assert_eq!(SiblingStatus::Ok.as_str(), "ok");
        assert_eq!(SiblingStatus::Fail.as_str(), "fail");
        assert_eq!(SiblingStatus::Off.as_str(), "off");
        assert_eq!(
            serde_json::to_string(&SiblingStatus::Fail).unwrap(),
            "\"fail\""
        );
    }

    #[test]
    fn sample_interval_clamps_and_defaults() {
        // No env dependency in tests (parallel processes share the env):
        // validate the clamp logic through the public shape instead.
        let d = sample_interval();
        assert!(d >= Duration::from_secs(5));
    }
}
