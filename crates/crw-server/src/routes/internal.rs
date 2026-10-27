//! `/internal/*` — operator diagnostics: log-ring readback + health snapshot.
//!
//! Ops surface in the `/metrics` family: root-level, inside the auth boundary
//! (Bearer-gated when `[auth].api_keys` is set), deliberately NOT part of the
//! versioned Firecrawl-compat surface — so it never lands under `/firecrawl/*`
//! and can evolve freely. Read with:
//!
//! ```text
//! curl -H "Authorization: Bearer $CRW_KEY" \
//!   'http://host:3000/internal/logs?tier=errors&level=warn&grep=searxng&limit=100'
//! ```

use axum::Json;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;

use crate::hoststats;
use crate::logring::{self, Tier};
use crate::state::AppState;

/// Default / maximum tail length returned by `/internal/logs`.
const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 5_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogsQuery {
    /// `all` (default) or `errors` (WARN+ ring, 4× retention).
    pub tier: Option<String>,
    /// Minimum severity: `error` | `warn` | `info` | `debug` | `trace`.
    pub level: Option<String>,
    /// Only entries at/after this unix-ms timestamp.
    pub since_ms: Option<u64>,
    /// Case-insensitive substring over target + message.
    pub grep: Option<String>,
    /// Tail length (default 200, capped at 5000).
    pub limit: Option<usize>,
}

/// `GET /internal/logs` — filtered tail of the in-RAM diagnostic ring.
pub async fn logs(Query(q): Query<LogsQuery>) -> impl IntoResponse {
    let tier = match q.tier.as_deref() {
        Some("errors") => Tier::Errors,
        _ => Tier::All,
    };
    let min_level: Option<tracing::Level> = q
        .level
        .as_deref()
        .and_then(|s| std::str::FromStr::from_str(s).ok());
    let entries = logring::query(&logring::RingQuery {
        tier,
        min_level,
        since_ms: q.since_ms,
        grep: q.grep,
        limit: q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT),
    });
    Json(json!({
        "success": true,
        "data": {
            "bootMs": logring::boot_ms(),
            "nowMs": logring::now_ms(),
            "tier": match tier { Tier::Errors => "errors", Tier::All => "all" },
            "count": entries.len(),
            "entries": entries,
            "ring": logring::stats(),
        }
    }))
}

/// `GET /internal/health` — point-in-time diagnosability snapshot.
///
/// Split from `/health` on purpose: `/health` is the Docker healthcheck's
/// liveness probe and MUST stay sub-millisecond + always-200 (failing it
/// restarts the container); this endpoint is the "is it degraded, why, since
/// when" answer, assembled from already-cached state — ring error rates, the
/// latest host/sibling sample, breaker snapshots, renderer names. For live
/// CDP probes use `/ready`.
pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let now = logring::now_ms();
    let boot = logring::boot_ms();
    let errors_5m = logring::error_count_since(now.saturating_sub(5 * 60_000));
    let errors_15m = logring::error_count_since(now.saturating_sub(15 * 60_000));
    let active_crawl_jobs = state.crawl_jobs.read().await.len();
    Json(json!({
        "success": true,
        "data": {
            "bootMs": boot,
            "uptimeSecs": now.saturating_sub(boot) / 1000,
            "ring": {
                "errors5m": errors_5m,
                "errors15m": errors_15m,
                "stats": logring::stats(),
            },
            "host": hoststats::latest(),
            "breakers": state.renderer.breakers().snapshot(),
            "renderers": state.renderer.js_renderer_names(),
            "searxngConfigured": state.searxng.is_some(),
            "activeCrawlJobs": active_crawl_jobs,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::create_app;
    use crate::state::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use serde_json::Value;
    use tower::ServiceExt;

    fn app_with(config_toml: &str) -> axum::Router {
        let config: crw_core::config::AppConfig = toml::from_str(config_toml).unwrap();
        let state = AppState::new(config).unwrap();
        create_app(state)
    }

    #[tokio::test]
    async fn logs_endpoint_returns_ring_tail() {
        let app = app_with("");
        logring::push(logring::LogEntry {
            ts_ms: logring::now_ms(),
            level: "WARN".to_string(),
            target: "internal-endpoint-test".to_string(),
            message: "unique-logread-marker-xyz".to_string(),
        });
        let resp = app
            .oneshot(
                Request::get("/internal/logs?grep=unique-logread-marker-xyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["success"], json!(true));
        assert_eq!(v["data"]["count"], json!(1));
        assert!(
            v["data"]["entries"][0]["message"]
                .as_str()
                .unwrap()
                .contains("unique-logread-marker-xyz")
        );
    }

    #[tokio::test]
    async fn internal_endpoints_are_auth_gated_like_the_api() {
        let app = app_with("[auth]\napi_keys = [\"k\"]\n");
        let unauth = app
            .clone()
            .oneshot(Request::get("/internal/logs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let authed_logs = app
            .clone()
            .oneshot(
                Request::get("/internal/logs")
                    .header(header::AUTHORIZATION, "Bearer k")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authed_logs.status(), StatusCode::OK);

        let authed_health = app
            .oneshot(
                Request::get("/internal/health")
                    .header(header::AUTHORIZATION, "Bearer k")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authed_health.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(authed_health.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["success"], json!(true));
        // Snapshot sections all present (values vary by host/platform).
        for key in ["ring", "host", "breakers", "renderers", "uptimeSecs"] {
            assert!(v["data"].get(key).is_some(), "missing {key}");
        }
    }
}
