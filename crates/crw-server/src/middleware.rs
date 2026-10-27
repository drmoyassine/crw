use axum::Json;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use crw_core::types::ApiResponse;
use std::sync::Arc;

/// Constant-time byte comparison to prevent timing attacks.
/// Does not leak the length of valid keys via timing side-channels:
/// always iterates over the longer of the two inputs.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len = a.len().max(b.len());
    let mut result = (a.len() != b.len()) as u8;
    for i in 0..len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        result |= x ^ y;
    }
    result == 0
}

/// Exposed for integration tests only.
#[cfg(feature = "test-utils")]
pub fn constant_time_eq_pub(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq(a, b)
}

/// Bearer token authentication middleware.
pub async fn auth_middleware(
    axum::extract::State(api_keys): axum::extract::State<Arc<Vec<String>>>,
    req: Request,
    next: Next,
) -> Response {
    if api_keys.is_empty() {
        return next.run(req).await;
    }

    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];
            // Compare against all keys without short-circuiting to avoid
            // leaking which key index matched via timing.
            if api_keys.iter().fold(false, |found, k| {
                constant_time_eq(k.as_bytes(), token.as_bytes()) | found
            }) {
                next.run(req).await
            } else {
                let body = ApiResponse::<()>::err("Invalid API key");
                (StatusCode::UNAUTHORIZED, Json(body)).into_response()
            }
        }
        _ => {
            let body = ApiResponse::<()>::err("Missing Authorization header");
            (StatusCode::UNAUTHORIZED, Json(body)).into_response()
        }
    }
}

/// Error-boundary capture for the diagnostic ring (`logring`): every 4xx/5xx
/// response is logged at WARN with method, path, status, latency AND the
/// response's `error` message when the body is one of our JSON envelopes.
///
/// This is the guarantee that every failure leaves a readable trace in
/// `/internal/logs` even when the handler produced its error response
/// without an intermediate `tracing::error!` — all error shapes converge at
/// the response boundary. Layered OUTSIDE auth/rate-limit/timeout (see
/// `app.rs`) so their 401/429/504 rejections are captured too.
///
/// The body is buffered (≤ `CAPTURE_MAX_BYTES`) to extract the message, then
/// rebuilt verbatim. Oversized error bodies (per `Content-Length`) are logged
/// without a message and passed through untouched; a body that turns out
/// mid-read to exceed the cap keeps a captured line but ships an empty body
/// — acceptable for a shape that cannot occur with today's error envelopes.
pub async fn error_capture_middleware(req: Request, next: Next) -> Response {
    /// Max bytes buffered to extract an error message from the response body.
    const CAPTURE_MAX_BYTES: usize = 16 * 1024;

    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let started = std::time::Instant::now();
    let resp = next.run(req).await;
    let status = resp.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return resp;
    }

    let latency_ms = started.elapsed().as_millis() as u64;
    let over_cap = resp
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > CAPTURE_MAX_BYTES);
    if over_cap {
        tracing::warn!(
            target: "crw::http",
            method = %method,
            path = %path,
            status = status.as_u16(),
            latency_ms,
            error = "(body too large to capture)",
            "request failed"
        );
        return resp;
    }

    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, CAPTURE_MAX_BYTES).await.ok();
    let error = bytes
        .as_ref()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
        .unwrap_or_default();
    tracing::warn!(
        target: "crw::http",
        method = %method,
        path = %path,
        status = status.as_u16(),
        latency_ms,
        error = %error,
        "request failed"
    );
    let body = match bytes {
        Some(b) => axum::body::Body::from(b),
        None => axum::body::Body::empty(),
    };
    Response::from_parts(parts, body)
}
