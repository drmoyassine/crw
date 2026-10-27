//! Axum-based HTTP API server for the CRW web scraper.
//!
//! Implements the Firecrawl-compatible REST API and built-in MCP transport:
//!
//! - [`app`] — Application builder and router setup
//! - [`routes`] — API endpoint handlers (`/v1/scrape`, `/v1/crawl`, `/v1/map`, `/mcp`)
//! - [`middleware`] — Auth middleware with constant-time Bearer token comparison
//! - [`error`] — HTTP error responses
//! - [`state`] — Shared application state (renderer, crawler, config)
//! - [`logring`] — In-RAM diagnostic log ring read back via `/internal/logs`
//! - [`hoststats`] — Host + sibling-container health sampler for the ring
//!
//! # Example
//!
//! ```rust,ignore
//! use crw_server::app::create_app;
//! use crw_server::state::AppState;
//!
//! let state = AppState::new(config)?;
//! let app = create_app(state);
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//! axum::serve(listener, app).await?;
//! ```

pub mod app;
pub mod diagnostics;
pub mod error;
pub mod hoststats;
pub mod logring;
pub mod middleware;
pub mod routes;
pub mod setup;
pub mod state;
