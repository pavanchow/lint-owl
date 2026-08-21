//! HTTP API + a paste-and-scan console for Lint-Owl.
//!   GET  /            the console UI
//!   GET  /health      "ok"
//!   POST /scan {"code":"..."}  -> findings with source-to-sink hops

use anyhow::Result;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct ScanReq {
    code: String,
}

pub fn serve(port: u16) -> Result<()> {
    let app = Router::new()
        .route("/", get(|| async { Html(include_str!("ui.html")) }))
        .route("/health", get(|| async { "ok" }))
        .route("/scan", post(scan));

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
        eprintln!("lint-owl console on http://127.0.0.1:{port}  (UI at /, POST /scan)");
        axum::serve(listener, app).await?;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

async fn scan(Json(req): Json<ScanReq>) -> impl IntoResponse {
    let task = tokio::task::spawn_blocking(move || crate::scan_json(&req.code));
    match tokio::time::timeout(std::time::Duration::from_secs(3), task).await {
        Ok(Ok(v)) => (StatusCode::OK, Json(v)),
        Ok(Err(_)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "scan task failed" })),
        ),
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({ "error": "scan timed out" })),
        ),
    }
}
