//! SIGIL Registry — DID resolution server for the SIGIL Protocol.
//!
//! Resolves `did:sigil:` identifiers to Ed25519 public keys and metadata.
//!
//! ## Endpoints
//!
//! - `GET  /health`             — Health check
//! - `GET  /resolve/{did}`      — Resolve a DID to its public key + metadata
//! - `POST /register`           — Register a new DID
//! - `POST /revoke/{did}`       — Revoke a DID

mod db;
mod error;
mod handlers;
mod models;

use axum::{routing::{get, post}, Router};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub use db::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise structured logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "sigil_registry=debug,info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Connect to PostgreSQL
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sigil:sigil@localhost:5432/sigil_registry".into());

    let state = AppState::connect(&database_url).await?;
    let state = Arc::new(state);

    tracing::info!("SIGIL Registry connected to database");

    // Run migrations
    sqlx::migrate!("./migrations").run(&state.pool).await?;
    tracing::info!("Migrations applied");

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/resolve/:did", get(handlers::resolve_did))
        .route("/register", post(handlers::register_did))
        .route("/revoke/:did", post(handlers::revoke_did))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3100".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("SIGIL Registry listening on http://{addr}");

    axum::serve(listener, app).await?;
    Ok(())
}
