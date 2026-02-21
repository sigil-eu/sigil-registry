//! SIGIL Registry — DID resolution + Crowdsourced Scanner & Policy registry.
//!
//! ## DID Endpoints
//!
//! - `GET  /health`             — Health check
//! - `GET  /resolve/{did}`      — Resolve a DID to its public key + metadata
//! - `POST /register`           — Register a new DID
//! - `POST /revoke/{did}`       — Revoke a DID
//!
//! ## Scanner Pattern Endpoints
//!
//! - `GET  /patterns`           — List community patterns (filterable by category/verified)
//! - `GET  /patterns/bundle`    — Compiled bundle of verified patterns (for SDK consumption)
//! - `GET  /patterns/:id`       — Get a single pattern
//! - `POST /patterns`           — Submit a new pattern (requires Ed25519 signature)
//! - `POST /patterns/:id/vote`  — Vote on a pattern
//!
//! ## Security Policy Endpoints
//!
//! - `GET  /policies`           — List community tool-risk policies
//! - `GET  /policies/:id`       — Get a single policy
//! - `POST /policies`           — Submit a new policy (requires Ed25519 signature)
//! - `POST /policies/:id/vote`  — Vote on a policy

mod auth;
mod db;
mod error;
mod handlers;
mod handlers_patterns;
mod handlers_policies;
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

    // Run all migrations (0001_create_dids + 0002_crowdsourced_registry)
    sqlx::migrate!("./migrations").run(&state.pool).await?;
    tracing::info!("Migrations applied");

    let app = Router::new()
        // ── Health
        .route("/health", get(handlers::health))

        // ── DID resolution
        .route("/resolve/:did", get(handlers::resolve_did))
        .route("/register", post(handlers::register_did))
        .route("/revoke/:did", post(handlers::revoke_did))

        // ── Scanner Patterns
        .route("/patterns",             get(handlers_patterns::list_patterns)
                                            .post(handlers_patterns::create_pattern))
        .route("/patterns/bundle",      get(handlers_patterns::get_bundle))
        .route("/patterns/:id",         get(handlers_patterns::get_pattern))
        .route("/patterns/:id/vote",    post(handlers_patterns::vote_pattern))

        // ── Security Policies
        .route("/policies",             get(handlers_policies::list_policies)
                                            .post(handlers_policies::create_policy))
        .route("/policies/:id",         get(handlers_policies::get_policy))
        .route("/policies/:id/vote",    post(handlers_policies::vote_policy))

        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3100".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("SIGIL Registry listening on http://{addr}");

    axum::serve(listener, app).await?;
    Ok(())
}
