// SPDX-License-Identifier: EUPL-1.2
// Copyright (c) 2026 Benjamin Küttner <benjamin.kuettner@icloud.com>
// Patent Pending — DE Gebrauchsmuster, filed 2026-02-23

//! Database connection pool, Redis cache, and application state.

use redis::aio::ConnectionManager;
use sqlx::PgPool;

/// Shared application state injected into every Axum handler.
#[derive(Clone)]
pub struct AppState {
    pub pool:  PgPool,
    /// Redis connection manager — multiplexes a single async connection across all handlers.
    /// `None` if `REDIS_URL` is not set (registry operates without cache, just slower at scale).
    pub cache: Option<ConnectionManager>,
    /// Optional API key for `POST /register`.
    /// When `Some`, callers must supply the matching value in `X-Registry-Key`.
    /// When `None`, registration is open (useful for local dev / migration).
    /// Set via `REGISTRY_KEY` environment variable.
    pub registry_key: Option<String>,
}

impl AppState {
    /// Connect to PostgreSQL (required) and Redis (optional — falls back gracefully).
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPool::connect(database_url).await?;

        let cache = match std::env::var("REDIS_URL") {
            Ok(url) => {
                match redis::Client::open(url.as_str()) {
                    Ok(client) => match ConnectionManager::new(client).await {
                        Ok(mgr) => {
                            tracing::info!("Redis cache connected: {}", url);
                            Some(mgr)
                        }
                        Err(e) => {
                            tracing::warn!("Redis connect failed (cache disabled): {e}");
                            None
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Redis URL invalid (cache disabled): {e}");
                        None
                    }
                }
            }
            Err(_) => {
                tracing::info!("REDIS_URL not set — DID cache disabled");
                None
            }
        };

        let registry_key = std::env::var("REGISTRY_KEY").ok();
        if registry_key.is_some() {
            tracing::info!("REGISTRY_KEY set — POST /register is key-protected");
        } else {
            tracing::warn!("REGISTRY_KEY not set — POST /register is open (dev mode)");
        }

        Ok(Self { pool, cache, registry_key })
    }
}
