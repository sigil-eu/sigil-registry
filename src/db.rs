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

        Ok(Self { pool, cache })
    }
}
