//! Database connection pool and application state.

use sqlx::PgPool;

/// Shared application state injected into every Axum handler.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
}

impl AppState {
    /// Connect to PostgreSQL and return an `AppState`.
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self { pool })
    }
}
