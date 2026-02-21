//! Error types for the SIGIL Registry.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Application-level errors returned by handlers.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("DID not found: {0}")]
    NotFound(String),

    #[error("DID already registered: {0}")]
    Conflict(String),

    #[error("Invalid DID format: {0}")]
    InvalidDid(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            RegistryError::NotFound(did) => {
                (StatusCode::NOT_FOUND, format!("DID not found: {did}"))
            }
            RegistryError::Conflict(did) => (
                StatusCode::CONFLICT,
                format!("DID already registered: {did}"),
            ),
            RegistryError::InvalidDid(msg) => {
                (StatusCode::BAD_REQUEST, format!("Invalid DID: {msg}"))
            }
            RegistryError::Database(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {e}"),
            ),
            RegistryError::Internal(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal error: {e}"),
            ),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
