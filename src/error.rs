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

    #[error("Resource not found: {0}")]
    ResourceNotFound(String),

    #[error("Duplicate entry: {0}")]
    Duplicate(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Author DID not registered: {0}")]
    UnknownAuthor(String),

    #[error("Already voted")]
    AlreadyVoted,

    #[error("Invalid vote: must be 'up' or 'down'")]
    InvalidVote,

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
            RegistryError::ResourceNotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            RegistryError::Duplicate(msg) => (StatusCode::CONFLICT, msg.clone()),
            RegistryError::Validation(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg.clone()),
            RegistryError::InvalidSignature(msg) => (
                StatusCode::UNAUTHORIZED,
                format!("Invalid signature: {msg}"),
            ),
            RegistryError::UnknownAuthor(did) => (
                StatusCode::FORBIDDEN,
                format!("Author DID not registered: {did}"),
            ),
            RegistryError::AlreadyVoted => (
                StatusCode::CONFLICT,
                "You have already voted on this entry".into(),
            ),
            RegistryError::InvalidVote => (
                StatusCode::BAD_REQUEST,
                "Vote must be 'up' or 'down'".into(),
            ),
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
