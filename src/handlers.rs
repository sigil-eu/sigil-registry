//! Axum route handlers for the SIGIL Registry.

use crate::{
    db::AppState,
    error::RegistryError,
    models::{RegisterRequest, ResolveResponse},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use std::sync::Arc;

// ── Health ────────────────────────────────────────────────────────────────────

/// `GET /health` — Health check
pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "sigil-registry",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// ── Resolve ───────────────────────────────────────────────────────────────────

/// `GET /resolve/:did` — Resolve a DID to its public key and metadata.
///
/// Per SIGIL Spec §7.2: revoked DIDs return `"status": "revoked"`.
/// Verifiers MUST reject envelopes signed by revoked identities.
pub async fn resolve_did(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<ResolveResponse>, RegistryError> {
    let row = sqlx::query_as::<_, crate::models::DidDocument>(
        "SELECT did, public_key, namespace, label, status, created_at, updated_at, revoked_at
         FROM dids WHERE did = $1",
    )
    .bind(&did)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| RegistryError::NotFound(did.clone()))?;

    Ok(Json(row.into()))
}

// ── Register ──────────────────────────────────────────────────────────────────

/// `POST /register` — Register a new DID.
///
/// Body: `{ "did": "did:sigil:foo", "public_key": "<base64url>", "namespace": "foo", "label": "..." }`
pub async fn register_did(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<Value>), RegistryError> {
    // Validate DID format
    if !req.did.starts_with("did:sigil:") {
        return Err(RegistryError::InvalidDid(format!(
            "DID must start with 'did:sigil:' — got: {}",
            req.did
        )));
    }

    // Check for duplicates
    let exists: bool = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM dids WHERE did = $1)",
    )
    .bind(&req.did)
    .fetch_one(&state.pool)
    .await?;

    if exists {
        return Err(RegistryError::Conflict(req.did));
    }

    // Insert the new DID
    sqlx::query(
        "INSERT INTO dids (did, public_key, namespace, label, status)
         VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(&req.did)
    .bind(&req.public_key)
    .bind(&req.namespace)
    .bind(&req.label)
    .execute(&state.pool)
    .await?;

    tracing::info!("Registered new DID: {}", req.did);

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "did": req.did,
            "status": "active",
            "message": "DID registered successfully",
        })),
    ))
}

// ── Revoke ────────────────────────────────────────────────────────────────────

/// `POST /revoke/:did` — Revoke a DID.
///
/// Per SIGIL Spec §11.3: revoked keys must remain in the DID Document
/// for at least 24 hours so in-flight messages can still be verified.
pub async fn revoke_did(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<Value>, RegistryError> {
    let result = sqlx::query(
        "UPDATE dids
         SET status = 'revoked', revoked_at = NOW(), updated_at = NOW()
         WHERE did = $1 AND status = 'active'",
    )
    .bind(&did)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(RegistryError::NotFound(did));
    }

    tracing::warn!("Revoked DID: {}", did);

    Ok(Json(json!({
        "did": did,
        "status": "revoked",
        "message": "DID revoked. Key remains resolvable for 24h per SIGIL Spec §11.3.",
    })))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_returns_ok() {
        let resp = health().await;
        assert_eq!(resp.0["status"], "ok");
        assert_eq!(resp.0["service"], "sigil-registry");
    }
}
