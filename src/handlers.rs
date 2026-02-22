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
use redis::AsyncCommands;
use serde_json::{json, Value};
use std::sync::Arc;

/// Cache TTL for DID documents: 5 minutes.
const DID_CACHE_TTL_SECS: u64 = 300;

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
/// Cache-aside: check Redis first (5-min TTL), fall through to PostgreSQL on miss.
/// Per SIGIL Spec §7.2: revoked DIDs return `"status": "revoked"`.
pub async fn resolve_did(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<ResolveResponse>, RegistryError> {
    let cache_key = format!("did:{}", did);

    // ── Cache read ────────────────────────────────────────────────────────────
    if let Some(mut cache) = state.cache.clone() {
        match cache.get::<_, Option<String>>(&cache_key).await {
            Ok(Some(cached)) => {
                // Cache hit — deserialize and return
                match serde_json::from_str::<ResolveResponse>(&cached) {
                    Ok(resp) => {
                        tracing::debug!("DID cache HIT: {}", did);
                        return Ok(Json(resp));
                    }
                    Err(e) => {
                        // Corrupted cache entry — log and fall through to DB
                        tracing::warn!("DID cache deserialization error for {}: {}", did, e);
                    }
                }
            }
            Ok(None) => {
                tracing::debug!("DID cache MISS: {}", did);
            }
            Err(e) => {
                // Redis error — log and fall through (graceful degradation)
                tracing::warn!("Redis GET error (falling back to DB): {}", e);
            }
        }
    }

    // ── Database read ─────────────────────────────────────────────────────────
    let row = sqlx::query_as::<_, crate::models::DidDocument>(
        "SELECT did, public_key, namespace, label, status, created_at, updated_at, revoked_at
         FROM dids WHERE did = $1",
    )
    .bind(&did)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| RegistryError::NotFound(did.clone()))?;

    let resp: ResolveResponse = row.into();

    // ── Cache write ───────────────────────────────────────────────────────────
    // Only cache active DIDs. Revoked DIDs have a short natural TTL from the
    // 24-hour spec window — don't cache them to allow timely revocation propagation.
    if resp.status == "active" {
        if let Some(mut cache) = state.cache.clone() {
            if let Ok(serialized) = serde_json::to_string(&resp) {
                if let Err(e) = cache
                    .set_ex::<_, _, ()>(&cache_key, serialized, DID_CACHE_TTL_SECS)
                    .await
                {
                    // Non-fatal: log and continue
                    tracing::warn!("Redis SET error (continuing without cache): {}", e);
                }
            }
        }
    }

    Ok(Json(resp))
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
/// Invalidates the Redis cache entry immediately so verifiers see the revocation
/// within the next request (no need to wait for TTL expiry).
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

    // ── Cache invalidation on revoke ──────────────────────────────────────────
    // Delete immediately — don't wait for TTL. Revocation must propagate fast.
    if let Some(mut cache) = state.cache.clone() {
        let cache_key = format!("did:{}", did);
        if let Err(e) = cache.del::<_, ()>(&cache_key).await {
            tracing::warn!("Redis DEL failed on revoke (cache may be stale for up to 5m): {}", e);
        } else {
            tracing::info!("Cache invalidated for revoked DID: {}", did);
        }
    }

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
