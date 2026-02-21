//! Handlers for the crowdsourced Scanner Pattern registry.
//!
//! ## Endpoints
//!
//! - `GET  /patterns`            — List patterns (filterable by category/verified)
//! - `GET  /patterns/bundle`     — Compiled bundle of all verified patterns (for SDK use)
//! - `GET  /patterns/:id`        — Get a single pattern
//! - `POST /patterns`            — Submit a new pattern (requires Ed25519 signature)
//! - `POST /patterns/:id/vote`   — Vote on a pattern (requires Ed25519 signature)

use crate::{
    auth,
    db::AppState,
    error::RegistryError,
    models::{BundleEntry, CreatePatternRequest, PatternQuery, ScannerPattern, VoteRequest},
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

// ── List ──────────────────────────────────────────────────────────────────────

/// `GET /patterns` — List scanner patterns, optionally filtered.
pub async fn list_patterns(
    State(state): State<Arc<AppState>>,
    Query(q): Query<PatternQuery>,
) -> Result<Json<Value>, RegistryError> {
    let limit = q.limit.unwrap_or(50).min(200);
    let offset = q.offset.unwrap_or(0);

    let patterns = match (q.category.as_deref(), q.verified) {
        (Some(cat), Some(v)) => sqlx::query_as::<_, ScannerPattern>(
            "SELECT * FROM scanner_patterns
             WHERE active = TRUE AND category = $1 AND verified = $2
             ORDER BY votes_up DESC, downloads DESC
             LIMIT $3 OFFSET $4",
        )
        .bind(cat)
        .bind(v)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?,

        (Some(cat), None) => sqlx::query_as::<_, ScannerPattern>(
            "SELECT * FROM scanner_patterns
             WHERE active = TRUE AND category = $1
             ORDER BY votes_up DESC, downloads DESC
             LIMIT $2 OFFSET $3",
        )
        .bind(cat)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?,

        (None, Some(v)) => sqlx::query_as::<_, ScannerPattern>(
            "SELECT * FROM scanner_patterns
             WHERE active = TRUE AND verified = $1
             ORDER BY votes_up DESC, downloads DESC
             LIMIT $2 OFFSET $3",
        )
        .bind(v)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?,

        (None, None) => sqlx::query_as::<_, ScannerPattern>(
            "SELECT * FROM scanner_patterns
             WHERE active = TRUE
             ORDER BY votes_up DESC, downloads DESC
             LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?,
    };

    Ok(Json(json!({
        "count": patterns.len(),
        "offset": offset,
        "patterns": patterns,
    })))
}

// ── Bundle ────────────────────────────────────────────────────────────────────

/// `GET /patterns/bundle` — Download all verified patterns as a compiled bundle.
///
/// This is the endpoint consumed by the `sigil-protocol` Rust crate and
/// `@sigil-eu/sdk-node` at startup to fetch the latest community patterns.
pub async fn get_bundle(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, RegistryError> {
    let patterns = sqlx::query_as::<_, ScannerPattern>(
        "SELECT * FROM scanner_patterns
         WHERE active = TRUE AND verified = TRUE
         ORDER BY category, name",
    )
    .fetch_all(&state.pool)
    .await?;

    // Increment download counter for all returned patterns
    sqlx::query(
        "UPDATE scanner_patterns SET downloads = downloads + 1
         WHERE active = TRUE AND verified = TRUE",
    )
    .execute(&state.pool)
    .await?;

    let bundle: Vec<BundleEntry> = patterns
        .into_iter()
        .map(|p| BundleEntry {
            name: p.name,
            category: p.category,
            pattern: p.pattern,
            severity: p.severity,
            replacement_hint: p.replacement_hint,
        })
        .collect();

    Ok(Json(json!({
        "version": "1",
        "generated_at": chrono::Utc::now(),
        "count": bundle.len(),
        "patterns": bundle,
    })))
}

// ── Get one ───────────────────────────────────────────────────────────────────

/// `GET /patterns/:id` — Get a single pattern by UUID.
pub async fn get_pattern(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ScannerPattern>, RegistryError> {
    let pattern = sqlx::query_as::<_, ScannerPattern>(
        "SELECT * FROM scanner_patterns WHERE id = $1 AND active = TRUE",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| RegistryError::ResourceNotFound(format!("Pattern {id} not found")))?;

    Ok(Json(pattern))
}

// ── Create ────────────────────────────────────────────────────────────────────

/// `POST /patterns` — Submit a new community scanner pattern.
///
/// Requires a valid Ed25519 signature from the author's `did:sigil:` key.
pub async fn create_pattern(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreatePatternRequest>,
) -> Result<(StatusCode, Json<Value>), RegistryError> {
    // 1. Validate category
    let valid_categories = ["secret", "pii", "credential", "financial"];
    if !valid_categories.contains(&req.category.as_str()) {
        return Err(RegistryError::Validation(format!(
            "category must be one of: {}",
            valid_categories.join(", ")
        )));
    }

    // 2. Validate severity
    let severity = req.severity.as_deref().unwrap_or("high");
    let valid_severities = ["low", "medium", "high", "critical"];
    if !valid_severities.contains(&severity) {
        return Err(RegistryError::Validation(format!(
            "severity must be one of: {}",
            valid_severities.join(", ")
        )));
    }

    // 3. Validate the regex compiles
    if let Err(e) = regex::Regex::new(&req.pattern) {
        return Err(RegistryError::Validation(format!("invalid regex: {e}")));
    }

    // 4. Verify the author DID exists and fetch its public key
    let author_key: Option<String> = sqlx::query_scalar(
        "SELECT public_key FROM dids WHERE did = $1 AND status = 'active'",
    )
    .bind(&req.author_did)
    .fetch_optional(&state.pool)
    .await?;

    let public_key = author_key.ok_or_else(|| RegistryError::UnknownAuthor(req.author_did.clone()))?;

    // 5. Verify the Ed25519 signature
    let message = auth::pattern_message(&req.name, &req.category, &req.pattern, &req.author_did);
    auth::verify_signature(&public_key, &message, &req.signature)
        .map_err(RegistryError::InvalidSignature)?;

    // 6. Check for duplicate name
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM scanner_patterns WHERE name = $1 AND active = TRUE)",
    )
    .bind(&req.name)
    .fetch_one(&state.pool)
    .await?;

    if exists {
        return Err(RegistryError::Duplicate(format!(
            "Pattern '{}' already exists",
            req.name
        )));
    }

    // 7. Insert
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO scanner_patterns
           (name, description, category, pattern, replacement_hint, severity, author_did)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id",
    )
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.category)
    .bind(&req.pattern)
    .bind(&req.replacement_hint)
    .bind(severity)
    .bind(&req.author_did)
    .fetch_one(&state.pool)
    .await?;

    tracing::info!("New scanner pattern submitted: '{}' by {}", req.name, req.author_did);

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "name": req.name,
            "status": "pending_review",
            "message": "Pattern submitted. It will appear in the bundle once verified by a SIGIL maintainer.",
        })),
    ))
}

// ── Vote ──────────────────────────────────────────────────────────────────────

/// `POST /patterns/:id/vote` — Vote on a scanner pattern.
///
/// Requires a valid Ed25519 signature from the voter's `did:sigil:` key.
/// Each DID can only vote once per pattern.
pub async fn vote_pattern(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<VoteRequest>,
) -> Result<Json<Value>, RegistryError> {
    // Validate vote direction
    if req.vote != "up" && req.vote != "down" {
        return Err(RegistryError::InvalidVote);
    }

    // Verify the voter DID exists
    let voter_key: Option<String> = sqlx::query_scalar(
        "SELECT public_key FROM dids WHERE did = $1 AND status = 'active'",
    )
    .bind(&req.voter_did)
    .fetch_optional(&state.pool)
    .await?;

    let public_key = voter_key.ok_or_else(|| RegistryError::UnknownAuthor(req.voter_did.clone()))?;

    // Verify signature
    let message = auth::vote_message("pattern", &id.to_string(), &req.vote, &req.voter_did);
    auth::verify_signature(&public_key, &message, &req.signature)
        .map_err(RegistryError::InvalidSignature)?;

    // Check pattern exists
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM scanner_patterns WHERE id = $1 AND active = TRUE)",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    if !exists {
        return Err(RegistryError::ResourceNotFound(format!("Pattern {id} not found")));
    }

    // Record vote (unique constraint prevents double-voting)
    let insert_result = sqlx::query(
        "INSERT INTO registry_votes (voter_did, target_type, target_id, vote)
         VALUES ($1, 'pattern', $2, $3)
         ON CONFLICT (voter_did, target_type, target_id) DO NOTHING
         RETURNING id",
    )
    .bind(&req.voter_did)
    .bind(id)
    .bind(&req.vote)
    .execute(&state.pool)
    .await?;

    if insert_result.rows_affected() == 0 {
        return Err(RegistryError::AlreadyVoted);
    }

    // Update the vote counter on the pattern
    let col = if req.vote == "up" { "votes_up" } else { "votes_down" };
    sqlx::query(&format!(
        "UPDATE scanner_patterns SET {col} = {col} + 1, updated_at = NOW() WHERE id = $1"
    ))
    .bind(id)
    .execute(&state.pool)
    .await?;

    Ok(Json(json!({ "id": id, "vote": req.vote, "recorded": true })))
}
