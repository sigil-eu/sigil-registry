//! Handlers for the crowdsourced Security Policy registry.
//!
//! ## Endpoints
//!
//! - `GET  /policies`            — List policies (filterable by tool_name/risk/verified)
//! - `GET  /policies/:id`        — Get a single policy
//! - `POST /policies`            — Submit a policy (requires Ed25519 signature)
//! - `POST /policies/:id/vote`   — Vote on a policy (requires Ed25519 signature)

use crate::{
    auth,
    db::AppState,
    error::RegistryError,
    models::{CreatePolicyRequest, PolicyQuery, SecurityPolicy, VoteRequest},
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

/// `GET /policies` — List security policies, optionally filtered.
pub async fn list_policies(
    State(state): State<Arc<AppState>>,
    Query(q): Query<PolicyQuery>,
) -> Result<Json<Value>, RegistryError> {
    let limit = q.limit.unwrap_or(50).min(200);
    let offset = q.offset.unwrap_or(0);

    // Build base query conditionally
    let policies = match (q.tool_name.as_deref(), q.risk_level.as_deref(), q.verified) {
        (Some(tool), None, None) => sqlx::query_as::<_, SecurityPolicy>(
            "SELECT * FROM security_policies
             WHERE active = TRUE AND tool_name = $1
             ORDER BY verified DESC, votes_up DESC LIMIT $2 OFFSET $3",
        )
        .bind(tool)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?,

        (None, Some(risk), None) => sqlx::query_as::<_, SecurityPolicy>(
            "SELECT * FROM security_policies
             WHERE active = TRUE AND risk_level = $1
             ORDER BY verified DESC, votes_up DESC LIMIT $2 OFFSET $3",
        )
        .bind(risk)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?,

        (None, None, Some(v)) => sqlx::query_as::<_, SecurityPolicy>(
            "SELECT * FROM security_policies
             WHERE active = TRUE AND verified = $1
             ORDER BY votes_up DESC LIMIT $2 OFFSET $3",
        )
        .bind(v)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?,

        (Some(tool), None, Some(v)) => sqlx::query_as::<_, SecurityPolicy>(
            "SELECT * FROM security_policies
             WHERE active = TRUE AND tool_name = $1 AND verified = $2
             ORDER BY votes_up DESC LIMIT $3 OFFSET $4",
        )
        .bind(tool)
        .bind(v)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?,

        _ => sqlx::query_as::<_, SecurityPolicy>(
            "SELECT * FROM security_policies
             WHERE active = TRUE
             ORDER BY verified DESC, votes_up DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?,
    };

    Ok(Json(json!({
        "count": policies.len(),
        "offset": offset,
        "policies": policies,
    })))
}

// ── Get one ───────────────────────────────────────────────────────────────────

/// `GET /policies/:id` — Get a single security policy by UUID.
pub async fn get_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<SecurityPolicy>, RegistryError> {
    let policy = sqlx::query_as::<_, SecurityPolicy>(
        "SELECT * FROM security_policies WHERE id = $1 AND active = TRUE",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| RegistryError::ResourceNotFound(format!("Policy {id} not found")))?;

    Ok(Json(policy))
}

// ── Create ────────────────────────────────────────────────────────────────────

/// `POST /policies` — Submit a new community security policy.
///
/// Requires a valid Ed25519 signature from the author's `did:sigil:` key.
pub async fn create_policy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<Value>), RegistryError> {
    // 1. Validate risk level
    let valid_risks = ["low", "medium", "high", "critical"];
    if !valid_risks.contains(&req.risk_level.as_str()) {
        return Err(RegistryError::Validation(format!(
            "risk_level must be one of: {}",
            valid_risks.join(", ")
        )));
    }

    // 2. Validate requires_trust
    let valid_trusts = ["Low", "Medium", "High"];
    if !valid_trusts.contains(&req.requires_trust.as_str()) {
        return Err(RegistryError::Validation(format!(
            "requires_trust must be one of: {}",
            valid_trusts.join(", ")
        )));
    }

    // 3. Validate tool_name is non-empty
    if req.tool_name.trim().is_empty() {
        return Err(RegistryError::Validation("tool_name must not be empty".into()));
    }

    // 4. Verify the author DID exists and fetch its public key
    let author_key: Option<String> = sqlx::query_scalar(
        "SELECT public_key FROM dids WHERE did = $1 AND status = 'active'",
    )
    .bind(&req.author_did)
    .fetch_optional(&state.pool)
    .await?;

    let public_key = author_key.ok_or_else(|| RegistryError::UnknownAuthor(req.author_did.clone()))?;

    // 5. Verify Ed25519 signature
    let message = auth::policy_message(
        &req.tool_name,
        &req.risk_level,
        &req.requires_trust,
        &req.author_did,
    );
    auth::verify_signature(&public_key, &message, &req.signature)
        .map_err(RegistryError::InvalidSignature)?;

    // 6. Insert (allow multiple policies per tool — community votes surface the best one)
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO security_policies
           (tool_name, risk_level, requires_trust, requires_confirmation, rationale, author_did)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id",
    )
    .bind(&req.tool_name)
    .bind(&req.risk_level)
    .bind(&req.requires_trust)
    .bind(req.requires_confirmation.unwrap_or(false))
    .bind(&req.rationale)
    .bind(&req.author_did)
    .fetch_one(&state.pool)
    .await?;

    tracing::info!(
        "New security policy submitted: '{}' (risk={}) by {}",
        req.tool_name, req.risk_level, req.author_did
    );

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "tool_name": req.tool_name,
            "status": "pending_review",
            "message": "Policy submitted. It will be verified by a SIGIL maintainer.",
        })),
    ))
}

// ── Vote ──────────────────────────────────────────────────────────────────────

/// `POST /policies/:id/vote` — Vote on a security policy.
///
/// Each DID can only vote once per policy. Requires Ed25519 signature.
pub async fn vote_policy(
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
    let message = auth::vote_message("policy", &id.to_string(), &req.vote, &req.voter_did);
    auth::verify_signature(&public_key, &message, &req.signature)
        .map_err(RegistryError::InvalidSignature)?;

    // Check policy exists
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM security_policies WHERE id = $1 AND active = TRUE)",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    if !exists {
        return Err(RegistryError::ResourceNotFound(format!("Policy {id} not found")));
    }

    // Record vote (unique constraint prevents double-voting)
    let insert_result = sqlx::query(
        "INSERT INTO registry_votes (voter_did, target_type, target_id, vote)
         VALUES ($1, 'policy', $2, $3)
         ON CONFLICT (voter_did, target_type, target_id) DO NOTHING",
    )
    .bind(&req.voter_did)
    .bind(id)
    .bind(&req.vote)
    .execute(&state.pool)
    .await?;

    if insert_result.rows_affected() == 0 {
        return Err(RegistryError::AlreadyVoted);
    }

    // Update vote counter
    let col = if req.vote == "up" { "votes_up" } else { "votes_down" };
    sqlx::query(&format!(
        "UPDATE security_policies SET {col} = {col} + 1, updated_at = NOW() WHERE id = $1"
    ))
    .bind(id)
    .execute(&state.pool)
    .await?;

    Ok(Json(json!({ "id": id, "vote": req.vote, "recorded": true })))
}
