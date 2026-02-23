// SPDX-License-Identifier: EUPL-1.2
// Copyright (c) 2026 Benjamin Küttner <benjamin.kuettner@icloud.com>
// Patent Pending — DE Gebrauchsmuster, filed 2026-02-23

//! Domain models for the SIGIL Registry.
//!
//! Covers both the DID resolution layer and the crowdsourced
//! Scanner Pattern + Security Policy registry.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── DID models ────────────────────────────────────────────────────────────────

/// A registered DID document.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct DidDocument {
    /// The full DID, e.g. `did:sigil:parent_01`
    pub did: String,
    /// Ed25519 public key, base64url-encoded
    pub public_key: String,
    /// Namespace, e.g. `parent`
    pub namespace: String,
    /// Human-readable label
    pub label: Option<String>,
    /// `active` or `revoked`
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Request body for `POST /register`.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// Desired DID (must start with `did:sigil:`)
    pub did: String,
    /// Ed25519 public key, base64url-encoded
    pub public_key: String,
    /// Namespace portion of the DID
    pub namespace: String,
    /// Optional human-readable label
    pub label: Option<String>,
}

/// Response for `GET /resolve/{did}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ResolveResponse {
    pub did: String,
    pub status: String,
    pub public_key: String,
    pub namespace: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<DidDocument> for ResolveResponse {
    fn from(d: DidDocument) -> Self {
        Self {
            did: d.did,
            status: d.status,
            public_key: d.public_key,
            namespace: d.namespace,
            label: d.label,
            created_at: d.created_at,
            updated_at: d.updated_at,
            revoked_at: d.revoked_at,
        }
    }
}

// ── Scanner Pattern models ────────────────────────────────────────────────────

/// A community-submitted regex pattern for PII / secret detection.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ScannerPattern {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// `secret` | `pii` | `credential` | `financial`
    pub category: String,
    pub pattern: String,
    pub replacement_hint: Option<String>,
    /// `low` | `medium` | `high` | `critical`
    pub severity: String,
    pub author_did: Option<String>,
    pub downloads: i64,
    pub votes_up: i32,
    pub votes_down: i32,
    pub verified: bool,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request body for `POST /patterns`.
///
/// The `signature` field must be the Ed25519 signature of the canonical
/// JSON body (without `signature` key), base64url-encoded, produced by
/// the private key corresponding to `author_did`.
#[derive(Debug, Deserialize)]
pub struct CreatePatternRequest {
    pub name: String,
    pub description: Option<String>,
    /// `secret` | `pii` | `credential` | `financial`
    pub category: String,
    pub pattern: String,
    pub replacement_hint: Option<String>,
    /// `low` | `medium` | `high` | `critical`
    pub severity: Option<String>,
    /// Submitter's `did:sigil:` identifier
    pub author_did: String,
    /// Ed25519 signature over the canonical payload, base64url-encoded
    pub signature: String,
}

/// Query parameters for `GET /patterns`.
#[derive(Debug, Deserialize)]
pub struct PatternQuery {
    pub category: Option<String>,
    pub verified: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ── Security Policy models ────────────────────────────────────────────────────

/// A community-submitted risk classification for an MCP tool.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SecurityPolicy {
    pub id: Uuid,
    pub tool_name: String,
    /// `low` | `medium` | `high` | `critical`
    pub risk_level: String,
    /// `Low` | `Medium` | `High`
    pub requires_trust: String,
    pub requires_confirmation: bool,
    pub rationale: Option<String>,
    pub author_did: Option<String>,
    pub votes_up: i32,
    pub votes_down: i32,
    pub verified: bool,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request body for `POST /policies`.
#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub tool_name: String,
    /// `low` | `medium` | `high` | `critical`
    pub risk_level: String,
    /// `Low` | `Medium` | `High`
    pub requires_trust: String,
    pub requires_confirmation: Option<bool>,
    pub rationale: Option<String>,
    /// Submitter's `did:sigil:` identifier
    pub author_did: String,
    /// Ed25519 signature over the canonical payload, base64url-encoded
    pub signature: String,
}

/// Query parameters for `GET /policies`.
#[derive(Debug, Deserialize)]
pub struct PolicyQuery {
    pub tool_name: Option<String>,
    pub risk_level: Option<String>,
    pub verified: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ── Vote models ───────────────────────────────────────────────────────────────

/// Request body for `POST /patterns/:id/vote` and `POST /policies/:id/vote`.
#[derive(Debug, Deserialize)]
pub struct VoteRequest {
    /// The voter's `did:sigil:` identifier
    pub voter_did: String,
    /// `up` | `down`
    pub vote: String,
    /// Ed25519 signature over `"{target_type}:{target_id}:{vote}"`, base64url
    pub signature: String,
}

// ── Bundle models ─────────────────────────────────────────────────────────────

/// An entry in the compiled pattern bundle (`GET /patterns/bundle`).
/// This is what the `sigil-protocol` Rust crate consumes at startup.
#[derive(Debug, Serialize)]
pub struct BundleEntry {
    pub name: String,
    pub category: String,
    pub pattern: String,
    pub severity: String,
    pub replacement_hint: Option<String>,
}
