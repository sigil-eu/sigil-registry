//! Domain models for the SIGIL Registry.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Serialize)]
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
