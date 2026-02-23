// SPDX-License-Identifier: EUPL-1.2
// Copyright (c) 2026 Benjamin Küttner <benjamin.kuettner@icloud.com>
// Patent Pending — DE Gebrauchsmuster, filed 2026-02-23

//! Ed25519 signature verification for community submissions.
//!
//! Every `POST /patterns` and `POST /policies` request must include a signature
//! produced by the author's private key (corresponding to their registered
//! `did:sigil:` public key). This prevents spam and ensures accountability.
//!
//! ## Canonical message format
//!
//! For pattern submissions, the message to sign is:
//! ```text
//! sigil-registry:pattern:{name}:{category}:{pattern}:{author_did}
//! ```
//!
//! For policy submissions:
//! ```text
//! sigil-registry:policy:{tool_name}:{risk_level}:{requires_trust}:{author_did}
//! ```
//!
//! For votes:
//! ```text
//! sigil-registry:vote:{target_type}:{target_id}:{vote}:{voter_did}
//! ```

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};

/// Verify an Ed25519 signature over a message.
///
/// - `public_key_b64` — base64url-encoded 32-byte Ed25519 public key (from DID record)
/// - `message`       — the canonical message that was signed
/// - `signature_b64` — base64url-encoded 64-byte Ed25519 signature
pub fn verify_signature(
    public_key_b64: &str,
    message: &str,
    signature_b64: &str,
) -> Result<(), String> {
    // Decode public key
    let pk_bytes = URL_SAFE_NO_PAD
        .decode(public_key_b64)
        .map_err(|e| format!("bad public key encoding: {e}"))?;

    let pk_bytes: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;

    let verifying_key =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|e| format!("invalid public key: {e}"))?;

    // Decode signature
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| format!("bad signature encoding: {e}"))?;

    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;

    let signature = Signature::from_bytes(&sig_bytes);

    // Verify
    use ed25519_dalek::Verifier;
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|e| format!("signature verification failed: {e}"))
}

/// Build the canonical message for a pattern submission.
pub fn pattern_message(name: &str, category: &str, pattern: &str, author_did: &str) -> String {
    format!("sigil-registry:pattern:{name}:{category}:{pattern}:{author_did}")
}

/// Build the canonical message for a policy submission.
pub fn policy_message(
    tool_name: &str,
    risk_level: &str,
    requires_trust: &str,
    author_did: &str,
) -> String {
    format!("sigil-registry:policy:{tool_name}:{risk_level}:{requires_trust}:{author_did}")
}

/// Build the canonical message for a vote.
pub fn vote_message(target_type: &str, target_id: &str, vote: &str, voter_did: &str) -> String {
    format!("sigil-registry:vote:{target_type}:{target_id}:{vote}:{voter_did}")
}
