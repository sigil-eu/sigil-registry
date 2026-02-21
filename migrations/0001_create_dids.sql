-- SIGIL Registry — PostgreSQL Schema
-- Migration: 0001_create_dids.sql
--
-- This table stores DID documents for the SIGIL Protocol.
-- Each row represents a registered did:sigil: identifier with its
-- Ed25519 public key and metadata.

CREATE TABLE IF NOT EXISTS dids (
    -- The full DID string, e.g. "did:sigil:parent_01"
    did TEXT PRIMARY KEY,

    -- Ed25519 public key, base64url-encoded (32 bytes = 43 chars base64url)
    public_key TEXT NOT NULL,

    -- Owner namespace, e.g. "parent", "enterprise_gateway"
    namespace TEXT NOT NULL,

    -- Human-readable label for this DID
    label TEXT,

    -- Status: 'active' | 'revoked'
    status TEXT NOT NULL DEFAULT 'active',

    -- When the DID was first registered
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- When the DID document was last updated
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- When the DID was revoked (NULL if still active)
    revoked_at TIMESTAMPTZ
);

-- Index for fast namespace lookups
CREATE INDEX IF NOT EXISTS idx_dids_namespace ON dids(namespace);
CREATE INDEX IF NOT EXISTS idx_dids_status ON dids(status);

-- Audit log for DID lifecycle events
CREATE TABLE IF NOT EXISTS did_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did TEXT NOT NULL REFERENCES dids(did),
    event_type TEXT NOT NULL, -- 'registered' | 'revoked' | 'key_rotated'
    actor TEXT,               -- IP or agent that performed the action
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_did_events_did ON did_events(did);
