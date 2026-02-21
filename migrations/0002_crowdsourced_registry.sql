-- SIGIL Registry — Migration 0002: Crowdsourced Scanner + Policy Registry
--
-- Adds two community-contributed tables:
--   1. scanner_patterns — regex rules for PII/secret detection
--   2. security_policies — tool risk classifications

-- ── Scanner Patterns ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scanner_patterns (
    -- Unique identifier
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Short machine-readable name, e.g. "aws_secret_key"
    name          TEXT NOT NULL,

    -- Human-readable description
    description   TEXT,

    -- Category: 'secret' | 'pii' | 'credential' | 'financial'
    category      TEXT NOT NULL,

    -- The regex pattern itself
    pattern       TEXT NOT NULL,

    -- Optional replacement hint shown in audit log (e.g. "[SIGIL-VAULT: AWS_KEY]")
    replacement_hint TEXT,

    -- Severity when matched: 'low' | 'medium' | 'high' | 'critical'
    severity      TEXT NOT NULL DEFAULT 'high',

    -- Submitter's did:sigil: identifier (must be registered in dids table)
    author_did    TEXT REFERENCES dids(did) ON DELETE SET NULL,

    -- Stats
    downloads     BIGINT NOT NULL DEFAULT 0,
    votes_up      INT NOT NULL DEFAULT 0,
    votes_down    INT NOT NULL DEFAULT 0,

    -- Curated by SIGIL maintainers
    verified      BOOLEAN NOT NULL DEFAULT FALSE,

    -- Active/inactive (soft delete)
    active        BOOLEAN NOT NULL DEFAULT TRUE,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_patterns_category ON scanner_patterns(category);
CREATE INDEX IF NOT EXISTS idx_patterns_verified  ON scanner_patterns(verified);
CREATE INDEX IF NOT EXISTS idx_patterns_author    ON scanner_patterns(author_did);
CREATE UNIQUE INDEX IF NOT EXISTS idx_patterns_name_uniq ON scanner_patterns(name);

-- ── Security Policies ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS security_policies (
    -- Unique identifier
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The MCP tool name this policy applies to, e.g. "execute_sql"
    tool_name       TEXT NOT NULL,

    -- Risk classification: 'low' | 'medium' | 'high' | 'critical'
    risk_level      TEXT NOT NULL,

    -- Minimum SIGIL trust level required: 'Low' | 'Medium' | 'High'
    requires_trust  TEXT NOT NULL,

    -- Whether human confirmation is required before execution
    requires_confirmation BOOLEAN NOT NULL DEFAULT FALSE,

    -- Human explanation of why this tool is classified this way
    rationale       TEXT,

    -- Submitter's did:sigil: identifier
    author_did      TEXT REFERENCES dids(did) ON DELETE SET NULL,

    -- Stats
    votes_up        INT NOT NULL DEFAULT 0,
    votes_down      INT NOT NULL DEFAULT 0,

    -- Curated by SIGIL maintainers
    verified        BOOLEAN NOT NULL DEFAULT FALSE,

    -- Active/inactive (soft delete)
    active          BOOLEAN NOT NULL DEFAULT TRUE,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policies_tool      ON security_policies(tool_name);
CREATE INDEX IF NOT EXISTS idx_policies_verified  ON security_policies(verified);
CREATE INDEX IF NOT EXISTS idx_policies_risk      ON security_policies(risk_level);

-- ── Vote Audit Log ───────────────────────────────────────────────────────────
-- Prevents a single DID from voting twice on the same entry.

CREATE TABLE IF NOT EXISTS registry_votes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    voter_did   TEXT NOT NULL REFERENCES dids(did) ON DELETE CASCADE,
    target_type TEXT NOT NULL, -- 'pattern' | 'policy'
    target_id   UUID NOT NULL,
    vote        TEXT NOT NULL, -- 'up' | 'down'
    voted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(voter_did, target_type, target_id)
);
