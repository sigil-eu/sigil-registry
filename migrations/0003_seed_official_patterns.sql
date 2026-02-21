-- SIGIL Registry — Migration 0003: Official Seed Data
--
-- Seeds the registry with SIGIL-curated scanner patterns and security policies.
-- All entries are marked verified=TRUE and author_did=NULL (maintainer-submitted).
-- Uses ON CONFLICT DO NOTHING so re-running is safe.

-- ══════════════════════════════════════════════════════════════════════════════
-- SCANNER PATTERNS
-- ══════════════════════════════════════════════════════════════════════════════

INSERT INTO scanner_patterns (name, description, category, pattern, replacement_hint, severity, verified) VALUES

-- ── Cloud Credentials ─────────────────────────────────────────────────────────

(
  'aws_access_key_id',
  'Amazon Web Services Access Key ID (AKIA/ABIA/ACCA/ASIA prefix). Exposure grants API access to the associated AWS account.',
  'credential',
  '(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
  '[SIGIL-VAULT: AWS_KEY_ID]',
  'critical',
  TRUE
),
(
  'aws_secret_access_key',
  'Amazon Web Services Secret Access Key. Always paired with an Access Key ID; together they grant full programmatic AWS access.',
  'secret',
  '(?i)aws[_\-\s]{0,20}secret[_\-\s]{0,20}(access[_\-\s]{0,10})?key[_\-\s]{0,10}[=:"\s]{0,5}[0-9a-zA-Z/+]{40}',
  '[SIGIL-VAULT: AWS_SECRET_KEY]',
  'critical',
  TRUE
),
(
  'gcp_service_account_key',
  'Google Cloud Platform service account private key JSON blob. Grants access to GCP resources as the associated service account.',
  'secret',
  '"type"\s*:\s*"service_account"',
  '[SIGIL-VAULT: GCP_SA_KEY]',
  'critical',
  TRUE
),
(
  'azure_client_secret',
  'Azure Active Directory client secret. Used in OAuth2 client-credentials flow to authenticate as an app registration.',
  'credential',
  '(?i)(azure|aad)[_\-\s]{0,10}(client[_\-\s]{0,10})?secret[_\-\s]{0,10}[=:"\s]{0,5}[a-zA-Z0-9_\-\.~]{20,}',
  '[SIGIL-VAULT: AZURE_SECRET]',
  'critical',
  TRUE
),

-- ── Source Control & CI Tokens ────────────────────────────────────────────────

(
  'github_personal_access_token',
  'GitHub fine-grained or classic personal access token (ghp_ / github_pat_ prefix).',
  'credential',
  'gh[pousr]_[0-9a-zA-Z]{36,255}',
  '[SIGIL-VAULT: GITHUB_TOKEN]',
  'critical',
  TRUE
),
(
  'gitlab_personal_access_token',
  'GitLab personal or project access token (glpat- prefix).',
  'credential',
  'glpat-[0-9a-zA-Z\-]{20}',
  '[SIGIL-VAULT: GITLAB_TOKEN]',
  'high',
  TRUE
),
(
  'npm_access_token',
  'npm registry access token (npm_- prefix). Grants publish rights to package namespaces.',
  'credential',
  'npm_[0-9a-zA-Z]{36}',
  '[SIGIL-VAULT: NPM_TOKEN]',
  'high',
  TRUE
),

-- ── AI / LLM API Keys ─────────────────────────────────────────────────────────

(
  'openai_api_key',
  'OpenAI API secret key (sk- prefix). Grants access to GPT-4, DALL-E, and all OpenAI API endpoints.',
  'credential',
  'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}',
  '[SIGIL-VAULT: OPENAI_KEY]',
  'critical',
  TRUE
),
(
  'openai_api_key_generic',
  'Generic OpenAI-style API key pattern (sk- followed by 40+ chars). Catches both legacy and new key formats.',
  'credential',
  'sk-[a-zA-Z0-9\-_]{40,}',
  '[SIGIL-VAULT: OPENAI_KEY]',
  'high',
  TRUE
),
(
  'anthropic_api_key',
  'Anthropic Claude API key (sk-ant- prefix).',
  'credential',
  'sk-ant-[a-zA-Z0-9\-_]{40,}',
  '[SIGIL-VAULT: ANTHROPIC_KEY]',
  'critical',
  TRUE
),

-- ── Auth / Session Tokens ─────────────────────────────────────────────────────

(
  'jwt_token',
  'JSON Web Token (three base64url segments). May contain user identity, permissions, or session data.',
  'credential',
  'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
  '[SIGIL-VAULT: JWT]',
  'high',
  TRUE
),
(
  'bearer_token',
  'HTTP Authorization Bearer token (any value after "Bearer "). Grants API access as the token holder.',
  'credential',
  '(?i)bearer\s+[a-zA-Z0-9\-_\.=+/]{20,}',
  '[SIGIL-VAULT: BEARER_TOKEN]',
  'high',
  TRUE
),
(
  'private_key_pem',
  'PEM-encoded private key block (RSA, EC, Ed25519, or PKCS#8). Direct exposure compromises the associated identity or TLS certificate.',
  'secret',
  '-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----',
  '[SIGIL-VAULT: PRIVATE_KEY]',
  'critical',
  TRUE
),
(
  'ssh_private_key',
  'OpenSSH private key block. Grants SSH access to any servers this key is authorized on.',
  'secret',
  '-----BEGIN OPENSSH PRIVATE KEY-----',
  '[SIGIL-VAULT: SSH_KEY]',
  'critical',
  TRUE
),

-- ── EU Financial (GDPR & PSD2) ────────────────────────────────────────────────

(
  'eu_iban',
  'European IBAN bank account number. Classified as financial data under GDPR Art. 9 and PSD2. Two-letter country code + check digits + BBAN.',
  'financial',
  '\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]{0,16})\b',
  '[SIGIL-VAULT: IBAN]',
  'critical',
  TRUE
),
(
  'credit_card_number',
  'Credit/debit card number (Visa, Mastercard, Amex, Discover). PCI-DSS requires this never appears in plain text.',
  'financial',
  '\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
  '[SIGIL-VAULT: CARD_NUMBER]',
  'critical',
  TRUE
),
(
  'credit_card_formatted',
  'Credit card number in formatted display (groups of 4 digits separated by spaces or dashes).',
  'financial',
  '\b[0-9]{4}[\s\-][0-9]{4}[\s\-][0-9]{4}[\s\-][0-9]{4}\b',
  '[SIGIL-VAULT: CARD_NUMBER]',
  'high',
  TRUE
),

-- ── EU PII (GDPR) ─────────────────────────────────────────────────────────────

(
  'email_address',
  'Email address. Constitutes personal data under GDPR Art. 4(1). Exposure may enable phishing or account enumeration.',
  'pii',
  '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
  '[SIGIL-VAULT: EMAIL]',
  'medium',
  TRUE
),
(
  'eu_phone_number',
  'European phone number with international prefix (+3x, +4x, +35x, +36x). PII under GDPR.',
  'pii',
  '\+(?:3[0-9]|4[0-9]|35[0-9]|36[0-9])[0-9\s\-()]{7,15}',
  '[SIGIL-VAULT: PHONE]',
  'medium',
  TRUE
),
(
  'ipv4_address_private',
  'Private IPv4 address (RFC 1918: 10.x, 172.16-31.x, 192.168.x). Leaks internal network topology.',
  'pii',
  '\b(?:10\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b',
  '[SIGIL-VAULT: INTERNAL_IP]',
  'medium',
  TRUE
),
(
  'german_vat_id',
  'German VAT (Umsatzsteuer-Identifikationsnummer). Format: DE + 9 digits. Business PII under GDPR.',
  'pii',
  '\bDE[0-9]{9}\b',
  '[SIGIL-VAULT: VAT_ID]',
  'medium',
  TRUE
),
(
  'eu_national_id_de',
  'German national ID or tax ID (Steueridentifikationsnummer). 11-digit number. Sensitive PII under GDPR Art. 9.',
  'pii',
  '\b[0-9]{2}\s?[0-9]{3}\s?[0-9]{3}\s?[0-9]{3}\b',
  '[SIGIL-VAULT: NATIONAL_ID]',
  'high',
  TRUE
),

-- ── Database / Connection Strings ─────────────────────────────────────────────

(
  'database_connection_url',
  'Database connection URL with embedded credentials (postgres://, mysql://, mongodb://, etc.).',
  'secret',
  '(?i)(postgres|mysql|mongodb|redis|mssql)://[^:]+:[^@]+@[a-zA-Z0-9.\-]+(:[0-9]+)?/[a-zA-Z0-9_\-]+',
  '[SIGIL-VAULT: DB_URL]',
  'critical',
  TRUE
),
(
  'generic_password_field',
  'Generic password assignment in config/code (password=, passwd=, pwd=, secret=). High false-positive rate — use in combination with other rules.',
  'secret',
  '(?i)(password|passwd|pwd|secret)\s*[=:]\s*["\x27][^"\x27\s]{6,}["\x27]',
  '[SIGIL-VAULT: PASSWORD]',
  'high',
  TRUE
)

ON CONFLICT (name) DO NOTHING;


-- ══════════════════════════════════════════════════════════════════════════════
-- SECURITY POLICIES
-- ══════════════════════════════════════════════════════════════════════════════
-- Canonical MCP tool risk classifications from the SIGIL Spec §8.
-- Mirror the built-in SecurityPolicy::default() rules in sigil-protocol crate.

INSERT INTO security_policies (tool_name, risk_level, requires_trust, requires_confirmation, rationale, verified) VALUES

-- ── File System ───────────────────────────────────────────────────────────────
(
  'read_file',
  'medium',
  'Medium',
  FALSE,
  'Reads arbitrary files from the host filesystem. May expose secrets, private keys, or configuration. Requires verified host identity.',
  TRUE
),
(
  'write_file',
  'high',
  'High',
  TRUE,
  'Writes to the host filesystem. Can overwrite credentials, inject code, or corrupt application state. Requires High trust and explicit confirmation.',
  TRUE
),
(
  'delete_file',
  'critical',
  'High',
  TRUE,
  'Permanently deletes files. Irreversible data loss risk. Always requires High trust and user confirmation.',
  TRUE
),
(
  'list_directory',
  'low',
  'Low',
  FALSE,
  'Lists directory contents. Low risk but leaks filesystem structure and file names. Safe for most verified agents.',
  TRUE
),

-- ── Code / Shell Execution ────────────────────────────────────────────────────
(
  'execute_command',
  'critical',
  'High',
  TRUE,
  'Executes arbitrary shell commands. Full host compromise possible. Only permitted for High-trust agents with explicit confirmation.',
  TRUE
),
(
  'execute_python',
  'critical',
  'High',
  TRUE,
  'Executes arbitrary Python code. Equivalent to shell execution in risk. High trust + confirmation mandatory.',
  TRUE
),
(
  'execute_javascript',
  'critical',
  'High',
  TRUE,
  'Executes arbitrary JavaScript. Can exfiltrate data, install malware, or manipulate UI. High trust + confirmation mandatory.',
  TRUE
),
(
  'run_terminal_command',
  'critical',
  'High',
  TRUE,
  'Alias for execute_command. Full shell access risk.',
  TRUE
),

-- ── Database ──────────────────────────────────────────────────────────────────
(
  'execute_sql',
  'high',
  'High',
  TRUE,
  'Executes SQL queries. DROP, DELETE, or UPDATE without WHERE can cause irreversible data loss. Requires High trust and confirmation.',
  TRUE
),
(
  'query_database',
  'medium',
  'Medium',
  FALSE,
  'Read-only database query. May expose PII or sensitive business data. Requires Medium trust.',
  TRUE
),

-- ── Network / HTTP ────────────────────────────────────────────────────────────
(
  'http_request',
  'medium',
  'Medium',
  FALSE,
  'Makes outbound HTTP requests. Can be used for SSRF, data exfiltration, or C2 communication. Requires Medium trust.',
  TRUE
),
(
  'fetch_url',
  'medium',
  'Medium',
  FALSE,
  'Fetches a URL. Same risk profile as http_request — SSRF and exfiltration vectors apply.',
  TRUE
),
(
  'send_email',
  'high',
  'High',
  TRUE,
  'Sends email on behalf of the user. Phishing, spam, and reputation damage risk. High trust + confirmation required.',
  TRUE
),
(
  'send_slack_message',
  'medium',
  'Medium',
  FALSE,
  'Posts to a Slack channel or user. Can impersonate, spam, or leak data. Medium trust required.',
  TRUE
),

-- ── Identity / Auth ───────────────────────────────────────────────────────────
(
  'get_credentials',
  'critical',
  'High',
  TRUE,
  'Retrieves credentials or tokens. Direct secret exfiltration risk. Only permitted with High trust and explicit confirmation.',
  TRUE
),
(
  'authenticate',
  'high',
  'High',
  FALSE,
  'Performs authentication on behalf of the agent. Credential exposure risk. Requires High trust.',
  TRUE
),
(
  'create_api_key',
  'critical',
  'High',
  TRUE,
  'Creates a new API key or token. Privilege escalation risk. High trust + confirmation required.',
  TRUE
),

-- ── Low-risk Utility Tools ────────────────────────────────────────────────────
(
  'get_current_time',
  'low',
  'Low',
  FALSE,
  'Returns the current date/time. No sensitive data access. Safe for all verified agents.',
  TRUE
),
(
  'calculate',
  'low',
  'Low',
  FALSE,
  'Performs mathematical calculation. No data access. Safe for all agents.',
  TRUE
),
(
  'search_web',
  'low',
  'Low',
  FALSE,
  'Searches the public web. Low risk but results may be used to construct phishing content. Low trust sufficient.',
  TRUE
),
(
  'get_weather',
  'low',
  'Low',
  FALSE,
  'Fetches weather data from a public API. No sensitive data involved.',
  TRUE
),
(
  'translate_text',
  'low',
  'Low',
  FALSE,
  'Translates text. Passes content to a third-party service — avoid with sensitive data.',
  TRUE
),

-- ── MCP / SIGIL Meta ──────────────────────────────────────────────────────────
(
  'drop_table',
  'critical',
  'High',
  TRUE,
  'Drops a database table. Causes irreversible data loss. Always requires High trust and explicit user confirmation per SIGIL Spec §8.',
  TRUE
),
(
  'truncate_table',
  'critical',
  'High',
  TRUE,
  'Truncates a database table. All rows permanently deleted. Requires High trust and confirmation.',
  TRUE
),
(
  'grant_permissions',
  'critical',
  'High',
  TRUE,
  'Grants database or system permissions. Privilege escalation vector. High trust + confirmation mandatory.',
  TRUE
)

ON CONFLICT DO NOTHING;
