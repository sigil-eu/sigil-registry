-- Migration 0004: Extended scanner patterns and security policies
-- SIGIL Registry — official maintainer seed, 2026-02-21
--
-- Adds 18 scanner patterns (AI providers, SaaS tokens, EU PII expansion)
-- and 10 security policies (infrastructure tools, advanced MCP tools).
-- All entries are verified = TRUE and submitted by maintainers (author_did IS NULL).
-- Safe to re-run: ON CONFLICT DO NOTHING.

-- ── Extended Scanner Patterns ──────────────────────────────────────────────

INSERT INTO scanner_patterns
    (name, description, category, pattern, replacement_hint, severity, verified)
VALUES

-- AI / LLM providers
('huggingface_token',
 'Hugging Face API token (hf_ prefix). Used for model downloads and inference.',
 'credential',
 'hf_[a-zA-Z0-9]{34,}',
 '[SIGIL-VAULT: HF_TOKEN]',
 'high',
 TRUE),

('replicate_api_token',
 'Replicate.com API token (r8_ prefix). Grants access to hosted model inference.',
 'credential',
 'r8_[a-zA-Z0-9]{38,}',
 '[SIGIL-VAULT: REPLICATE_TOKEN]',
 'high',
 TRUE),

('cohere_api_key',
 'Cohere API key. Grants access to language model inference endpoints.',
 'credential',
 'co-[a-zA-Z0-9]{40,}',
 '[SIGIL-VAULT: COHERE_KEY]',
 'high',
 TRUE),

('together_ai_key',
 'Together AI API key. Used for open-source model inference.',
 'credential',
 'together-[a-zA-Z0-9\-]{40,}',
 '[SIGIL-VAULT: TOGETHER_KEY]',
 'high',
 TRUE),

-- SaaS / Payment
('stripe_secret_key',
 'Stripe live secret key. Full access to charges, customers, and payouts.',
 'credential',
 'sk_live_[0-9a-zA-Z]{24,}',
 '[SIGIL-VAULT: STRIPE_SECRET]',
 'critical',
 TRUE),

('stripe_restricted_key',
 'Stripe restricted API key with limited scope permissions.',
 'credential',
 'rk_live_[0-9a-zA-Z]{24,}',
 '[SIGIL-VAULT: STRIPE_RESTRICTED]',
 'high',
 TRUE),

('twilio_account_sid',
 'Twilio Account SID. Identifies the Twilio account for API calls.',
 'credential',
 'AC[0-9a-f]{32}',
 '[SIGIL-VAULT: TWILIO_SID]',
 'high',
 TRUE),

('twilio_auth_token',
 'Twilio Auth Token. Combined with Account SID grants full API access.',
 'secret',
 '^[0-9a-f]{32}$',
 '[SIGIL-VAULT: TWILIO_TOKEN]',
 'critical',
 TRUE),

('sendgrid_api_key',
 'SendGrid API key. Grants email send and domain configuration access.',
 'credential',
 'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
 '[SIGIL-VAULT: SENDGRID_KEY]',
 'high',
 TRUE),

('slack_bot_token',
 'Slack bot OAuth token. Grants access to workspace messages, channels, and users.',
 'credential',
 'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
 '[SIGIL-VAULT: SLACK_BOT_TOKEN]',
 'high',
 TRUE),

('slack_user_token',
 'Slack user OAuth token. Acts on behalf of a real user in the workspace.',
 'credential',
 'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32,}',
 '[SIGIL-VAULT: SLACK_USER_TOKEN]',
 'critical',
 TRUE),

('shopify_access_token',
 'Shopify Admin API access token. Full store management access.',
 'credential',
 'shpat_[a-fA-F0-9]{32}',
 '[SIGIL-VAULT: SHOPIFY_TOKEN]',
 'critical',
 TRUE),

('cloudflare_api_key',
 'Cloudflare Global API Key. Full account access including DNS and WAF.',
 'credential',
 '(?i)cloudflare(.{0,20})([0-9a-f]{37})',
 '[SIGIL-VAULT: CF_API_KEY]',
 'critical',
 TRUE),

('hashicorp_vault_token',
 'HashiCorp Vault token (s. or hvs. prefix). Root or service tokens grant secret store access.',
 'secret',
 '(hvs\.|s\.)[A-Za-z0-9]{24,}',
 '[SIGIL-VAULT: VAULT_TOKEN]',
 'critical',
 TRUE),

('docker_hub_token',
 'Docker Hub personal access token (dckr_pat_ prefix).',
 'credential',
 'dckr_pat_[a-zA-Z0-9\-_]{24,}',
 '[SIGIL-VAULT: DOCKERHUB_TOKEN]',
 'high',
 TRUE),

-- EU PII expansion (GDPR Art. 4)
('french_insee_number',
 'French INSEE/NIR social security number. EU personal data under GDPR Art. 4.',
 'pii',
 '\b[12][0-9]{2}(0[1-9]|1[0-2]|20)(2[AB]|[0-9]{2})[0-9]{3}[0-9]{3}[0-9]{2}\b',
 '[SIGIL-VAULT: FR_INSEE]',
 'critical',
 TRUE),

('dutch_bsn',
 'Dutch Burgerservicenummer (BSN). Unique personal identifier, EU personal data.',
 'pii',
 '\b[0-9]{9}\b',
 '[SIGIL-VAULT: NL_BSN]',
 'critical',
 TRUE),

('spanish_nie_nif',
 'Spanish NIF/NIE national identity number (e.g. 12345678A or X1234567A).',
 'pii',
 '\b([XYZ][0-9]{7}[A-Z]|[0-9]{8}[A-HJ-NP-TV-Z])\b',
 '[SIGIL-VAULT: ES_NIF_NIE]',
 'critical',
 TRUE),

('italian_codice_fiscale',
 'Italian Codice Fiscale (tax code). 16-character alphanumeric personal identifier.',
 'pii',
 '\b[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]\b',
 '[SIGIL-VAULT: IT_CF]',
 'critical',
 TRUE)

ON CONFLICT (name) DO NOTHING;


-- ── Extended Security Policies ─────────────────────────────────────────────

INSERT INTO security_policies
    (tool_name, risk_level, requires_trust, requires_confirmation, rationale, verified)
VALUES

('send_webhook',
 'high',
 'High',
 TRUE,
 'Sends data to an arbitrary external URL. Risk of data exfiltration and SSRF attacks. Requires explicit user confirmation and High trust.',
 TRUE),

('write_environment_variable',
 'critical',
 'High',
 TRUE,
 'Modifies process environment variables. Can alter credentials, paths, or behaviour for all subsequent tool calls in the session.',
 TRUE),

('install_package',
 'critical',
 'High',
 TRUE,
 'Installs system or language packages. Supply chain attack vector. Packages can contain malicious code with full host access.',
 TRUE),

('deploy_infrastructure',
 'critical',
 'High',
 TRUE,
 'Creates or modifies cloud infrastructure. Can incur cost, expose services, or destroy production resources.',
 TRUE),

('modify_dns',
 'critical',
 'High',
 TRUE,
 'Changes DNS records. Can redirect traffic, intercept communications, or cause service outages.',
 TRUE),

('spawn_browser',
 'high',
 'High',
 FALSE,
 'Launches a browser automation session. Can access authenticated sites and exfiltrate session data.',
 TRUE),

('spawn_subprocess',
 'critical',
 'High',
 TRUE,
 'Spawns an arbitrary child process. Equivalent in risk to execute_command. Can escape tool sandboxing.',
 TRUE),

('bind_port',
 'medium',
 'Medium',
 FALSE,
 'Opens a network port on the host. Can expose services to the network unexpectedly.',
 TRUE),

('write_config_file',
 'high',
 'High',
 TRUE,
 'Writes application configuration files (e.g. ~/.ssh/config, /etc/hosts). Can persist malicious settings across sessions.',
 TRUE),

('read_environment_variable',
 'medium',
 'Medium',
 FALSE,
 'Reads process environment variables. May expose credentials, API keys, or tokens set in the shell environment.',
 TRUE)

ON CONFLICT DO NOTHING;
