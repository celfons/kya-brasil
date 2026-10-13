-- Agents registered by companies. One row per (agent key, CNPJ) pair.
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,                    -- credential_id (uuid)
  agent_kind TEXT NOT NULL,               -- 'evm' | 'web-bot-auth' | 'erc8004'
  agent_id TEXT NOT NULL,                 -- checksummed address or base64url Ed25519 key
  cnpj TEXT NOT NULL,                     -- normalized 14 chars
  legal_name TEXT,
  mandate TEXT NOT NULL,                  -- JSON
  status TEXT NOT NULL,                   -- 'pending' | 'active' | 'suspended' | 'revoked'
  status_reason TEXT,
  certificate_sha256 TEXT,                -- e-CNPJ that authorized it (never the signer's CPF)
  certificate_subject TEXT,
  certificate_issuer TEXT,
  authorized_at TEXT,
  credential TEXT,                        -- JSON, the signed credential currently published
  issued_at TEXT,
  expires_at TEXT,
  last_kyb_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_key_cnpj ON agents(agent_kind, agent_id, cnpj);
CREATE INDEX IF NOT EXISTS idx_agents_cnpj ON agents(cnpj);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status, expires_at);

-- One-time challenges handed to the company at registration (agent signature + e-CNPJ signature).
CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  agent_row TEXT NOT NULL REFERENCES agents(id),
  text TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

-- Every status change, for the audit trail the credential's revocation_url exposes.
CREATE TABLE IF NOT EXISTS credential_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_row TEXT NOT NULL REFERENCES agents(id),
  ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  event TEXT NOT NULL,                    -- 'registered' | 'issued' | 'renewed' | 'suspended' | 'reinstated' | 'revoked'
  reason TEXT,
  actor TEXT                              -- 'company' | 'cron' | 'issuer'
);
CREATE INDEX IF NOT EXISTS idx_events_agent ON credential_events(agent_row, ts);

-- Every call (free or paid), same shape as KYB Brasil's call_log.
CREATE TABLE IF NOT EXISTS call_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  transport TEXT NOT NULL,
  tool TEXT NOT NULL,
  cnpj_root TEXT,
  price_usd REAL NOT NULL DEFAULT 0,
  paid INTEGER NOT NULL DEFAULT 0,
  network TEXT,
  payer TEXT,
  tx_hash TEXT,
  latency_ms INTEGER,
  error_code TEXT
);
CREATE INDEX IF NOT EXISTS idx_call_log_ts ON call_log(ts);
