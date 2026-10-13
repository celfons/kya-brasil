-- D-19: the issuer no longer records what agents do (the acts registry, D-14, is removed; it had no rows).
DROP INDEX IF EXISTS idx_acts_agent_day;
DROP TABLE IF EXISTS acts;

-- D-20: one webhook per company (CNPJ) for signed events about its agents. signed_at is the `at:` of the last
-- accepted e-CNPJ-signed request, so an older request cannot be replayed over a newer one.
CREATE TABLE IF NOT EXISTS company_webhooks (
  cnpj TEXT PRIMARY KEY,
  url TEXT,                               -- null when removed
  signed_at TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
