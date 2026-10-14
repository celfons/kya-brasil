-- D-29: natural persons as principals. principal_kind 'company' (every row before this) or 'person'.
-- For persons cnpj = '' and the CPF exists only as person_hash, HMAC-SHA256 with a secret key (version in
-- person_key_version). No name, no CPF, no certificate subject. person_hash is cleared, and the checks below
-- deleted, when the credential is revoked or expires.
ALTER TABLE agents ADD COLUMN principal_kind TEXT NOT NULL DEFAULT 'company';
ALTER TABLE agents ADD COLUMN person_hash TEXT;
ALTER TABLE agents ADD COLUMN person_key_version INTEGER;
CREATE INDEX IF NOT EXISTS idx_agents_person ON agents(person_hash);

-- Every "does this CPF match" answer, visible to the person in their inventory. verifier = payer wallet
-- (x402) or channel; matched 0/1. Non-matching answers limit the verifier (3 per credential).
CREATE TABLE IF NOT EXISTS person_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_row TEXT NOT NULL REFERENCES agents(id),
  verifier TEXT NOT NULL,
  matched INTEGER NOT NULL,
  ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_person_checks ON person_checks(agent_row, verifier);
