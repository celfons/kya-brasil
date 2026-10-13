-- D-18: only acts with a proof of origin count toward the daily total.
--   proof: 'agent_signature' (the agent signed the act text) | 'agent_request' (the agent's signed KYA request
--   that the counterparty received) | 'none' (kept as evidence, not counted).
--   counted: 1 when the act is allowed and carries a proof; the daily sum reads only these.
--   proof_sha256: SHA-256 of the proof signature, unique, so one proof cannot be registered twice.
ALTER TABLE acts ADD COLUMN proof TEXT NOT NULL DEFAULT 'none';
ALTER TABLE acts ADD COLUMN counted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE acts ADD COLUMN proof_sha256 TEXT;
UPDATE acts SET proof = 'agent_signature' WHERE agent_signed = 1;
UPDATE acts SET counted = 1 WHERE agent_signed = 1 AND allowed = 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_acts_proof ON acts(proof_sha256) WHERE proof_sha256 IS NOT NULL;
