-- Acts: what an agent did, registered by the party that accepted it (or by the agent), checked against
-- the mandate and signed. Only metadata and an optional content hash; never the content itself.
CREATE TABLE IF NOT EXISTS acts (
  id TEXT PRIMARY KEY,                    -- act_id (uuid)
  agent_row TEXT NOT NULL REFERENCES agents(id),
  ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  day TEXT NOT NULL,                      -- UTC date, the unit of max_per_day
  action TEXT NOT NULL,
  amount REAL,
  currency TEXT,
  counterparty TEXT,
  reference TEXT,
  content_sha256 TEXT,
  registered_by TEXT NOT NULL,            -- 'counterparty' | 'agent'
  registrant TEXT,
  agent_signed INTEGER NOT NULL DEFAULT 0,
  allowed INTEGER NOT NULL,
  receipt TEXT NOT NULL                   -- JSON, the signed receipt returned to the registrant
);
CREATE INDEX IF NOT EXISTS idx_acts_agent_day ON acts(agent_row, day);
CREATE INDEX IF NOT EXISTS idx_acts_agent_ts ON acts(agent_row, ts);
