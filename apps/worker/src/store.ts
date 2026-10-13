/** D1 persistence for agents, challenges and events. Rows never carry personal data. */
import type { AgentKey, Credential, CredentialStatus, Mandate } from "@kya-br/core";
import type { AppEnv } from "./env";

export interface AgentRow {
  id: string;
  agent_kind: AgentKey["kind"];
  agent_id: string;
  /** erc8004: agentWallet resolved at issuance. */
  agent_wallet: string | null;
  cnpj: string;
  legal_name: string | null;
  mandate: string;
  status: CredentialStatus;
  status_reason: string | null;
  certificate_sha256: string | null;
  certificate_subject: string | null;
  certificate_issuer: string | null;
  authorized_at: string | null;
  credential: string | null;
  issued_at: string | null;
  expires_at: string | null;
  last_kyb_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ActRow {
  id: string;
  agent_row: string;
  ts: string;
  day: string;
  action: string;
  amount: number | null;
  currency: string | null;
  counterparty: string | null;
  reference: string | null;
  content_sha256: string | null;
  registered_by: "counterparty" | "agent";
  registrant: string | null;
  agent_signed: number;
  allowed: number;
  receipt: string;
}

export interface ChallengeRow {
  id: string;
  agent_row: string;
  text: string;
  expires_at: string;
  used_at: string | null;
}

const now = () => new Date().toISOString();

export class Store {
  constructor(private db: D1Database) {}

  async createAgent(p: { id: string; agent: AgentKey; cnpj: string; mandate: Mandate }): Promise<void> {
    await this.db
      .prepare("INSERT INTO agents (id, agent_kind, agent_id, agent_wallet, cnpj, mandate, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending')")
      .bind(p.id, p.agent.kind, p.agent.id, p.agent.wallet ?? null, p.cnpj, JSON.stringify(p.mandate))
      .run();
  }

  async setWallet(id: string, wallet: string | null): Promise<void> {
    await this.db.prepare("UPDATE agents SET agent_wallet = ?2, updated_at = ?3 WHERE id = ?1").bind(id, wallet, now()).run();
  }

  async findByKey(agent: AgentKey, cnpj: string): Promise<AgentRow | null> {
    return (await this.db.prepare("SELECT * FROM agents WHERE agent_kind = ?1 AND agent_id = ?2 AND cnpj = ?3").bind(agent.kind, agent.id, cnpj).first<AgentRow>()) ?? null;
  }

  async findActiveByKey(agent: AgentKey): Promise<AgentRow[]> {
    const { results } = await this.db.prepare("SELECT * FROM agents WHERE agent_kind = ?1 AND agent_id = ?2 AND status = 'active' ORDER BY issued_at DESC").bind(agent.kind, agent.id).all<AgentRow>();
    return results;
  }

  async get(id: string): Promise<AgentRow | null> {
    return (await this.db.prepare("SELECT * FROM agents WHERE id = ?1").bind(id).first<AgentRow>()) ?? null;
  }

  async createChallenge(c: { id: string; agent_row: string; text: string; expires_at: string }): Promise<void> {
    await this.db.prepare("INSERT INTO challenges (id, agent_row, text, expires_at) VALUES (?1, ?2, ?3, ?4)").bind(c.id, c.agent_row, c.text, c.expires_at).run();
  }

  async takeChallenge(id: string, agent_row: string): Promise<ChallengeRow | null> {
    const row = await this.db.prepare("SELECT * FROM challenges WHERE id = ?1 AND agent_row = ?2").bind(id, agent_row).first<ChallengeRow>();
    if (!row || row.used_at || Date.parse(row.expires_at) < Date.now()) return null;
    await this.db.prepare("UPDATE challenges SET used_at = ?1 WHERE id = ?2").bind(now(), id).run();
    return row;
  }

  async issue(p: { id: string; legal_name: string; credential: Credential; certificate: { sha256: string; subject: string; issuer: string; signed_at: string }; mandate: Mandate; event: "issued" | "renewed" }): Promise<void> {
    await this.db.batch([
      this.db
        .prepare("UPDATE agents SET status = 'active', status_reason = NULL, legal_name = ?2, mandate = ?3, certificate_sha256 = ?4, certificate_subject = ?5, certificate_issuer = ?6, authorized_at = ?7, credential = ?8, issued_at = ?9, expires_at = ?10, last_kyb_at = ?11, updated_at = ?11 WHERE id = ?1")
        .bind(p.id, p.legal_name, JSON.stringify(p.mandate), p.certificate.sha256, p.certificate.subject, p.certificate.issuer, p.certificate.signed_at, JSON.stringify(p.credential), p.credential.issued_at, p.credential.expires_at, now()),
      this.db.prepare("INSERT INTO credential_events (agent_row, event, actor) VALUES (?1, ?2, 'company')").bind(p.id, p.event)
    ]);
  }

  async setStatus(p: { id: string; status: CredentialStatus; reason: string | null; actor: "company" | "cron" | "issuer"; credential?: Credential | null; last_kyb_at?: string }): Promise<void> {
    const event = p.status === "revoked" ? "revoked" : p.status === "suspended" ? "suspended" : p.status === "active" ? "reinstated" : p.status;
    await this.db.batch([
      this.db
        .prepare("UPDATE agents SET status = ?2, status_reason = ?3, credential = COALESCE(?4, credential), last_kyb_at = COALESCE(?5, last_kyb_at), updated_at = ?6 WHERE id = ?1")
        .bind(p.id, p.status, p.reason, p.credential ? JSON.stringify(p.credential) : null, p.last_kyb_at ?? null, now()),
      this.db.prepare("INSERT INTO credential_events (agent_row, event, reason, actor) VALUES (?1, ?2, ?3, ?4)").bind(p.id, event, p.reason, p.actor)
    ]);
  }

  async events(id: string): Promise<{ ts: string; event: string; reason: string | null; actor: string }[]> {
    const { results } = await this.db.prepare("SELECT ts, event, reason, actor FROM credential_events WHERE agent_row = ?1 ORDER BY ts").bind(id).all<{ ts: string; event: string; reason: string | null; actor: string }>();
    return results;
  }

  /** Credentials to re-evaluate: active or suspended, not expired. */
  async dueForReview(limit = 500): Promise<AgentRow[]> {
    const { results } = await this.db.prepare("SELECT * FROM agents WHERE status IN ('active', 'suspended') AND expires_at > ?1 ORDER BY last_kyb_at LIMIT ?2").bind(now(), limit).all<AgentRow>();
    return results;
  }

  async revocations(sinceIso: string): Promise<{ credential_id: string; revoked_at: string; reason: string | null }[]> {
    const { results } = await this.db
      .prepare("SELECT e.agent_row AS credential_id, e.ts AS revoked_at, e.reason FROM credential_events e WHERE e.event = 'revoked' AND e.ts >= ?1 ORDER BY e.ts DESC")
      .bind(sinceIso)
      .all<{ credential_id: string; revoked_at: string; reason: string | null }>();
    return results;
  }

  async createAct(a: Omit<ActRow, "ts">): Promise<void> {
    await this.db
      .prepare("INSERT INTO acts (id, agent_row, day, action, amount, currency, counterparty, reference, content_sha256, registered_by, registrant, agent_signed, allowed, receipt) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)")
      .bind(a.id, a.agent_row, a.day, a.action, a.amount, a.currency, a.counterparty, a.reference, a.content_sha256, a.registered_by, a.registrant, a.agent_signed, a.allowed, a.receipt)
      .run();
  }

  async getAct(id: string): Promise<ActRow | null> {
    return (await this.db.prepare("SELECT * FROM acts WHERE id = ?1").bind(id).first<ActRow>()) ?? null;
  }

  async actsOfDay(agent_row: string, day: string): Promise<Pick<ActRow, "amount" | "currency" | "allowed">[]> {
    const { results } = await this.db.prepare("SELECT amount, currency, allowed FROM acts WHERE agent_row = ?1 AND day = ?2").bind(agent_row, day).all<Pick<ActRow, "amount" | "currency" | "allowed">>();
    return results;
  }

  async acts(agent_row: string, sinceIso: string, limit = 500): Promise<ActRow[]> {
    const { results } = await this.db.prepare("SELECT * FROM acts WHERE agent_row = ?1 AND ts >= ?2 ORDER BY ts DESC LIMIT ?3").bind(agent_row, sinceIso, limit).all<ActRow>();
    return results;
  }

  async counts(): Promise<Record<string, number>> {
    const { results } = await this.db.prepare("SELECT status, count(*) AS n FROM agents GROUP BY status").all<{ status: string; n: number }>();
    return Object.fromEntries(results.map((r) => [r.status, r.n]));
  }
}
