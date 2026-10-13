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
  /** D-16: CRL inputs of the e-CNPJ (public data; null on credentials issued before it). */
  certificate_serial: string | null;
  certificate_issuer_der: string | null;
  certificate_crl_urls: string | null;
  last_revocation_check_at: string | null;
  suspension_cause: SuspensionCause | null;
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

/** Why a credential is suspended: the review reinstates only what it suspended for a reason that can clear. */
export type SuspensionCause = "registration" | "certificate" | "wallet";

/** What the e-CNPJ proof leaves for the revocation checks (serial, AC certificate, CRL URLs). */
export interface CertificateRecord {
  sha256: string;
  subject: string;
  issuer: string;
  signed_at: string;
  serial_number: string;
  issuer_certificate: string | null;
  crl_urls: string[];
  revocation_checked_at: string;
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

  async issue(p: { id: string; legal_name: string; credential: Credential; certificate: CertificateRecord; mandate: Mandate; event: "issued" | "renewed" }): Promise<void> {
    const c = p.certificate;
    await this.db.batch([
      this.db
        .prepare(
          "UPDATE agents SET status = 'active', status_reason = NULL, suspension_cause = NULL, legal_name = ?2, mandate = ?3, certificate_sha256 = ?4, certificate_subject = ?5, certificate_issuer = ?6, authorized_at = ?7, credential = ?8, issued_at = ?9, expires_at = ?10, last_kyb_at = ?11, updated_at = ?11, certificate_serial = ?12, certificate_issuer_der = ?13, certificate_crl_urls = ?14, last_revocation_check_at = ?15 WHERE id = ?1"
        )
        .bind(p.id, p.legal_name, JSON.stringify(p.mandate), c.sha256, c.subject, c.issuer, c.signed_at, JSON.stringify(p.credential), p.credential.issued_at, p.credential.expires_at, now(), c.serial_number, c.issuer_certificate, JSON.stringify(c.crl_urls), c.revocation_checked_at),
      this.db.prepare("INSERT INTO credential_events (agent_row, event, actor) VALUES (?1, ?2, 'company')").bind(p.id, p.event)
    ]);
  }

  async setStatus(p: { id: string; status: CredentialStatus; reason: string | null; actor: "company" | "cron" | "issuer"; cause?: SuspensionCause; credential?: Credential | null; last_kyb_at?: string }): Promise<void> {
    const event = p.status === "revoked" ? "revoked" : p.status === "suspended" ? "suspended" : p.status === "active" ? "reinstated" : p.status;
    await this.db.batch([
      this.db
        .prepare("UPDATE agents SET status = ?2, status_reason = ?3, credential = COALESCE(?4, credential), last_kyb_at = COALESCE(?5, last_kyb_at), suspension_cause = ?7, updated_at = ?6 WHERE id = ?1")
        .bind(p.id, p.status, p.reason, p.credential ? JSON.stringify(p.credential) : null, p.last_kyb_at ?? null, now(), p.status === "suspended" ? (p.cause ?? null) : null),
      this.db.prepare("INSERT INTO credential_events (agent_row, event, reason, actor) VALUES (?1, ?2, ?3, ?4)").bind(p.id, event, p.reason, p.actor)
    ]);
  }

  async markReviewed(id: string, p: { last_kyb_at?: string; last_revocation_check_at?: string }): Promise<void> {
    await this.db.prepare("UPDATE agents SET last_kyb_at = COALESCE(?2, last_kyb_at), last_revocation_check_at = COALESCE(?3, last_revocation_check_at) WHERE id = ?1").bind(id, p.last_kyb_at ?? null, p.last_revocation_check_at ?? null).run();
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
