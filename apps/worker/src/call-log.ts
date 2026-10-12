import type { AppEnv } from "./env";

export interface CallRow {
  transport: "http" | "cron" | "internal";
  tool: string;
  cnpj_root?: string | null;
  price_usd: number;
  paid: boolean;
  network?: string | null;
  payer?: string | null;
  latency_ms: number;
  error_code?: string | null;
}

export async function logCall(env: AppEnv, r: CallRow): Promise<number | null> {
  try {
    const res = await env.DB.prepare(
      "INSERT INTO call_log (transport, tool, cnpj_root, price_usd, paid, network, payer, latency_ms, error_code) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) RETURNING id"
    )
      .bind(r.transport, r.tool, r.cnpj_root ?? null, r.price_usd, r.paid ? 1 : 0, r.network ?? null, r.payer ?? null, r.latency_ms, r.error_code ?? null)
      .first<{ id: number }>();
    return res?.id ?? null;
  } catch (e) {
    console.error("call_log insert failed", e);
    return null;
  }
}

/** PAYMENT-RESPONSE header (base64 JSON) from the x402 middleware after settlement. */
export function decodeSettlementHeader(h: string | null): { success: boolean; transaction?: string; network?: string; payer?: string } | null {
  if (!h) return null;
  try {
    return JSON.parse(atob(h)) as { success: boolean; transaction?: string; network?: string; payer?: string };
  } catch {
    return null;
  }
}

export async function attachSettlement(env: AppEnv, id: number, s: { transaction?: string; network?: string; payer?: string }) {
  try {
    await env.DB.prepare("UPDATE call_log SET paid = 1, tx_hash = ?1, network = COALESCE(?2, network), payer = COALESCE(?3, payer) WHERE id = ?4").bind(s.transaction ?? null, s.network ?? null, s.payer ?? null, id).run();
  } catch (e) {
    console.error("settlement attach failed", e);
  }
}
