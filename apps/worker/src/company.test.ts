import { describe, expect, it } from "vitest";
import { companyAgents, companyText, setCompanyWebhook } from "./company";
import type { AppEnv } from "./env";

const env = {} as AppEnv;
const CNPJ = "11222333000181";

describe("company requests (D-20)", () => {
  it("builds the text the company signs", () => {
    expect(companyText("webhook", "11.222.333/0001-81", "2026-10-13T12:00:00.000Z", ["url: https://acme.com.br/kya"])).toBe(`KYA Brasil: webhook ${CNPJ}\nurl: https://acme.com.br/kya\nat: 2026-10-13T12:00:00.000Z`);
  });

  it("rejects malformed requests before touching the e-CNPJ", async () => {
    const now = new Date().toISOString();
    await expect(companyAgents(env, "123", {})).rejects.toMatchObject({ code: "INVALID_CNPJ" });
    await expect(companyAgents(env, CNPJ, { signed_text: companyText("agents", CNPJ, now) })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(companyAgents(env, CNPJ, { signed_text: companyText("webhook", CNPJ, now), ecnpj_signature: "x" })).rejects.toThrow(/must start with/);
    const stale = new Date(Date.now() - 11 * 60_000).toISOString();
    await expect(companyAgents(env, CNPJ, { signed_text: companyText("agents", CNPJ, stale), ecnpj_signature: "x" })).rejects.toThrow(/within 10 minutes/);
    await expect(setCompanyWebhook(env, CNPJ, { signed_text: companyText("webhook", CNPJ, "not a date", ["url: -"]), ecnpj_signature: "x" })).rejects.toThrow(/within 10 minutes/);
  });
});
