import { afterEach, describe, expect, it, vi } from "vitest";
import { companyRegistration, registrationOrWarning, registrationSources } from "./registration";
import type { AppEnv } from "./env";

const env = (vars: Record<string, unknown> = {}) => vars as unknown as AppEnv;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

afterEach(() => vi.unstubAllGlobals());

describe("registration status from open data (D-17, D-23)", () => {
  it("uses the public mirrors, with an optional BrasilAPI-format endpoint first", () => {
    expect(registrationSources(env()).map((s) => s.name)).toEqual(["brasilapi", "cnpjws"]);
    expect(registrationSources(env({ CNPJ_API_URL: "https://cnpj.example/v1/{cnpj}" })).map((s) => s.name)).toEqual(["custom", "brasilapi", "cnpjws"]);
    expect(() => registrationSources(env({ CNPJ_API_URL: "https://cnpj.example/v1/" }))).toThrow(/\{cnpj\}/);
  });

  it("tries the custom endpoint first and reads it in the BrasilAPI format", async () => {
    const urls: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      urls.push(url);
      return json({ razao_social: "ACME LTDA", descricao_situacao_cadastral: "ATIVA" });
    });
    const r = await companyRegistration(env({ CNPJ_API_URL: "https://cnpj.example/v1/{cnpj}" }), "11.222.333/0001-81");
    expect(r).toMatchObject({ legal_name: "ACME LTDA", registration_status: "ATIVA", source: "custom" });
    expect(urls).toEqual(["https://cnpj.example/v1/11222333000181"]);
  });

  it("reads BrasilAPI and falls back to CNPJ.ws, normalizing the status", async () => {
    const urls: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      urls.push(url);
      if (url.includes("brasilapi")) return new Response("busy", { status: 429 });
      return json({ razao_social: "ACME LTDA", estabelecimento: { situacao_cadastral: "Ativa" } });
    });
    const r = await companyRegistration(env(), "11.222.333/0001-81");
    expect(r).toMatchObject({ legal_name: "ACME LTDA", registration_status: "ATIVA", source: "cnpjws" });
    expect(urls).toEqual(["https://brasilapi.com.br/api/cnpj/v1/11222333000181", "https://publica.cnpj.ws/cnpj/11222333000181"]);
  });

  it("takes BrasilAPI's answer when it has one", async () => {
    vi.stubGlobal("fetch", async () => json({ razao_social: "BETA SA", descricao_situacao_cadastral: "BAIXADA" }));
    expect(await companyRegistration(env(), "11222333000181")).toMatchObject({ legal_name: "BETA SA", registration_status: "BAIXADA", source: "brasilapi" });
  });

  it("a 404 is an answer (unknown CNPJ); all sources down is REGISTRY_UNAVAILABLE", async () => {
    vi.stubGlobal("fetch", async () => new Response("", { status: 404 }));
    await expect(companyRegistration(env(), "11222333000181")).rejects.toMatchObject({ code: "NOT_FOUND" });
    vi.stubGlobal("fetch", async () => { throw new Error("network"); });
    await expect(companyRegistration(env(), "11222333000181")).rejects.toMatchObject({ code: "REGISTRY_UNAVAILABLE" });
  });

  it("never blocks: sources down → UNVERIFIED with a warning; check off → NOT_CHECKED, no request (D-24)", async () => {
    let calls = 0;
    vi.stubGlobal("fetch", async () => { calls++; return new Response("down", { status: 503 }); });
    const down = await registrationOrWarning(env(), "11222333000181");
    expect(down).toMatchObject({ registration_status: "UNVERIFIED", legal_name: null });
    expect(down.warning).toMatch(/could not be confirmed/);
    calls = 0;
    const off = await registrationOrWarning(env({ REGISTRATION_CHECK: "off" }), "11222333000181");
    expect(off).toMatchObject({ registration_status: "NOT_CHECKED", warning: expect.stringMatching(/REGISTRATION_CHECK=off/) });
    expect(calls).toBe(0);
    vi.stubGlobal("fetch", async () => json({ razao_social: "ACME LTDA", descricao_situacao_cadastral: "Baixada" }));
    expect(await registrationOrWarning(env(), "11222333000181")).toMatchObject({ registration_status: "BAIXADA", warning: null });
  });
});
