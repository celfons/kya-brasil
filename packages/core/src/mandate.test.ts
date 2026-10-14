import { describe, expect, it } from "vitest";
import { checkAction, hashPaymentRef, validateMandate } from "./mandate.js";

describe("mandate", () => {
  it("normalizes reserved fields and keeps extensions", () => {
    const m = validateMandate({ actions: ["buy", "buy", "quote"], max_per_operation: { amount: 500, currency: "USDC" }, counterparties: ["33.000.167/0001-01", "0xB5A72BB9106975869165C380E52D157388346626", "Supplier.com"], custom_policy: { tier: 2 } });
    expect(m.actions).toEqual(["buy", "quote"]);
    expect(m.counterparties).toEqual(["33000167000101", "0xb5a72bb9106975869165c380e52d157388346626", "supplier.com"]);
    expect(m.custom_policy).toEqual({ tier: 2 });
  });

  it("rejects malformed reserved fields", () => {
    expect(() => validateMandate({ actions: ["Buy"] })).toThrow(/actions/);
    expect(() => validateMandate({ max_per_day: { amount: -1, currency: "BRL" } })).toThrow(/max_per_day/);
    expect(() => validateMandate({ valid_from: "2026-10-12T00:00:00Z", valid_until: "2026-10-01T00:00:00Z" })).toThrow(/valid_until/);
    expect(() => validateMandate([])).toThrow(/object/);
  });

  it("evaluates an action against the reserved rules and lists what it did not evaluate", () => {
    const m = validateMandate({ actions: ["pay"], max_per_operation: { amount: 100, currency: "USDC" }, max_per_day: { amount: 250, currency: "USDC" }, currencies: ["USDC"], counterparties: ["33000167000101"], valid_until: "2027-01-01T00:00:00Z", notes: "x" });
    const ok = checkAction(m, { action: "pay", amount: 80, currency: "USDC", counterparty: "33.000.167/0001-01", spent_today: 100, now: new Date("2026-10-12T00:00:00Z") });
    expect(ok.allowed).toBe(true);
    expect(ok.not_evaluated).toEqual(["notes"]);
    const tooMuch = checkAction(m, { action: "pay", amount: 80, currency: "USDC", counterparty: "33000167000101", spent_today: 200, now: new Date("2026-10-12T00:00:00Z") });
    expect(tooMuch.allowed).toBe(false);
    expect(tooMuch.checks.find((c) => c.rule === "max_per_day")?.ok).toBe(false);
    expect(checkAction(m, { action: "sell", now: new Date("2026-10-12T00:00:00Z") }).allowed).toBe(false);
    expect(checkAction(m, { action: "pay", now: new Date("2027-06-01T00:00:00Z") }).checks.find((c) => c.rule === "valid_until")?.ok).toBe(false);
  });

  describe("payment_instruments (D-25)", () => {
    it("hashes a reference as SHA-256 hex, whitespace removed, case kept", async () => {
      expect(await hashPaymentRef("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
      expect(await hashPaymentRef(" a b c ")).toBe(await hashPaymentRef("abc"));
      expect(await hashPaymentRef("ABC")).not.toBe(await hashPaymentRef("abc"));
    });

    it("validates and normalizes; refuses card numbers, unknown fields and duplicates", async () => {
      const h = await hashPaymentRef("V0010013018123456789012345678");
      const m = validateMandate({ payment_instruments: [{ network: "Visa", ref_sha256: h.toUpperCase(), label: "compras" }] });
      expect(m.payment_instruments).toEqual([{ network: "visa", ref_sha256: h, label: "compras" }]);
      expect(() => validateMandate({ payment_instruments: [{ network: "visa", ref_sha256: "4111111111111111" }] })).toThrow(/never a card number/);
      expect(() => validateMandate({ payment_instruments: [{ network: "visa", ref_sha256: h, label: "4111 1111 1111 1111" }] })).toThrow(/without card numbers/);
      expect(() => validateMandate({ payment_instruments: [{ network: "visa", ref_sha256: h, pan: "x" }] })).toThrow(/unknown field/);
      expect(() => validateMandate({ payment_instruments: [{ network: "visa", ref_sha256: h }, { network: "VISA", ref_sha256: h }] })).toThrow(/duplicate/);
    });

    it("evaluates the instrument when the verifier passes one, by hash and network", async () => {
      const visa = await hashPaymentRef("tok-visa-1");
      const m = validateMandate({ actions: ["buy"], payment_instruments: [{ network: "visa", ref_sha256: visa }] });
      const ok = checkAction(m, { action: "buy", payment_network: "VISA", payment_ref_sha256: visa });
      expect(ok.allowed).toBe(true);
      expect(ok.checks.find((c) => c.rule === "payment_instruments")?.ok).toBe(true);
      expect(checkAction(m, { action: "buy", payment_network: "mastercard", payment_ref_sha256: visa }).allowed).toBe(false);
      expect(checkAction(m, { action: "buy", payment_ref_sha256: await hashPaymentRef("other") }).allowed).toBe(false);
      // Not given: not evaluated (like counterparties), and reserved, so not listed as an extension.
      const none = checkAction(m, { action: "buy" });
      expect(none.checks.some((c) => c.rule === "payment_instruments")).toBe(false);
      expect(none.not_evaluated).not.toContain("payment_instruments");
    });
  });

  it("matches *. counterparties on the domain and its subdomains (SPEC section 5)", () => {
    const m = validateMandate({ counterparties: ["*.beta.com.br", "12345678000190"] });
    expect(checkAction(m, { counterparty: "shop.beta.com.br" }).allowed).toBe(true);
    expect(checkAction(m, { counterparty: "beta.com.br" }).allowed).toBe(true);
    expect(checkAction(m, { counterparty: "evilbeta.com.br" }).allowed).toBe(false);
    expect(checkAction(m, { counterparty: "12.345.678/0001-90" }).allowed).toBe(true);
  });

  it("validates delegation as a reserved field, not listed as not evaluated", () => {
    const m = validateMandate({ actions: ["quote"], delegation: { max_depth: 1, max_ttl_seconds: 600 } });
    expect(checkAction(m, { action: "quote" }).not_evaluated).toEqual([]);
  });
});
