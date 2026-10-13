import { describe, expect, it } from "vitest";
import { actText, dayOf, spentToday, validateAct } from "./acts";

describe("acts", () => {
  it("validates and normalizes", () => {
    const a = validateAct({ action: "pay", amount: "80.5", currency: "usdc", counterparty: "33.000.167/0001-01", reference: "PO-1", content_sha256: "AB".repeat(32), registered_by: "counterparty" });
    expect(a).toEqual({ action: "pay", amount: 80.5, currency: "USDC", counterparty: "33000167000101", reference: "PO-1", content_sha256: "ab".repeat(32), registered_by: "counterparty" });
    expect(() => validateAct({ action: "Pay!" })).toThrow(/action/);
    expect(() => validateAct({ action: "pay", amount: 10 })).toThrow(/currency/);
    expect(() => validateAct({ action: "pay", content_sha256: "zz" })).toThrow(/content_sha256/);
  });

  it("writes a stable act text", () => {
    const t = actText({ issuer: "https://kya.example", credential_id: "c1", agent: { kind: "evm", id: "0xAb" }, act: { action: "pay", amount: 80, currency: "USDC" } });
    expect(t.split("\n")).toEqual(["KYA Brasil: act", "issuer: https://kya.example", "credential: c1", "agent: evm:0xAb", "action: pay", "amount: 80 USDC", "counterparty: -", "reference: -", "content_sha256: -"]);
  });

  it("sums only allowed acts in the daily currency", () => {
    expect(dayOf("2026-10-13T23:59:59Z")).toBe("2026-10-13");
    expect(spentToday([{ amount: 10, currency: "USDC", allowed: true }, { amount: 5, currency: "USDC", allowed: false }, { amount: 7, currency: "BRL", allowed: true }, { amount: null, currency: "USDC", allowed: true }], "USDC")).toBe(10);
  });
});
