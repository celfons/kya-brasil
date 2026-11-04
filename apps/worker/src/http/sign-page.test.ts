import { describe, expect, it } from "vitest";
import { canonicalize, mandateSha256, validateMandate } from "@kya-brasil/core";
import { signHtml } from "./sign-page";

describe("/sign page script", () => {
  const html = signHtml("https://kya.test", "nonce123");
  const script = /<script nonce="nonce123">([\s\S]*?)<\/script>/.exec(html)?.[1] ?? "";

  it("is valid JavaScript", () => {
    expect(script.length).toBeGreaterThan(100);
    expect(() => new Function(script)).not.toThrow();
  });

  it("hashes the mandate exactly as the core does (D-33), so its check matches the issuer's", async () => {
    const canonSrc = /const canon = ([^\n]*);\n/.exec(script)?.[1];
    expect(canonSrc).toBeTruthy();
    const canon = new Function(`const canon = ${canonSrc}; return canon;`)() as (v: unknown) => string;
    const mandate = validateMandate({ max_per_operation: { currency: "BRL", amount: 500 }, actions: ["buy", "quote"], counterparties: ["*.a.com"], notes: { b: 1, a: [2, { z: 1, y: 2 }], "é": true, Z: null } });
    expect(canon(mandate)).toBe(canonicalize(mandate));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canon(mandate))));
    expect([...digest].map((b) => b.toString(16).padStart(2, "0")).join("")).toBe(await mandateSha256(mandate));
  });

  it("offers the signed text and the .p7s for the holder to keep", () => {
    expect(html).toContain('id="dl-p7s"');
    expect(html).toContain('id="dl-signed"');
  });
});
