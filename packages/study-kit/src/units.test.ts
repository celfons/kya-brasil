import { isValidCnpj } from "@kya-brasil/core";
import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { compareSnapshots, findGit } from "./diffstats.js";
import { categorize, categorizeThrown } from "./errors.js";
import { SCENARIO, gradePolicy, referenceMandate } from "./policy.js";
import { quantile, scrub } from "./report.js";

const now = new Date("2026-11-05T12:00:00Z");
const cred = (patch: Record<string, unknown> = {}, expiresDays = 30) => ({
  mandate: { ...referenceMandate(now), delegation: undefined, ...patch } as Record<string, unknown>,
  issued_at: now.toISOString(),
  expires_at: new Date(now.getTime() + expiresDays * 86_400_000).toISOString()
});

describe("policy grading (T2)", () => {
  it("the scenario's CNPJs are valid", () => {
    expect(isValidCnpj(SCENARIO.supplierCnpj)).toBe(true);
    expect(isValidCnpj(SCENARIO.otherSupplierCnpj)).toBe(true);
  });

  it("the answer key grades correct, with formatted CNPJs and a day of slack", () => {
    expect(gradePolicy(cred(), true)).toEqual({ grade: "correct", deviations: [] });
    expect(gradePolicy(cred({ counterparties: ["98.765.432/0001-98"] }, 30.5), true).grade).toBe("correct");
  });

  it("too permissive: extra actions, no currency, extra counterparty, delegation", () => {
    const r = gradePolicy(cred({ actions: ["buy", "pay"], currencies: [], counterparties: [SCENARIO.supplierCnpj, "*.loja.com.br"], delegation: { max_depth: 1, max_ttl_seconds: 600 } }), true);
    expect(r.grade).toBe("permissive");
    expect(r.deviations.map((d) => d.field)).toEqual(["actions", "currencies", "counterparties", "delegation"]);
  });

  it("too restrictive: lower ceilings, shorter validity, supplier missing", () => {
    const r = gradePolicy(cred({ max_per_operation: { amount: 300, currency: "BRL" }, counterparties: [SCENARIO.otherSupplierCnpj] }, 7), true);
    // The other supplier is an extra counterparty (permissive) and supplier X is missing (restrictive): permissive wins.
    expect(r.grade).toBe("permissive");
    const only = gradePolicy(cred({ max_per_day: { amount: 1000, currency: "BRL" } }, 7), true);
    expect(only.grade).toBe("restrictive");
    expect(only.deviations.map((d) => [d.field, d.direction])).toEqual([["max_per_day", "restrictive"], ["valid_until", "restrictive"]]);
  });

  it("a mandate whose validity is cut by the credential's expiry counts the effective period", () => {
    const r = gradePolicy(cred({ valid_until: new Date(now.getTime() + 90 * 86_400_000).toISOString() }, 30), true);
    expect(r.grade).toBe("correct");
  });

  it("invalid when T1 did not produce a verifiable credential", () => {
    expect(gradePolicy(null, false).grade).toBe("invalid");
    expect(gradePolicy(cred(), false).grade).toBe("invalid");
  });
});

describe("error categories", () => {
  it("maps library codes before words", () => {
    expect(categorize("KYA_REQUEST_REPLAYED")).toBe("replay");
    expect(categorize("KYA_CERTIFICATE_REVOKED")).toBe("revocation");
    expect(categorize("KYA_CERTIFICATE_STATUS_STALE: certificate evidence expired")).toBe("freshness");
    expect(categorize("KYA_PRINCIPAL_PROOF_INVALID: certificate: expired")).toBe("icp_chain");
    expect(categorize("KYA_BAD_SIGNATURE")).toBe("signature");
    expect(categorize("max_per_operation")).toBe("mandate");
    expect(categorize("counterparties, max_per_operation")).toBe("mandate");
    expect(categorize("")).toBe("other");
  });
  it("thrown errors: library errors by code, anything else is runtime", () => {
    expect(categorizeThrown(Object.assign(new Error("mandate.actions: bad"), { name: "KyaError", code: "INVALID_INPUT" }))).toBe("mandate");
    expect(categorizeThrown(new TypeError("x is not a function"))).toBe("runtime");
    // QA 5: a wrong .pfx password is INVALID_INPUT too, but a certificate problem.
    expect(categorizeThrown({ name: "KyaError", code: "INVALID_INPUT", message: "could not open the certificate file (wrong password or not a .pfx/.p12): PKCS#12 MAC could not be verified. Invalid password?" })).toBe("icp_chain");
    expect(categorizeThrown({ name: "Error", code: "ERR_MODULE_NOT_FOUND", message: "Cannot find package" })).toBe("runtime");
  });
});

describe("report helpers", () => {
  it("snapshot comparison counts files and lines, not content", () => {
    const a = { "src/a.mjs": { sha256: "1", lines: { x: 2, y: 1 } }, "src/gone.mjs": { sha256: "2", lines: { z: 3 } } };
    const b = { "src/a.mjs": { sha256: "3", lines: { x: 1, y: 1, w: 4 } }, "src/new.mjs": { sha256: "4", lines: { q: 5 } } };
    expect(compareSnapshots(a, b)).toEqual({ files_changed: 3, lines_added: 9, lines_removed: 4 });
    expect(compareSnapshots(a, a)).toEqual({ files_changed: 0, lines_added: 0, lines_removed: 0 });
  });
  it("quantiles", () => {
    expect(quantile([], 0.5)).toBeNull();
    expect(quantile([1, 2, 3, 4], 0.5)).toBe(2.5);
    expect(quantile([5], 0.25)).toBe(5);
  });
  it("scrub removes e-mails and other users' home folders", () => {
    expect(scrub("C:\\Users\\fulana\\proj e /home/beltrano/x, mail a@b.com")).toBe("<caminho> e <caminho>, mail <email>");
  });
});

describe("git lookup", () => {
  it.skipIf(process.platform === "win32")("only absolute PATH entries, never the current folder", () => {
    const dir = mkdtempSync(join(tmpdir(), "kya-study-git-"));
    writeFileSync(join(dir, "git"), "#!/bin/sh\n");
    expect(findGit({ PATH: [".", "bin", dir].join(delimiter) })).toBe(join(dir, "git"));
    expect(findGit({ PATH: "." })).toBeNull();
  });
});
