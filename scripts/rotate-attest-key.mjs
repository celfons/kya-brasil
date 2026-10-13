#!/usr/bin/env node
/**
 * Attestation key rotation helper (RUNBOOK §4). Reads the CURRENT private key (PKCS#8 base64, as
 * stored in the Pulumi config) from stdin and prints a JSON object with:
 *   retired   the public half of that key, as an entry for attestPreviousKeys ({ key_id, jwk, retired_at })
 *   next      a NEW private key for attestPrivateKey
 * Nothing is written anywhere: the operator applies both with `pulumi config set`.
 */
import { createPrivateKey, createPublicKey } from "node:crypto";

const current = (await new Promise((r) => { let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => r(s)); })).trim();
if (!current) { console.error("usage: pulumi config get kya-br-agents:attestPrivateKey | node scripts/rotate-attest-key.mjs"); process.exit(2); }
const pub = createPublicKey(createPrivateKey({ key: Buffer.from(current, "base64"), format: "der", type: "pkcs8" })).export({ format: "jwk" });
const jwk = { kty: pub.kty, crv: pub.crv, x: pub.x, key_ops: ["verify"], ext: true, alg: "EdDSA" };
const keyId = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pub.x))).toString("hex").slice(0, 16);
const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const next = Buffer.from(await crypto.subtle.exportKey("pkcs8", kp.privateKey)).toString("base64");
process.stdout.write(JSON.stringify({ retired: { key_id: keyId, jwk, retired_at: new Date().toISOString() }, next }, null, 2) + "\n");
