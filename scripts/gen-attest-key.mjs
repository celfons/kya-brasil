#!/usr/bin/env node
/** Prints a new Ed25519 private key (PKCS#8, base64) for ATTEST_PRIVATE_KEY. Node 20+. */
const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
process.stdout.write(Buffer.from(pkcs8).toString("base64"));
