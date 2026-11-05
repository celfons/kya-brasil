// TEST ONLY: uses the worthless PKI from make-test-pki.mjs. Run that first.
//
// A company issues its own agent credential, no issuer service (D-37, SPEC sections 20 and 21):
//   buildMandate -> mandateSigningInput -> e-CNPJ signs the exact text -> assembleCredential
//   -> a legal representative co-signs the same text with an e-CPF -> addCosignature -> verifyCompanyWill.
// The same flow from the terminal: kya-sign --pfx company.pfx --issue mandate-input.json --anchors anchors.pem --out credential.json
//                                  kya-sign --pfx representative.pfx --cosign credential.json --anchors anchors.pem --out credential.json
// Writes out/credential.json ({ credential, proof }), what the agent presents. Exits non-zero on anything unexpected.
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { addCosignature, assembleCredential, buildMandate, encodePrincipalProofHeader, mandateSigningInput, openPfx, verifyCompanyWill, verifySelfIssuedCredential } from "@kya-brasil/core";

const OUT = resolve(process.env.KYA_QUICKSTART_OUT ?? join(import.meta.dirname, "out"));
const read = (f) => readFileSync(join(OUT, f));
const fail = (why, detail) => {
  console.error(`FAIL: ${why}`, detail === undefined ? "" : JSON.stringify(detail, null, 2));
  process.exit(1);
};

const pki = JSON.parse(read("pki.json"));
const agent = JSON.parse(read("agent.json"));
const anchors = read("anchors.pem").toString().match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
const now = new Date();

// mandate-input.json is the same file kya-sign --issue reads; dates and ids are refreshed so the example never expires.
const input = JSON.parse(readFileSync(join(import.meta.dirname, "mandate-input.json"), "utf8"));
input.credential_id = crypto.randomUUID();
input.agent = { kind: "evm", id: agent.id };
input.mandate.valid_from = now.toISOString();
input.mandate.valid_until = new Date(now.getTime() + 90 * 86_400_000).toISOString();

// 1. Build: validated as a verifier validates it; every risk field must be stated.
const built = await buildMandate({ ...input, now });
// 2. The exact text the e-CNPJ signs (show it to the person who signs).
const { text } = await mandateSigningInput(built);
console.log(`text signed by the e-CNPJ:\n${text}\n`);
// 3. Sign with the company's e-CNPJ (A1 here; openToken / ecnpjSigner / cloudSigner for A3 and cloud).
const company = await openPfx(read("company.pfx"), pki.password);
if (company.cnpj !== pki.cnpj) fail("company.pfx does not carry the expected CNPJ", company.cnpj);
const cms = await company.sign(text);
// 4. Assemble: verifies the CMS and the chain as a verifier would, then builds the credential.
const issued = await assembleCredential(built, cms, [], { anchors, now });
const self = await verifySelfIssuedCredential({ credential: issued.credential, proof: issued.proof, anchors, now });
if (!self.ok) fail("verifySelfIssuedCredential refused the fresh credential", self.checks);

// 5. Company will (SPEC section 21): a legal representative co-signs the SAME text with their e-CPF.
const rep = await openPfx(read("representative.pfx"), pki.password);
const cosigned = await addCosignature(issued, await rep.sign(issued.proof.text), [], { anchors, now });
// The verifier supplies the representatives (the QSA, from its own source), never the credential.
const will = await verifyCompanyWill(cosigned, { anchors, now, representatives: () => [pki.representative_cpf], minCosigners: 1 });
if (!will.ok) fail("verifyCompanyWill refused", will);
// Negative check: someone who is not a representative is refused.
const notRep = await verifyCompanyWill(cosigned, { anchors, now, representatives: () => ["11144477735"], minCosigners: 1 });
if (notRep.ok || notRep.code !== "COSIGNER_NOT_REPRESENTATIVE") fail("a co-signer outside the QSA was accepted", notRep);
if (JSON.stringify(cosigned.credential).includes(pki.representative_cpf)) fail("the credential leaks the representative's CPF");

writeFileSync(join(OUT, "credential.json"), JSON.stringify(cosigned, null, 2));
console.log(`OK self-issued ${cosigned.credential.credential_id} (issuer ${cosigned.credential.issuer}), ${will.detail}`);
console.log(`KYA-Principal-Proof header with one co-signature: ${encodePrincipalProofHeader(cosigned.proof).length} bytes`);
