/**
 * Issuance by the principal from the terminal (D-37, SPEC sections 20 and 21), behind `kya-sign --issue` and
 * `kya-sign --cosign`: buildMandate -> mandateSigningInput -> signer.sign (A3 token, A1 file or cloud) ->
 * assembleCredential, and addCosignature for a legal representative's e-CPF. Separate from cli.ts so it can be
 * tested with an in-memory signer instead of a token.
 */
import { type ECnpjSigner, type IssuedCredential, type MandateInput, addCosignature, assembleCredential, buildMandate, mandateSigningInput } from "@kya-brasil/core";

/** Anchors from a PEM bundle (one or more certificates) or a single base64 DER. */
export function parseAnchors(text: string): string[] {
  const pems = text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  if (pems?.length) return pems;
  const raw = text.trim();
  if (!raw) throw new Error("the anchors file is empty");
  return [raw];
}

/** Reads the mandate input JSON: MandateInput with `now` as an ISO date (default: the given clock). */
export function parseMandateInput(json: string, clock: Date): MandateInput {
  let o: Record<string, unknown>;
  try {
    o = JSON.parse(json) as Record<string, unknown>;
  } catch (e) {
    throw new Error(`mandate input is not JSON: ${(e as Error).message}`);
  }
  if (!o || typeof o !== "object" || Array.isArray(o)) throw new Error("mandate input must be a JSON object");
  const now = o.now === undefined ? clock : new Date(String(o.now));
  if (Number.isNaN(now.getTime())) throw new Error("mandate input: now is not a date");
  return { ...(o as unknown as MandateInput), now };
}

export interface IssueIo {
  /** Writes progress and the text being signed (stderr in the CLI). */
  log: (s: string) => void;
}

const show = (io: IssueIo, signer: ECnpjSigner, text: string) =>
  io.log(`certificate: ${signer.subject}\nsigning:\n${text.split("\n").map((l) => `  ${l}`).join("\n")}\n`);

/** The whole issuance with one signer: returns { credential, proof } after verifying it as a verifier would. */
export async function issueCredential(p: { input: MandateInput; signer: ECnpjSigner; anchors: string[]; now: Date; io: IssueIo }): Promise<IssuedCredential> {
  const built = await buildMandate(p.input);
  const { text } = await mandateSigningInput(built);
  show(p.io, p.signer, text);
  const cms = await p.signer.sign(text);
  return assembleCredential(built, cms, [], { anchors: p.anchors, now: p.now });
}

/** A legal representative co-signs an issued company credential with their e-CPF (the same text). */
export async function cosignCredential(p: { issued: IssuedCredential; signer: ECnpjSigner; anchors: string[]; now: Date; io: IssueIo }): Promise<IssuedCredential> {
  if (!p.issued?.credential || typeof p.issued.proof?.text !== "string") throw new Error("not an issued credential ({ credential, proof }) from kya-sign --issue");
  show(p.io, p.signer, p.issued.proof.text);
  const cms = await p.signer.sign(p.issued.proof.text);
  return addCosignature(p.issued, cms, [], { anchors: p.anchors, now: p.now });
}
