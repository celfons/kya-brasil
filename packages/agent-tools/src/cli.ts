#!/usr/bin/env node
/**
 * kya-sign: sign a KYA challenge (or a company request text) with the company's e-CNPJ, A1 or A3.
 *   A1 file:   kya-sign --pfx empresa.pfx --link "<sign_url>&agent_signature=…"
 *   A3 token:  kya-sign --pkcs11 /usr/lib/libeTPkcs11.so --link "<sign_url>&agent_signature=…"
 *              kya-sign --pkcs11 <library> --list              (certificates on the token)
 *   Text instead of a link: --text-file desafio.txt or --text "<text>" (prints the signature).
 * The password (A1) comes from KYA_PFX_PASSWORD and the PIN (A3) from KYA_TOKEN_PIN, or are asked for without
 * echo. With a link carrying agent_signature, the proof is sent and the issued credential printed. Everything
 * happens on this machine; the certificate and its password or PIN are never sent anywhere.
 */
import { readFileSync } from "node:fs";
import { openPfx, readSigningLink, type ECnpjSigner } from "@kya-brasil/core";
import { listTokenCertificates, openToken } from "./pkcs11.js";

const args = process.argv.slice(2);
const opt = (name: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const die = (msg: string): never => {
  process.stderr.write(`kya-sign: ${msg}\n`);
  process.exit(1);
};

async function askSecret(envName: string, prompt: string): Promise<string> {
  if (process.env[envName] !== undefined) return process.env[envName]!;
  if (!process.stdin.isTTY) die(`set ${envName} (no terminal to ask for it)`);
  process.stderr.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  let secret = "";
  return new Promise((resolve) => {
    process.stdin.on("data", (b: Buffer) => {
      for (const ch of b.toString("utf8")) {
        if (ch === "\r" || ch === "\n") {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stderr.write("\n");
          return resolve(secret);
        }
        if (ch === "\u0003") process.exit(130);
        secret = ch === "\u007f" ? secret.slice(0, -1) : secret + ch;
      }
    });
  });
}

const USAGE = `usage:
  kya-sign --pfx <file.pfx> (--link <signing link> | --text-file <file> | --text <text>)
  kya-sign --pkcs11 <library> [--slot N] [--label L] (--link … | --text-file … | --text …)
  kya-sign --pkcs11 <library> --list
`;

async function main() {
  if (args.includes("--help") || args.includes("-h")) return void process.stdout.write(USAGE);
  const pfxPath = opt("pfx");
  const library = opt("pkcs11");
  if (!pfxPath && !library) {
    process.stdout.write(USAGE);
    process.exit(2);
  }
  const slot = opt("slot") !== undefined ? Number(opt("slot")) : undefined;
  if (library && args.includes("--list")) {
    for (const c of await listTokenCertificates({ library, slot })) process.stdout.write(`${c.label}\t${c.cnpj ?? "-"}\t${c.notAfter.toISOString().slice(0, 10)}\t${c.subject}\n`);
    return;
  }
  const link = opt("link") ? readSigningLink(opt("link")!) : null;
  const text = link ? link.text : opt("text-file") ? readFileSync(opt("text-file")!, "utf8") : (opt("text") ?? die("give --link, --text-file or --text"));

  let signer: ECnpjSigner & { close?: () => void };
  if (library) signer = await openToken({ library, slot, label: opt("label"), pin: await askSecret("KYA_TOKEN_PIN", "PIN do token / token PIN: ") });
  else signer = await openPfx(new Uint8Array(readFileSync(pfxPath!)), await askSecret("KYA_PFX_PASSWORD", "Senha do certificado / certificate password: "));

  try {
    process.stderr.write(`certificate: ${signer.subject}\nsigning:\n${text.split("\n").map((l) => `  ${l}`).join("\n")}\n`);
    const signature = await signer.sign(text);
    if (!link?.credentialId || !link.challengeId || !link.agentSignature) {
      process.stdout.write(`${signature}\n`);
      return;
    }
    const res = await fetch(new URL(`/v1/agents/${encodeURIComponent(link.credentialId)}/prove`, link.issuer), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ challenge_id: link.challengeId, agent_signature: link.agentSignature, ecnpj_signature: signature })
    });
    process.stdout.write(`${await res.text()}\n`);
    if (!res.ok) process.exitCode = 1;
  } finally {
    signer.close?.();
  }
}

main().catch((e: unknown) => die((e as Error).message));
