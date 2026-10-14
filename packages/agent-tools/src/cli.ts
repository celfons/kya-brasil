#!/usr/bin/env node
/**
 * kya-sign: sign a KYA challenge (or a company request text) with the e-CNPJ in a .pfx / .p12 file.
 *   npx -p @kya-brasil/agent-tools kya-sign --pfx empresa.pfx --text-file desafio.txt
 *   npx -p @kya-brasil/agent-tools kya-sign --pfx empresa.pfx --link "https://…/sign?id=…&challenge_id=…&text=…&agent_signature=…"
 * The password comes from KYA_PFX_PASSWORD or is asked for (not echoed). Prints the base64 signature, or with
 * --link and an agent_signature in it, sends the proof and prints the issued credential.
 * Everything happens on this machine; the certificate is never sent anywhere.
 */
import { readFileSync } from "node:fs";
import { openPfx } from "./pfx.js";

const args = process.argv.slice(2);
const opt = (name: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const die = (msg: string): never => {
  process.stderr.write(`kya-sign: ${msg}\n`);
  process.exit(1);
};

async function askPassword(): Promise<string> {
  if (process.env.KYA_PFX_PASSWORD !== undefined) return process.env.KYA_PFX_PASSWORD;
  if (!process.stdin.isTTY) die("set KYA_PFX_PASSWORD (no terminal to ask for the password)");
  process.stderr.write("Senha do certificado / certificate password: ");
  process.stdin.setRawMode(true);
  process.stdin.resume();
  let pw = "";
  return new Promise((resolve) => {
    process.stdin.on("data", (b: Buffer) => {
      for (const ch of b.toString("utf8")) {
        if (ch === "\r" || ch === "\n") {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stderr.write("\n");
          return resolve(pw);
        }
        if (ch === "\u0003") process.exit(130);
        pw = ch === "\u007f" ? pw.slice(0, -1) : pw + ch;
      }
    });
  });
}

const fromB64u = (s: string) => new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)));

async function main() {
  if (args.includes("--help") || args.includes("-h") || !opt("pfx")) {
    process.stdout.write("usage: kya-sign --pfx <file.pfx> (--text-file <file> | --text <text> | --link <signing link>)\n");
    process.exit(args.includes("--help") || args.includes("-h") ? 0 : 2);
  }
  const link = opt("link") ? new URL(opt("link")!) : null;
  const text = link ? fromB64u(link.searchParams.get("text") ?? die("the link has no text")) : opt("text-file") ? readFileSync(opt("text-file")!, "utf8") : (opt("text") ?? die("give --text-file, --text or --link"));
  const signer = openPfx(new Uint8Array(readFileSync(opt("pfx")!)), await askPassword());
  const cnpj = /^cnpj: (\d{14})$/m.exec(text)?.[1];
  process.stderr.write(`certificate: ${signer.subject}\n`);
  if (cnpj && signer.cnpj && cnpj !== signer.cnpj) die(`this certificate is for CNPJ ${signer.cnpj}, the text is for ${cnpj}`);
  process.stderr.write(`signing:\n${text.split("\n").map((l) => `  ${l}`).join("\n")}\n`);
  const signature = signer.sign(text);
  const id = link?.searchParams.get("id");
  const challengeId = link?.searchParams.get("challenge_id");
  const agentSignature = link?.searchParams.get("agent_signature");
  if (!link || !id || !challengeId || !agentSignature) {
    process.stdout.write(`${signature}\n`);
    return;
  }
  const res = await fetch(new URL(`/v1/agents/${encodeURIComponent(id)}/prove`, link.origin), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ challenge_id: challengeId, agent_signature: agentSignature, ecnpj_signature: signature })
  });
  const body = await res.text();
  process.stdout.write(`${body}\n`);
  if (!res.ok) process.exit(1);
}

main().catch((e: unknown) => die((e as Error).message));
