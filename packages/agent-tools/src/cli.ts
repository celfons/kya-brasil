#!/usr/bin/env node
/**
 * kya-sign: sign a KYA challenge (or a company request text) with the company's e-CNPJ, A1 or A3.
 *   A1 file:   kya-sign --pfx empresa.pfx --link "<sign_url>&agent_signature=…"
 *   A3 token:  kya-sign --pkcs11 /usr/lib/libeTPkcs11.so --link "<sign_url>&agent_signature=…"
 *              kya-sign --pkcs11 <library> --list              (certificates on the token)
 *   Cloud:     kya-sign --cloud ./my-psc.mjs --link "<sign_url>&agent_signature=…"
 *              (a module exporting a CloudSignatureProvider: yours, for your PSC; the browser opens for the
 *               approval and comes back to a one-time local address)
 *   Text instead of a link: --text-file desafio.txt or --text "<text>" (prints the signature).
 * The password (A1) comes from KYA_PFX_PASSWORD and the PIN (A3) from KYA_TOKEN_PIN, or are asked for without
 * echo. With a link carrying agent_signature, the proof is sent and the issued credential printed. Everything
 * happens on this machine; the certificate and its password or PIN are never sent anywhere.
 */
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import { cloudSigner, newState, pkcePair, openPfx, readSigningLink, type CloudSignatureProvider, type ECnpjSigner } from "@kya-brasil/core";
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

/** Loads a provider module: a path (./my-psc.mjs) or a package name; default export or `provider`. */
async function loadProvider(spec: string): Promise<CloudSignatureProvider> {
  const url = spec.startsWith(".") || spec.startsWith("/") ? pathToFileURL(resolve(spec)).href : spec;
  const mod = (await import(url)) as { default?: unknown; provider?: unknown };
  const p = (mod.provider ?? mod.default) as CloudSignatureProvider | undefined;
  if (!p || typeof p.authorizationUrl !== "function" || typeof p.exchangeCode !== "function") die(`${spec} does not export a CloudSignatureProvider (default export or "provider")`);
  return p!;
}

/**
 * OAuth with PKCE through the browser: a one-time server on 127.0.0.1 receives the code, checks the state,
 * exchanges it and returns an e-CNPJ signer over the provider's session.
 */
async function cloudLogin(provider: CloudSignatureProvider, port: number, open: boolean): Promise<ECnpjSigner & { close: () => Promise<void> }> {
  const state = newState();
  const { verifier, challenge } = await pkcePair();
  let answer!: (r: { code?: string; error?: string }) => void;
  const answered = new Promise<{ code?: string; error?: string }>((r) => (answer = r));
  const server = createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://127.0.0.1");
    if (u.pathname !== "/callback") return void res.writeHead(404).end();
    const ok = u.searchParams.get("state") === state && !!u.searchParams.get("code");
    res.writeHead(ok ? 200 : 400, { "content-type": "text/html; charset=utf-8" }).end(ok ? "<p>Autorizado. Pode fechar esta janela e voltar ao terminal.</p>" : "<p>Autorização recusada ou inválida.</p>");
    answer(ok ? { code: u.searchParams.get("code")! } : { error: u.searchParams.get("error_description") ?? u.searchParams.get("error") ?? "state mismatch" });
  });
  await new Promise<void>((r) => server.listen(port, "127.0.0.1", r));
  const addr = server.address();
  const redirectUri = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : port}/callback`;
  const timer = setTimeout(() => answer({ error: "no approval within 5 minutes" }), 300_000);
  try {
    const url = await provider.authorizationUrl({ redirectUri, state, codeChallenge: challenge });
    process.stderr.write(`Abra para aprovar no ${provider.name} / open to approve:\n  ${url}\n`);
    if (open) {
      const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
      const a = process.platform === "win32" ? ["/c", "start", "", url] : [url];
      spawn(cmd, a, { stdio: "ignore", detached: true }).on("error", () => undefined).unref();
    }
    const r = await answered;
    if (!r.code) throw new Error(`not authorized: ${r.error}`);
    const session = await provider.exchangeCode({ code: r.code, redirectUri, codeVerifier: verifier });
    const signer = await cloudSigner(session);
    return { ...signer, close: async () => void (await session.close?.().catch(() => undefined)) };
  } finally {
    clearTimeout(timer);
    server.close();
  }
}

const USAGE = `usage:
  kya-sign --pfx <file.pfx> (--link <signing link> | --text-file <file> | --text <text>)
  kya-sign --pkcs11 <library> [--slot N] [--label L] (--link … | --text-file … | --text …)
  kya-sign --pkcs11 <library> --list
  kya-sign --cloud <provider module> [--port N] [--no-open] (--link … | --text-file … | --text …)
`;

async function main() {
  if (args.includes("--help") || args.includes("-h")) return void process.stdout.write(USAGE);
  const pfxPath = opt("pfx");
  const library = opt("pkcs11");
  const cloud = opt("cloud");
  if (!pfxPath && !library && !cloud) {
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

  let signer: ECnpjSigner & { close?: () => void | Promise<void> };
  if (cloud) signer = await cloudLogin(await loadProvider(cloud), opt("port") ? Number(opt("port")) : 0, !args.includes("--no-open"));
  else if (library) signer = await openToken({ library, slot, label: opt("label"), pin: await askSecret("KYA_TOKEN_PIN", "PIN do token / token PIN: ") });
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
    await signer.close?.();
  }
}

main().catch((e: unknown) => die((e as Error).message));
