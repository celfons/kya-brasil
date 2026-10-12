/**
 * Cloud infrastructure for KYA Brasil, as code.
 *
 * Source of truth for everything that runs on Cloudflare:
 *   - KV namespace (cache, rate limits, ICP-Brasil trust anchors under icp:anchors)
 *   - D1 database + SQL migrations (apps/worker/migrations, applied through the D1 HTTP API)
 *   - Worker script (bundled by `wrangler deploy --dry-run`) with bindings, vars, secrets
 *   - Service Binding `KYB` to the KYB Brasil Worker (same account): Worker-to-Worker calls,
 *     never public HTTP, never x402. KYB's /internal/v1/* channel is opened with KYB_INTERNAL_KEY.
 *   - Cron trigger for the daily KYB review of live credentials
 *   - workers.dev subdomain
 *
 * `apps/worker/wrangler.jsonc` is kept only for local development (`wrangler dev`); it is never
 * used to deploy. Keep the two in sync when adding a binding.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import * as pulumi from "@pulumi/pulumi";
import * as cloudflare from "@pulumi/cloudflare";
import * as command from "@pulumi/command";

const cfg = new pulumi.Config();
const accountId = cfg.require("accountId");
const workerName = cfg.get("workerName") ?? "kya-br-agents";
/** Script name of the KYB Brasil Worker in the same account (kyb-br-agents on prod, kyb-br-agents-dev on dev). */
const kybWorkerName = cfg.get("kybWorkerName") ?? "kyb-br-agents";
const x402Network = cfg.get("x402Network") ?? "eip155:84532";
const facilitatorUrl = cfg.get("facilitatorUrl") ?? "https://x402.org/facilitator";
const freeTierDailyLimit = cfg.get("freeTierDailyLimit") ?? "50";
const issuerUrl = cfg.get("issuerUrl"); // optional; defaults to the request origin
const payTo = cfg.requireSecret("payTo");
const kybInternalKey = cfg.requireSecret("kybInternalKey");
const internalApiKey = cfg.getSecret("internalApiKey");
const cdpApiKeyId = cfg.getSecret("cdpApiKeyId");
const cdpApiKeySecret = cfg.getSecret("cdpApiKeySecret");
// Ed25519 key that signs credentials and verdicts; the CD generates it once per stack and keeps it in the stack config.
const attestPrivateKey = cfg.getSecret("attestPrivateKey");
// Retired public keys (JSON array of { jwk, retired_at }), kept so old credentials still verify.
const attestPreviousKeys = cfg.get("attestPreviousKeys");
// Glama connector claim token for this domain (served at /.well-known/glama.json).
const glamaClaim = cfg.get("glamaClaim");
const cfToken = new pulumi.Config("cloudflare").requireSecret("apiToken");

const repoRoot = path.resolve(__dirname, "..");
const workerDir = path.join(repoRoot, "apps", "worker");
const migrationsDir = path.join(workerDir, "migrations");

// Must match apps/worker/wrangler.jsonc (local dev).
const COMPATIBILITY_DATE = "2026-06-11";
const COMPATIBILITY_FLAGS = ["nodejs_compat"];
const DAILY_REVIEW_CRON = "17 3 * * *"; // 03:17 UTC, after KYB's own nightly dataset loads
const MCP_OBJECT_CLASS = "KyaMcp"; // one Durable Object per MCP session (apps/worker/src/mcp.ts)

// --- Storage -----------------------------------------------------------------

const cache = new cloudflare.WorkersKvNamespace("cache", { accountId, title: `${workerName}-cache` });

const db = new cloudflare.D1Database("db", { accountId, name: workerName, primaryLocationHint: "enam" });

// --- D1 migrations -----------------------------------------------------------

function hashDir(dir: string): string {
  const h = crypto.createHash("sha256");
  for (const f of fs.readdirSync(dir).filter((n) => n.endsWith(".sql")).sort()) h.update(f).update(fs.readFileSync(path.join(dir, f)));
  return h.digest("hex");
}

const migrate = new command.local.Command(
  "d1-migrate",
  {
    create: "node scripts/d1-migrate.mjs",
    update: "node scripts/d1-migrate.mjs",
    dir: __dirname,
    environment: { CLOUDFLARE_API_TOKEN: cfToken, CLOUDFLARE_ACCOUNT_ID: accountId, D1_DATABASE_ID: db.id, D1_MIGRATIONS_DIR: migrationsDir },
    triggers: [hashDir(migrationsDir), db.id]
  },
  { dependsOn: [db] }
);

// --- Worker bundle -----------------------------------------------------------

function hashSources(): string {
  const h = crypto.createHash("sha256");
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!["node_modules", "dist", ".wrangler"].includes(entry.name)) walk(p);
      } else if (/\.(ts|json|jsonc)$/.test(entry.name) && !entry.name.endsWith(".test.ts")) h.update(p).update(fs.readFileSync(p));
    }
  };
  walk(path.join(workerDir, "src"));
  walk(path.join(repoRoot, "packages", "core", "src"));
  h.update(fs.readFileSync(path.join(workerDir, "wrangler.jsonc")));
  h.update(fs.readFileSync(path.join(repoRoot, "pnpm-lock.yaml")));
  return h.digest("hex");
}

const sourcesHash = hashSources();
const distDir = path.join(workerDir, "dist");
const bundlePath = path.join(distDir, "server.js");
const hashPath = path.join(distDir, ".sources-sha256");
const upToDate = fs.existsSync(bundlePath) && fs.existsSync(hashPath) && fs.readFileSync(hashPath, "utf8") === sourcesHash;
if (!upToDate) {
  execFileSync("pnpm", ["exec", "wrangler", "deploy", "--dry-run", "--outdir", "dist"], { cwd: workerDir, stdio: "inherit" });
  fs.writeFileSync(hashPath, sourcesHash);
}
const bundle = fs.readFileSync(bundlePath, "utf8");

// --- Durable Object migrations -----------------------------------------------
// Cloudflare applies DO migrations once per tag; re-sending an applied tag fails (code 10079).
// Like wrangler, read the script's current tag and send only what is pending.

const DO_MIGRATIONS: { tag: string; newSqliteClasses?: string[] }[] = [
  { tag: "v1", newSqliteClasses: [MCP_OBJECT_CLASS] }
  // Append new steps here (never edit an applied one).
];

function pendingMigrations(currentTag: string | null) {
  const applied = currentTag ? DO_MIGRATIONS.findIndex((m) => m.tag === currentTag) : -1;
  if (currentTag && applied === -1) throw new Error(`Worker is at unknown DO migration tag "${currentTag}"`);
  const pending = DO_MIGRATIONS.slice(applied + 1);
  if (pending.length === 0) return undefined;
  return { oldTag: currentTag ?? undefined, newTag: pending[pending.length - 1]!.tag, steps: pending.map(({ tag: _t, ...step }) => step) };
}

async function currentMigrationTag(token: string): Promise<string | null> {
  const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts`, { headers: { authorization: `Bearer ${token}` } });
  const body = (await res.json()) as { success?: boolean; errors?: unknown; result?: { id: string; migration_tag?: string }[] };
  if (!res.ok || !body.success) throw new Error(`Cloudflare list scripts failed (${res.status}): ${JSON.stringify(body.errors)}`);
  return body.result?.find((s) => s.id === workerName)?.migration_tag || null;
}

const migrations = cfToken.apply(async (t) => pendingMigrations(await currentMigrationTag(t)));

// --- Worker script -----------------------------------------------------------

const bindings: pulumi.Input<cloudflare.types.input.WorkersScriptBinding>[] = [
  { type: "kv_namespace", name: "CACHE", namespaceId: cache.id },
  { type: "d1", name: "DB", id: db.id },
  { type: "durable_object_namespace", name: "MCP_OBJECT", className: MCP_OBJECT_CLASS },
  // Direct Worker-to-Worker call into KYB Brasil (no public HTTP hop, no x402; see apps/worker/src/kyb.ts).
  { type: "service", name: "KYB", service: kybWorkerName },
  { type: "plain_text", name: "X402_NETWORK", text: x402Network },
  { type: "plain_text", name: "X402_FACILITATOR_URL", text: facilitatorUrl },
  { type: "plain_text", name: "FREE_TIER_DAILY_LIMIT", text: freeTierDailyLimit },
  { type: "secret_text", name: "PAY_TO", text: payTo },
  { type: "secret_text", name: "KYB_INTERNAL_KEY", text: kybInternalKey }
];
if (issuerUrl) bindings.push({ type: "plain_text", name: "ISSUER_URL", text: issuerUrl });
if (internalApiKey) bindings.push({ type: "secret_text", name: "INTERNAL_API_KEY", text: internalApiKey });
if (attestPrivateKey) bindings.push({ type: "secret_text", name: "ATTEST_PRIVATE_KEY", text: attestPrivateKey });
if (attestPreviousKeys) bindings.push({ type: "plain_text", name: "ATTEST_PREVIOUS_KEYS", text: attestPreviousKeys });
if (glamaClaim) bindings.push({ type: "plain_text", name: "GLAMA_CLAIM", text: glamaClaim });
if (cdpApiKeyId && cdpApiKeySecret) {
  bindings.push({ type: "secret_text", name: "CDP_API_KEY_ID", text: cdpApiKeyId });
  bindings.push({ type: "secret_text", name: "CDP_API_KEY_SECRET", text: cdpApiKeySecret });
}

const worker = new cloudflare.WorkersScript(
  "worker",
  {
    accountId,
    scriptName: workerName,
    mainModule: "server.js",
    content: bundle,
    compatibilityDate: COMPATIBILITY_DATE,
    compatibilityFlags: COMPATIBILITY_FLAGS,
    bindings,
    migrations, // only the DO migrations not yet applied to this script
    observability: { enabled: true, headSamplingRate: 1 }
  },
  { dependsOn: [migrate] }
);

const subdomain = new cloudflare.WorkersScriptSubdomain("subdomain", { accountId, scriptName: worker.scriptName, enabled: true, previewsEnabled: false });

// Daily review: re-run KYB on every live credential (apps/worker/src/server.ts `scheduled`).
const cron = new cloudflare.WorkersCronTrigger("daily-review", { accountId, scriptName: worker.scriptName, schedules: [{ cron: DAILY_REVIEW_CRON }] });

// --- Outputs -----------------------------------------------------------------

export const kvNamespaceId = cache.id;
export const d1DatabaseId = db.id;
export const d1DatabaseName = db.name;
export const scriptName = worker.scriptName;
export const kybServiceBinding = pulumi.output(kybWorkerName);
export const network = x402Network;
export const bundleSha256 = pulumi.output(sourcesHash);
export const workersDevEnabled = subdomain.enabled;
export const dailyReviewCron = cron.schedules.apply((s) => s[0]?.cron ?? "");
