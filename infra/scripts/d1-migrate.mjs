#!/usr/bin/env node
/**
 * Apply SQL migrations to a remote D1 database through the Cloudflare HTTP API.
 * Idempotent: applied file names are recorded in `d1_migrations` (same table name and
 * shape wrangler uses, so `wrangler d1 migrations list --remote` stays truthful).
 *
 * Env: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, D1_DATABASE_ID, D1_MIGRATIONS_DIR
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const { CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, D1_DATABASE_ID, D1_MIGRATIONS_DIR } = process.env;
for (const [k, v] of Object.entries({ CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, D1_DATABASE_ID, D1_MIGRATIONS_DIR })) {
  if (!v) {
    console.error(`missing env ${k}`);
    process.exit(2);
  }
}

const endpoint = `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/d1/database/${D1_DATABASE_ID}/query`;

async function query(sql, params = []) {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify({ sql, params })
  });
  const body = await res.json();
  if (!res.ok || !body.success) {
    throw new Error(`D1 query failed (${res.status}): ${JSON.stringify(body.errors ?? body)}`);
  }
  return body.result;
}

await query(
  `CREATE TABLE IF NOT EXISTS d1_migrations (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     name TEXT UNIQUE NOT NULL,
     applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
   )`
);
const [{ results }] = await query("SELECT name FROM d1_migrations");
const applied = new Set(results.map((r) => r.name));

const files = readdirSync(D1_MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort();
let count = 0;
for (const file of files) {
  if (applied.has(file)) continue;
  const sql = readFileSync(join(D1_MIGRATIONS_DIR, file), "utf8");
  console.log(`applying ${file}`);
  await query(sql);
  await query("INSERT INTO d1_migrations (name) VALUES (?1)", [file]);
  count++;
}
console.log(`${count} migration(s) applied, ${files.length - count} already present`);
