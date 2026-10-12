import type { AppEnv } from "./env";

const DAY = 24 * 3600;

export async function cached<T>(env: AppEnv, key: string, ttlSeconds: number, compute: () => Promise<T>): Promise<{ value: T; hit: boolean }> {
  const hit = await env.CACHE.get<T>(key, "json");
  if (hit) return { value: hit, hit: true };
  const value = await compute();
  await env.CACHE.put(key, JSON.stringify(value), { expirationTtl: ttlSeconds });
  return { value, hit: false };
}

/** KV counters are eventually consistent: soft limits against abuse, not billing controls. */
async function bump(env: AppEnv, key: string, ttlSeconds: number): Promise<number> {
  const current = Number((await env.CACHE.get(key)) ?? "0") + 1;
  await env.CACHE.put(key, String(current), { expirationTtl: ttlSeconds });
  return current;
}

export interface LimitResult {
  allowed: boolean;
  remaining: number;
  retryAfter: number;
}

const hourWindow = () => Math.floor(Date.now() / 3600000);
const secondsToNextHour = () => 3600 - Math.floor((Date.now() % 3600000) / 1000);
const today = () => new Date().toISOString().slice(0, 10);
const secondsToMidnight = () => DAY - Math.floor((Date.now() % (DAY * 1000)) / 1000);

/** Free verification: FREE_TIER_DAILY_LIMIT per IP per day; above it the paid route (0.01) has no limit. */
export async function checkFreeTier(env: AppEnv, callerKey: string): Promise<LimitResult> {
  const limit = Number(env.FREE_TIER_DAILY_LIMIT || "50");
  const n = await bump(env, `rl:${today()}:${callerKey}`, DAY);
  return { allowed: n <= limit, remaining: Math.max(0, limit - n), retryAfter: secondsToMidnight() };
}

export const GLOBAL_HOURLY_LIMIT = 600;
export async function checkGlobal(env: AppEnv, ip: string): Promise<LimitResult> {
  const n = await bump(env, `rlg:${hourWindow()}:${ip}`, 3600);
  return { allowed: n <= GLOBAL_HOURLY_LIMIT, remaining: Math.max(0, GLOBAL_HOURLY_LIMIT - n), retryAfter: secondsToNextHour() };
}

/** Registration attempts per IP per day (each costs a KYB call once paid; the challenge step itself is free). */
export async function checkRegistrations(env: AppEnv, ip: string): Promise<LimitResult> {
  const n = await bump(env, `rlr:${today()}:${ip}`, DAY);
  return { allowed: n <= 200, remaining: Math.max(0, 200 - n), retryAfter: secondsToMidnight() };
}
