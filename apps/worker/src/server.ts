import { checkGlobal } from "./cache";
import type { AppEnv } from "./env";
import { buildHttpApp } from "./http/routes";
import { dailyReview } from "./service";

let httpApp: ReturnType<typeof buildHttpApp> | undefined;

export default {
  async fetch(request: Request, env: AppEnv, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
    if (url.pathname !== "/health") {
      const g = await checkGlobal(env, ip);
      if (!g.allowed) {
        return new Response(JSON.stringify({ error: "RATE_LIMITED", message: `Too many requests from this IP; try again in ${g.retryAfter}s.` }), { status: 429, headers: { "content-type": "application/json", "retry-after": String(g.retryAfter) } });
      }
    }
    httpApp ??= buildHttpApp(env);
    return httpApp.fetch(request, env, ctx);
  },
  /** Daily: re-run KYB on live credentials (cron trigger set by infra). */
  async scheduled(_event: ScheduledEvent, env: AppEnv, ctx: ExecutionContext) {
    ctx.waitUntil(dailyReview(env).then((r) => console.log("daily review", JSON.stringify(r))));
  }
};
