import { checkGlobal } from "./cache";
import type { AppEnv } from "./env";
import { buildHttpApp } from "./http/routes";
import { KyaMcp } from "./mcp";
import { dailyReview } from "./service";

export { KyaMcp };

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
    if (url.pathname === "/mcp" || url.pathname.startsWith("/mcp/")) {
      // The client IP reaches the agent as this.props.ip, so the free tier is per IP, not per session.
      const ctxWithProps = { waitUntil: ctx.waitUntil.bind(ctx), passThroughOnException: ctx.passThroughOnException.bind(ctx), props: { ip } } as unknown as ExecutionContext;
      return KyaMcp.serve("/mcp", { binding: "MCP_OBJECT" }).fetch(request, env, ctxWithProps);
    }
    httpApp ??= buildHttpApp(env);
    return httpApp.fetch(request, env, ctx);
  },
  /** Daily: e-CNPJ CRL and registration status of live credentials (cron trigger set by infra). */
  async scheduled(_event: ScheduledEvent, env: AppEnv, ctx: ExecutionContext) {
    ctx.waitUntil(dailyReview(env).then((r) => console.log("daily review", JSON.stringify(r))));
  }
};
