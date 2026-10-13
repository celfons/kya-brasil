# KYA Brasil issuer in a container: the same Worker runtime (workerd, via `wrangler dev`) with D1, KV and
# the Durable Object emulated locally. For evaluation and integration work, not for production
# (production runs on Cloudflare; see docs/SELF-HOSTING.md).
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* \
 && corepack enable && corepack prepare pnpm@10.28.0 --activate
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/worker/package.json apps/worker/
COPY packages/core/package.json packages/core/
COPY packages/agent-tools/package.json packages/agent-tools/
COPY infra/package.json infra/
RUN pnpm install --frozen-lockfile --filter @kya-br/worker... --filter @kya-br/core...
COPY apps/worker apps/worker
COPY packages/core packages/core
COPY scripts scripts
COPY anchors anchors
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /data
ENV WRANGLER_SEND_METRICS=false PORT=8787
EXPOSE 8787
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s CMD curl -fsS http://127.0.0.1:8787/health || exit 1
ENTRYPOINT ["/entrypoint.sh"]
