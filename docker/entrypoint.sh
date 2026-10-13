#!/bin/sh
# Builds .dev.vars from the environment, keeps the signing key and the local D1/KV state in /data,
# applies the migrations and starts the Worker on 0.0.0.0:$PORT.
set -eu
cd /app/apps/worker
STATE=/data/state
mkdir -p "$STATE"

# Signing key: generated once, kept in the volume. Credentials issued here verify against /.well-known/kya.json
# of this container only.
if [ -z "${ATTEST_PRIVATE_KEY:-}" ]; then
  if [ ! -s /data/attest.key ]; then
    node /app/scripts/gen-attest-key.mjs > /data/attest.key
    echo "generated a new signing key in /data/attest.key"
  fi
  ATTEST_PRIVATE_KEY=$(cat /data/attest.key)
fi

# ICP-Brasil anchors: the bundle shipped in the repository unless ICP_ANCHORS_PEM is given.
if [ -z "${ICP_ANCHORS_PEM:-}" ] && [ -s /app/anchors/icp-brasil.pem ]; then
  ICP_ANCHORS_PEM=$(cat /app/anchors/icp-brasil.pem)
fi

{
  echo "PAY_TO=${PAY_TO:-0x0000000000000000000000000000000000000001}"
  echo "ATTEST_PRIVATE_KEY=$ATTEST_PRIVATE_KEY"
  echo "REGISTRATION_SOURCE=${REGISTRATION_SOURCE:-public}"
  [ -n "${KYB_URL:-}" ] && echo "KYB_URL=$KYB_URL"
  [ -n "${KYB_INTERNAL_KEY:-}" ] && echo "KYB_INTERNAL_KEY=$KYB_INTERNAL_KEY"
  [ -n "${INTERNAL_API_KEY:-}" ] && echo "INTERNAL_API_KEY=$INTERNAL_API_KEY"
  [ -n "${EVM_RPC_URLS:-}" ] && echo "EVM_RPC_URLS=$EVM_RPC_URLS"
  [ -n "${CDP_API_KEY_ID:-}" ] && echo "CDP_API_KEY_ID=$CDP_API_KEY_ID"
  [ -n "${CDP_API_KEY_SECRET:-}" ] && echo "CDP_API_KEY_SECRET=$CDP_API_KEY_SECRET"
  # .dev.vars takes multi-line values in double quotes
  printf 'ICP_ANCHORS_PEM="%s"\n' "$ICP_ANCHORS_PEM"
} > .dev.vars

pnpm exec wrangler d1 migrations apply kya-br --local --persist-to "$STATE" >/dev/null
echo "KYA Brasil issuer on http://0.0.0.0:${PORT} (issuer url ${ISSUER_URL:-http://localhost:8787}, network ${X402_NETWORK:-eip155:84532}, registration ${REGISTRATION_SOURCE:-public})"
exec pnpm exec wrangler dev --ip 0.0.0.0 --port "${PORT}" --persist-to "$STATE" \
  --var "ISSUER_URL:${ISSUER_URL:-http://localhost:8787}" \
  --var "X402_NETWORK:${X402_NETWORK:-eip155:84532}" \
  --var "X402_FACILITATOR_URL:${X402_FACILITATOR_URL:-https://x402.org/facilitator}" \
  --var "FREE_TIER_DAILY_LIMIT:${FREE_TIER_DAILY_LIMIT:-50}"
