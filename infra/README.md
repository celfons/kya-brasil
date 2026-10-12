# infra

Pulumi program for KYA Brasil on Cloudflare. One stack per environment (`dev`, `prod`), created and
configured by `.github/workflows/cd.yml` from the GitHub environment's secrets; nothing runs from a laptop.

Resources: KV (`<worker>-cache`), D1 (`<worker>`) with migrations from `apps/worker/migrations`, the Worker
script with a Service Binding `KYB` to the KYB Brasil Worker of the same account, a daily cron trigger,
and the workers.dev subdomain.

The ICP-Brasil trust anchors are not infra: `scripts/icp-anchors.mjs` uploads the ITI PEM bundle to KV
(`icp:anchors`), and the CD runs it after every deploy.
