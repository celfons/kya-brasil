# Cloud e-CNPJ provider (template)

KYA Brasil supports e-CNPJ certificates held in the cloud by an ICP-Brasil PSC (prestador de serviço de confiança)
through one small interface, `CloudSignatureProvider` in `@kya-brasil/core`. The project ships no PSC
implementation: each PSC has its own contract, registration and API details, so whoever has an agreement with a
PSC implements the interface for it. [`my-psc.mjs`](my-psc.mjs) is the template, with the three methods to fill in.

KYA does the rest the same way for every provider: PKCE and a single-use `state`, building the CMS signature,
computing exactly what is signed (the hash of the signed attributes over the challenge text), and issuing.

| Entry point | How |
| --- | --- |
| Library | `const session = await provider.exchangeCode(...)`, then `(await cloudSigner(session)).sign(text)`; `pkcePair()` and `newState()` for the authorization step. |
| Terminal | `npx -p @kya-brasil/agent-tools kya-sign --cloud ./my-psc.mjs --link "<sign_url>"`: opens the browser for the approval and listens once on `127.0.0.1` for the redirect. Register `http://127.0.0.1:<port>/callback` at the PSC (fix the port with `--port`). |
| /sign page | On your own issuer, return the provider from `apps/worker/src/cloud-providers.ts`. The page shows a "Certificado em nuvem" tab; the redirect URI to register is `<issuer>/sign/cloud/callback`. |

What the issuer holds in the page flow: the PKCE verifier and the request ids in KV for 10 minutes, single use;
the PSC session only while the callback runs, never stored; and it only ever signs the stored challenge.
