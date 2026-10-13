# Security

KYA Brasil issues credentials that other parties rely on, so reports are taken seriously.

**Report privately** through GitHub (Security → [Report a vulnerability](https://github.com/celfons/kya-brasil/security/advisories/new)) or to marcelfons@gmail.com with "KYA security" in the subject. Do not open a
public issue for a vulnerability. You will get an answer within 72 hours and a fix or a mitigation plan
within 14 days for anything that lets a credential be issued, kept or verified wrongly.

In scope: the issuer (`apps/worker`), the domain logic (`packages/core`), the client (`packages/agent-tools`),
the deployment (`infra`, workflows). Out of scope: KYB Brasil (a separate, closed, optional service), BrasilAPI and CNPJ.ws, the x402
facilitator, ICP-Brasil certificate authorities.

What we consider severe: issuing without a valid e-CNPJ chain, accepting a challenge signature for another
agent or company, verifying a modified credential, leaking the certificate holder's personal data,
bypassing payment on paid routes.

Keys: the issuer signs with Ed25519; keys live only in the deployment's encrypted configuration and are
rotated through `scripts/rotate-attest-key.mjs`, keeping the previous public key published as `retired`.
