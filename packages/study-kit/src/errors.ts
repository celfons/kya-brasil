/**
 * Error categories recorded per failed attempt. They are mapped from the library's error codes, check rules and
 * messages; the participant's own text is only matched, never stored.
 */
export const ERROR_CATEGORIES = ["signature", "icp_chain", "mandate", "revocation", "freshness", "replay", "runtime", "other"] as const;
export type ErrorCategory = (typeof ERROR_CATEGORIES)[number];

// Library codes first (a message such as "KYA_PRINCIPAL_PROOF_INVALID: certificate: expired" is a chain problem),
// then words from check rules and messages.
const CODES: [RegExp, ErrorCategory][] = [
  [/KYA_REQUEST_REPLAYED/, "replay"],
  [/KYA_CERTIFICATE_REVOKED|\bCERTIFICATE_REVOKED/, "revocation"],
  [/KYA_CERTIFICATE_STATUS_(STALE|UNKNOWN|UNAVAILABLE)|KYA_CREDENTIAL_NOT_ACTIVE|KYA_SIGNATURE_(EXPIRED|NOT_YET_VALID|TTL)|KYA_CLOCK_INVALID/, "freshness"],
  [/KYA_BAD_SIGNATURE|KYA_BODY_(MISMATCH|UNSIGNED)|KYA_HEADERS_MISSING/, "signature"],
  [/KYA_PRINCIPAL_PROOF|KYA_ISSUER_NOT_TRUSTED|KYA_CREDENTIAL_(MALFORMED|MISMATCH|MISSING)|\bCERTIFICATE_INVALID|\bCHALLENGE_FAILED/, "icp_chain"],
  [/\bINVALID_INPUT/, "mandate"]
];
const WORDS: [RegExp, ErrorCategory][] = [
  [/replay|repeti/i, "replay"],
  [/revoga|revoked|revocation|\blcr\b|\bcrl\b/i, "revocation"],
  [/max_per_operation|max_per_day|counterpart|contraparte|fornecedor|currenc|moeda|\bactions?\b|payment_instruments|mandate|mandato|ceiling|teto|limite/i, "mandate"],
  [/nextUpdate|next_update|stale|expired|expir|not yet valid|clock|rel[oó]gio|skew|future|fresh|validity|valid_until|valid_from/i, "freshness"],
  [/signature|assinatura/i, "signature"],
  [/anchor|chain|cadeia|certificat|icp|\bcms\b|pfx|pkcs/i, "icp_chain"]
];

/** Category of a library error code, check rule or message. */
export function categorize(text: string | null | undefined): ErrorCategory {
  const s = String(text ?? "");
  for (const [re, cat] of CODES) if (re.test(s)) return cat;
  for (const [re, cat] of WORDS) if (re.test(s)) return cat;
  return "other";
}

/** Category of an exception thrown by the participant's code: library errors by their code/message, anything else is "runtime". */
export function categorizeThrown(e: unknown): ErrorCategory {
  const err = e as { name?: string; code?: string; message?: string } | null;
  if (err && (err.name === "KyaError" || typeof err.code === "string") && err.code !== "ERR_MODULE_NOT_FOUND") {
    const cat = categorize(`${err.code ?? ""} ${err.message ?? ""}`);
    return cat === "other" ? "runtime" : cat;
  }
  return "runtime";
}

/** Category of a failed check of verifySelfIssuedCredential (T1). */
export function categorizeSelfIssuedRule(rule: string, detail: string): ErrorCategory {
  switch (rule) {
    case "signature":
      return /chain|anchor|cadeia/i.test(detail) ? "icp_chain" : "signature";
    case "certificate":
      return "icp_chain";
    case "mandate":
      return "mandate";
    case "validity":
      return "freshness";
    default:
      return categorize(`${rule} ${detail}`);
  }
}
