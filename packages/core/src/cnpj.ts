/**
 * CNPJ (Cadastro Nacional da Pessoa Jurídica) helpers.
 *
 * Since 2026 the Receita Federal accepts alphanumeric CNPJs (letters in the first
 * 12 positions, digits in the 2 check digits). The check-digit algorithm maps each
 * character to (ASCII code - 48), so digits keep their value and letters get 17..42.
 */

const WEIGHTS_1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
const WEIGHTS_2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];

/** Strip punctuation and whitespace, upper-case letters. Does not validate. */
export function normalizeCnpj(input: string): string {
  return input.replace(/[^0-9A-Za-z]/g, "").toUpperCase();
}

function charValue(ch: string): number {
  return ch.charCodeAt(0) - 48;
}

function checkDigit(base: string, weights: number[]): number {
  let sum = 0;
  for (let i = 0; i < weights.length; i++) {
    sum += charValue(base[i]!) * weights[i]!;
  }
  const mod = sum % 11;
  return mod < 2 ? 0 : 11 - mod;
}

/** True when the string is a syntactically valid (numeric or alphanumeric) CNPJ. */
export function isValidCnpj(input: string): boolean {
  const cnpj = normalizeCnpj(input);
  if (!/^[0-9A-Z]{12}[0-9]{2}$/.test(cnpj)) return false;
  if (/^(.)\1{13}$/.test(cnpj)) return false;
  const d1 = checkDigit(cnpj.slice(0, 12), WEIGHTS_1);
  const d2 = checkDigit(cnpj.slice(0, 12) + String(d1), WEIGHTS_2);
  return cnpj[12] === String(d1) && cnpj[13] === String(d2);
}

/** Format as XX.XXX.XXX/XXXX-XX. Input must already be 14 chars. */
export function formatCnpj(cnpj: string): string {
  const c = normalizeCnpj(cnpj);
  if (c.length !== 14) throw new Error(`Invalid CNPJ length: ${c.length}`);
  return `${c.slice(0, 2)}.${c.slice(2, 5)}.${c.slice(5, 8)}/${c.slice(8, 12)}-${c.slice(12)}`;
}

/** First 8 characters: identifies the company; the remaining 4 identify the branch (0001 = HQ). */
export function cnpjRoot(cnpj: string): string {
  return normalizeCnpj(cnpj).slice(0, 8);
}

export function isHeadquarters(cnpj: string): boolean {
  return normalizeCnpj(cnpj).slice(8, 12) === "0001";
}
