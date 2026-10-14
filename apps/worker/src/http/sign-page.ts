/**
 * /sign: the page the company's e-CNPJ holder (owner or accountant) opens to authorize an agent. Everything
 * runs in the browser: the .pfx and its password never leave the computer. Two ways to sign:
 *   A1 (.pfx / .p12 file): node-forge reads the file (legacy 3DES/RC2 PKCS#12 included) and signs here;
 *   A3 (token, smart card, cloud) or any ICP-Brasil signer: download the challenge as a .txt, sign it in the
 *   usual software, upload the .p7s.
 * The signing steps mirror packages/agent-tools/src/pfx.ts; keep the two in sync.
 */

// node-forge from cdnjs, pinned with Subresource Integrity (the browser refuses any other bytes).
const FORGE_URL = "https://cdnjs.cloudflare.com/ajax/libs/forge/1.4.0/forge.min.js";
const FORGE_SRI = "sha512-7swq6FHnr/GlTmAjeML/XwRqb7zXLFhR3IsR3lcp4pxrpnU6R9hasA5MwDhJeRqW7DR9+JICZ02nnrp/p3SXGg==";

/** Strict CSP for /sign: only this inline script (by nonce) and the pinned forge; calls only to this origin. */
export function signPageCsp(nonce: string): string {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}' https://cdnjs.cloudflare.com`,
    "style-src 'unsafe-inline'",
    "connect-src 'self'",
    "img-src 'self' data:",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'"
  ].join("; ");
}

export function signHtml(origin: string, nonce: string): string {
  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Autorizar agente | KYA Brasil</title>
<link rel="icon" href="${origin}/icon.svg">
<style>
:root{--bg:#f7f7f4;--fg:#1d2129;--muted:#5d6470;--line:#d4d8de;--panel:#fff;--accent:#0b6e4f;--warn:#9a4d00;--bad:#b42318}
@media(prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e8eaee;--muted:#a0a7b2;--line:#3a414b;--panel:#1c2128;--accent:#4fc69a;--warn:#e5a04a;--bad:#f97066;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:24px 16px 48px}
main{max-width:760px;margin:0 auto;display:grid;gap:20px}h1{font-size:1.5rem;margin:0}h2{font-size:1rem;margin:0 0 8px}p{margin:0}
.muted{color:var(--muted)}.box{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px 16px;display:grid;gap:10px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}dt{color:var(--muted)}dd{margin:0;word-break:break-all}
pre,code,textarea{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em}pre{margin:0;white-space:pre-wrap;word-break:break-all}
textarea{width:100%;min-height:90px;border:1px solid var(--line);border-radius:6px;padding:8px;background:var(--bg);color:var(--fg)}
input[type=password],input[type=text]{width:100%;padding:8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
button,.btn{font:inherit;padding:8px 14px;border-radius:6px;border:1px solid var(--accent);background:var(--accent);color:#fff;cursor:pointer;text-decoration:none;display:inline-block}
button.alt,.btn.alt{background:transparent;color:var(--accent)}button:disabled{opacity:.5;cursor:not-allowed}
.tabs{display:flex;gap:8px;flex-wrap:wrap}.tabs button{background:transparent;color:var(--fg);border-color:var(--line)}.tabs button[aria-selected=true]{border-color:var(--accent);color:var(--accent)}
.warn{color:var(--warn)}.bad{color:var(--bad)}.ok{color:var(--accent)}[hidden]{display:none!important}
label{display:grid;gap:4px}.grid{display:grid;gap:10px}a{color:var(--accent)}
</style>
</head>
<body>
<main>
  <header>
    <h1>Autorizar um agente de IA a agir pela empresa</h1>
    <p class="muted">Assine com o e-CNPJ da empresa. A assinatura acontece neste navegador: o certificado e a senha não são enviados a ninguém.</p>
  </header>

  <section class="box" id="summary">
    <h2>O que você está autorizando</h2>
    <dl>
      <dt>Empresa (CNPJ)</dt><dd id="s-cnpj">-</dd>
      <dt>Agente</dt><dd id="s-agent">-</dd>
      <dt>Emissor</dt><dd id="s-issuer">-</dd>
      <dt>Válido até</dt><dd id="s-exp">-</dd>
    </dl>
    <div id="s-mandate-wrap" hidden><b>Mandato (o que o agente poderá fazer)</b><pre id="s-mandate"></pre></div>
    <p id="s-alert" class="bad" hidden></p>
    <details><summary class="muted">Texto exato que será assinado</summary><pre id="s-text"></pre></details>
  </section>

  <section class="box" id="nolink" hidden>
    <h2>Desafio</h2>
    <p class="muted">Abra esta página pelo link que o agente ou a plataforma enviou, ou cole o texto do desafio abaixo.</p>
    <textarea id="manual-text" placeholder="KYA Brasil: prove this agent key acts for a company&#10;issuer: …"></textarea>
    <button id="manual-go" class="alt">Usar este texto</button>
  </section>

  <section class="box" id="signbox">
    <h2>Assinar com o e-CNPJ</h2>
    <div class="tabs" role="tablist">
      <button role="tab" aria-selected="true" data-tab="a1">Arquivo .pfx (certificado A1)</button>
      <button role="tab" aria-selected="false" data-tab="a3">Token, cartão ou outro assinador (A3)</button>
    </div>
    <div id="tab-a1" class="grid">
      <label>Arquivo do certificado (.pfx ou .p12)<input type="file" id="pfx" accept=".pfx,.p12,application/x-pkcs12"></label>
      <label>Senha do certificado<input type="password" id="pw" autocomplete="off"></label>
      <p><button id="sign-a1">Assinar</button></p>
    </div>
    <div id="tab-a3" hidden>
      <p>1. Baixe o desafio e assine o arquivo no programa que você já usa (por exemplo o Assinador SERPRO ou o do fabricante do token). Não abra nem edite o arquivo antes de assinar.</p>
      <p><a class="btn alt" id="dl" download="desafio-kya.txt" href="#">Baixar desafio-kya.txt</a></p>
      <label>2. Envie a assinatura gerada (.p7s)<input type="file" id="p7s" accept=".p7s,.p7m,.pem,.txt,application/pkcs7-signature"></label>
    </div>
    <p id="sign-msg" class="muted"></p>
  </section>

  <section class="box" id="result" hidden>
    <h2>Assinatura pronta</h2>
    <div id="need-agent" hidden>
      <label>Assinatura do agente (o agente envia; cole aqui se não veio no link)<input type="text" id="agent-sig"></label>
    </div>
    <p><button id="prove">Emitir a credencial</button></p>
    <details><summary class="muted">Assinatura e-CNPJ (base64), para enviar manualmente</summary><textarea id="sig" readonly></textarea><p><button class="alt" id="copy">Copiar</button></p></details>
    <p id="prove-msg"></p>
  </section>

  <footer class="muted"><a href="${origin}/">KYA Brasil</a> · <a href="${origin}/docs">API</a> · código aberto: <a href="https://github.com/celfons/kya-brasil">github.com/celfons/kya-brasil</a></footer>
</main>
<script src="${FORGE_URL}" integrity="${FORGE_SRI}" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script nonce="${nonce}">
(() => {
  const $ = (id) => document.getElementById(id);
  const q = new URLSearchParams(location.search);
  const state = { id: q.get("id"), challengeId: q.get("challenge_id"), agentSig: q.get("agent_signature"), text: null, cnpj: null, signature: null };
  const fromB64u = (s) => new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)));
  const alertBad = (msg) => { $("s-alert").textContent = msg; $("s-alert").hidden = false; };

  function load(text) {
    state.text = text;
    const field = (k) => (new RegExp("^" + k + ": (.*)$", "m").exec(text) || [])[1] || "";
    state.cnpj = field("cnpj").replace(/\\D/g, "");
    $("s-cnpj").textContent = state.cnpj ? state.cnpj.replace(/^(\\d{2})(\\d{3})(\\d{3})(\\d{4})(\\d{2})$/, "$1.$2.$3/$4-$5") : "-";
    $("s-agent").textContent = field("agent") || "-";
    $("s-issuer").textContent = field("issuer") || "-";
    const exp = field("expires");
    $("s-exp").textContent = exp ? new Date(exp).toLocaleString("pt-BR") : "-";
    $("s-text").textContent = text;
    $("dl").href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    if (field("issuer") && field("issuer") !== location.origin) alertBad("Atenção: este desafio é de outro emissor (" + field("issuer") + "), não deste site. Não assine.");
    if (exp && Date.parse(exp) < Date.now()) alertBad("Este desafio expirou. Peça um novo link a quem está registrando o agente.");
    if (state.id) {
      fetch("/v1/agents/" + encodeURIComponent(state.id)).then((r) => r.ok ? r.json() : null).then((v) => {
        if (!v) return;
        const m = v.requested_mandate || (v.credential && v.credential.mandate);
        if (m) { $("s-mandate").textContent = JSON.stringify(m, null, 2); $("s-mandate-wrap").hidden = false; }
        if (v.status && v.status !== "pending") alertBad("Este registro está com status " + v.status + "; o link pode ser antigo.");
      }).catch(() => {});
    }
  }

  if (q.get("text")) { try { load(fromB64u(q.get("text"))); } catch { alertBad("O link está incompleto ou foi alterado."); } }
  else { $("nolink").hidden = false; }
  $("manual-go").onclick = () => { const t = $("manual-text").value.replace(/\\r\\n/g, "\\n").replace(/\\n+$/, ""); if (t) load(t); };

  document.querySelectorAll("[data-tab]").forEach((b) => b.onclick = () => {
    document.querySelectorAll("[data-tab]").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
    $("tab-a1").hidden = b.dataset.tab !== "a1"; $("tab-a3").hidden = b.dataset.tab !== "a3";
  });

  function ready(signature) {
    state.signature = signature;
    $("sig").value = signature;
    $("result").hidden = false;
    $("need-agent").hidden = !!state.agentSig;
    if (state.agentSig) $("agent-sig").value = state.agentSig;
    $("prove").disabled = !state.id || !state.challengeId;
    $("sign-msg").innerHTML = '<span class="ok">Assinado.</span>' + (state.id && state.challengeId ? " Agora emita a credencial." : " Envie a assinatura abaixo para quem está registrando o agente.");
  }

  $("sign-a1").onclick = async () => {
    const f = $("pfx").files[0];
    if (!state.text) return ($("sign-msg").textContent = "Falta o desafio.");
    if (!f) return ($("sign-msg").textContent = "Escolha o arquivo .pfx.");
    if (typeof forge === "undefined") return ($("sign-msg").textContent = "Não foi possível carregar a biblioteca de assinatura; verifique a conexão e recarregue.");
    $("sign-msg").textContent = "Assinando…";
    try {
      const bytes = new Uint8Array(await f.arrayBuffer());
      let bin = ""; for (const b of bytes) bin += String.fromCharCode(b);
      const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(bin), false, $("pw").value);
      const O = forge.pki.oids;
      const bag = [O.pkcs8ShroudedKeyBag, O.keyBag].flatMap((t) => p12.getBags({ bagType: t })[t] || []).find((x) => x.key);
      if (!bag) throw new Error("o arquivo não tem chave privada");
      const certs = (p12.getBags({ bagType: O.certBag })[O.certBag] || []).map((x) => x.cert).filter(Boolean);
      const leaf = certs.find((c) => c.publicKey.n && c.publicKey.n.equals(bag.key.n));
      if (!leaf) throw new Error("nenhum certificado do arquivo corresponde à chave");
      const cn = String((leaf.subject.getField("CN") || {}).value || "");
      const certCnpj = (/:(\\d{14})\\s*$/.exec(cn) || [])[1];
      if (certCnpj && state.cnpj && certCnpj !== state.cnpj) throw new Error("este certificado é do CNPJ " + certCnpj + ", o desafio é do CNPJ " + state.cnpj);
      if (leaf.validity.notAfter < new Date()) throw new Error("o certificado venceu em " + leaf.validity.notAfter.toLocaleDateString("pt-BR"));
      const p7 = forge.pkcs7.createSignedData();
      p7.content = forge.util.createBuffer(forge.util.encodeUtf8(state.text));
      p7.addCertificate(leaf); certs.forEach((c) => { if (c !== leaf) p7.addCertificate(c); });
      p7.addSigner({ key: bag.key, certificate: leaf, digestAlgorithm: O.sha256, authenticatedAttributes: [{ type: O.contentType, value: O.data }, { type: O.messageDigest }, { type: O.signingTime, value: new Date() }] });
      p7.sign({ detached: true });
      $("pw").value = "";
      ready(forge.util.encode64(forge.asn1.toDer(p7.toAsn1()).getBytes()));
    } catch (e) {
      const m = String(e && e.message || e);
      $("sign-msg").innerHTML = '<span class="bad"></span>';
      $("sign-msg").firstChild.textContent = /MAC could not be verified|Invalid password/i.test(m) ? "Senha incorreta." : "Não foi possível assinar: " + m;
    }
  };

  $("p7s").onchange = async () => {
    const f = $("p7s").files[0]; if (!f) return;
    const bytes = new Uint8Array(await f.arrayBuffer());
    let sig;
    if (bytes[0] === 0x30) { let bin = ""; for (const b of bytes) bin += String.fromCharCode(b); sig = btoa(bin); }
    else sig = new TextDecoder().decode(bytes).replace(/-----[^-]+-----/g, "").replace(/\\s+/g, "");
    if (!/^[A-Za-z0-9+/]+=*$/.test(sig)) return ($("sign-msg").textContent = "O arquivo não parece uma assinatura .p7s.");
    ready(sig);
  };

  $("copy").onclick = () => navigator.clipboard.writeText($("sig").value);

  $("prove").onclick = async () => {
    const agentSig = state.agentSig || $("agent-sig").value.trim();
    if (!agentSig) return ($("prove-msg").textContent = "Falta a assinatura do agente.");
    $("prove").disabled = true; $("prove-msg").textContent = "Emitindo…";
    try {
      const r = await fetch("/v1/agents/" + encodeURIComponent(state.id) + "/prove", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ challenge_id: state.challengeId, agent_signature: agentSig, ecnpj_signature: state.signature }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.message || ("erro " + r.status));
      const c = j.credential || {};
      $("prove-msg").innerHTML = '<span class="ok"></span>';
      $("prove-msg").firstChild.textContent = "Credencial emitida: " + (c.credential_id || state.id) + ", válida até " + (c.expires_at ? new Date(c.expires_at).toLocaleDateString("pt-BR") : "-") + "." + ((j.warnings || []).length ? " Aviso: " + j.warnings.join("; ") : "");
    } catch (e) {
      $("prove").disabled = false;
      $("prove-msg").innerHTML = '<span class="bad"></span>';
      $("prove-msg").firstChild.textContent = "Não emitida: " + (e.message || e);
    }
  };
})();
</script>
</body>
</html>`;
}
