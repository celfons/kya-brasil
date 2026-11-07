"""
Reasons of end-user revocations in the CRLs ICP-Brasil publishes now, to estimate how much of the revocation rate
is key compromise.

    python3 -I fetch_reasons.py   # needs the cryptography package and network; writes data/reasons.json

The source list and URLs come from the public collector (/api/summary); each current end-user CRL is downloaded
from the AC's own distribution point and every entry's reasonCode (RFC 5280, 5.3.1) is counted. Entries without the
extension count as "sem motivo". The share of key compromise among entries that carry a reason is an estimate of the
share of compromise among all revocations only if the ACs that state reasons behave like those that do not.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone

from cryptography import x509

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "reasons.json")
COLLECTOR = "https://kya-icp-collector.marcelfons.workers.dev"


def get(url, timeout=180):
    req = urllib.request.Request(url, headers={"User-Agent": "kya-brasil-research/1.0"})
    for i in range(4):  # the collector sits behind a CDN that now and then resets a connection
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # collector and AC distribution points
                return r.read()
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            if i == 3:
                raise
            print(f"warning: {url}: {e}; retrying in {2 ** i} s", file=sys.stderr)
            time.sleep(2 ** i)


def main():
    summary = json.loads(get(COLLECTOR + "/api/summary"))
    now = datetime.now(timezone.utc)
    out = {"collector": COLLECTOR, "fetched_at": now.isoformat(timespec="seconds"), "sources": {}}
    total = Counter()
    for s in summary["sources"]:
        if s["kind"] != "usuario-final" or not s.get("next_update"):
            continue
        if datetime.fromisoformat(s["next_update"].replace("Z", "+00:00")) < now.replace(year=now.year - 1):
            continue  # retired generation, no longer published
        meta = json.loads(get(COLLECTOR + "/api/source/" + s["source"]))
        try:
            crl = x509.load_der_x509_crl(get(meta["url"]))
        except Exception as e:  # noqa: BLE001 - an unreachable AC is reported, not fatal
            out["sources"][s["source"]] = {"ac": s["ac"], "error": type(e).__name__}
            continue
        c = Counter()
        for e in crl:
            try:
                c[e.extensions.get_extension_for_class(x509.CRLReason).value.reason.name] += 1
            except x509.ExtensionNotFound:
                c["sem motivo"] += 1
        out["sources"][s["source"]] = {"ac": s["ac"], "entries": sum(c.values()), "reasons": dict(c.most_common())}
        total.update(c)
    with_reason = sum(v for k, v in total.items() if k != "sem motivo")
    out["total"] = {"entries": sum(total.values()), "with_reason": with_reason, "reasons": dict(total.most_common()),
                    "key_compromise_share_of_with_reason": round(total["key_compromise"] / with_reason, 4) if with_reason else None}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps(out["total"], ensure_ascii=False))
    for k, v in out["sources"].items():
        print(k, json.dumps(v, ensure_ascii=False)[:300])


if __name__ == "__main__":
    main()
