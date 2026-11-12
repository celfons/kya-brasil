"""
Reasons of end-user revocations in the CRLs ICP-Brasil publishes now, to estimate how much of the revocation rate
is key compromise.

    python3 -I fetch_reasons.py   # after fetch_measured.py; needs the cryptography package and network; writes data/reasons.json

It reads the same files as the weekday-hour grid: the ones data/measured.json names, from the collector's archive, so
that the two counts describe the same bytes and a cut can be read again. Lists of retired generations stay out. Every
entry's reasonCode (RFC 5280, 5.3.1) is counted, and entries without the extension count as "sem motivo". No list is
skipped (crl_entries.py). The share of key compromise among entries that carry a reason is an estimate of the share
of compromise among all revocations only if the ACs that state reasons behave like those that do not.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # python3 -I leaves the script directory out of sys.path
import crl_entries  # noqa: E402

MEASURED = os.path.join(HERE, "data", "measured.json")
OUT = os.path.join(HERE, "data", "reasons.json")
COLLECTOR = "https://kya-icp-collector.marcelfons.workers.dev"


def get(url, timeout=180):
    req = urllib.request.Request(url, headers={"User-Agent": "kya-brasil-research/1.0"})
    for i in range(4):  # the collector sits behind a CDN that now and then resets a connection
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # fixed host
                return r.read()
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            if i == 3:
                raise
            print(f"warning: {url}: {e}; retrying in {2 ** i} s", file=sys.stderr)
            time.sleep(2 ** i)


def iso(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def main():
    with open(MEASURED, encoding="utf-8") as f:
        measured = json.load(f)
    cut = iso(measured["generated_at"])
    out = {"collector": COLLECTOR, "fetched_at": cut.isoformat(timespec="seconds"), "files": "data/measured.json", "sources": {}}
    total = Counter()
    for source, record in measured["weekday_hour_sources"].items():
        cadence = measured["cadence_usuario_final"][source]
        if not cadence.get("next_update") or iso(cadence["next_update"]) < cut - timedelta(days=365):
            continue  # retired generation, no longer published
        entries, _ = crl_entries.decode(get(COLLECTOR + "/files/" + urllib.parse.quote(record["file"])), f"{source}: {record['file']}")
        c = Counter(reason or "sem motivo" for _, reason in entries)
        out["sources"][source] = {"ac": cadence["ac"], "entries": sum(c.values()), "reasons": dict(c.most_common())}
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
