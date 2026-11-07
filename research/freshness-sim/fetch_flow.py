"""
Revocation rate from the FLOW of new entries the collector sees, and the per-AC table, from the public ICP-Brasil
CRL collector. Standard library only:

    python3 -I fetch_flow.py   # writes data/flow.json

Why the flow: the rate from the STOCK of entries a CRL holds is biased, because ACs drop expired certificates from
the list (older months are undercounted, and more so for ACs with short-lived certificates). The collector sees
every new entry appear (measured_delays per source: revocations whose first CRL was collected), so new entries per
hour of collection, over the certificates in force, is a rate without that bias. The denominator is still the
national count of active certificates (ITI), so the rate remains a lower bound for coverage.

Per source (end-user CRLs): entries in the current list, share registered on weekdays 8:00-17:59 Brasília, CRL
validity (nextUpdate - thisUpdate), new entries seen during collection, hours of collection for that source,
delay median and p95. Totals: new entries per hour summed over sources (each over its own window), divided by the
active certificates, per hour and per year.
"""
import json
import os
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone

BASE = "https://kya-icp-collector.marcelfons.workers.dev"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "flow.json")
UA = {"user-agent": "curl/8"}
SOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def get(path):
    with urllib.request.urlopen(urllib.request.Request(BASE + path, headers=UA), timeout=120) as r:
        return json.load(r)


def iso(s):
    return datetime.strptime(s.replace(".000Z", "Z"), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def main():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    status = get("/api/status")
    summary = get("/api/summary")
    iti = get("/api/iti")
    active = iti[-1]["active"] if iti else None
    # The collection started when the first in-force list was fetched (a retired list keeps the thisUpdate of its
    # final CRL, years before the collector existed). A source's window starts at its own first CRL, or at the
    # collection start if that is later.
    all_sources = [{"id": s["source"], "kind": s["kind"], "first_this_update": s.get("first_this_update"), "versions": s.get("versions")}
                   for s in summary["sources"] if SOURCE_ID.match(s["source"])]
    # In-force end-user lists are reissued every 1 to 6 h, so the first one stored dates the first collection.
    by_id = {s["source"]: s for s in summary["sources"]}
    start = min(iso(s["first_this_update"]) for s in all_sources
                if s["first_this_update"] and (s.get("versions") or 0) >= 2 and s["kind"] == "usuario-final"
                and by_id[s["id"]].get("next_update") and iso(by_id[s["id"]]["next_update"]) > now - __import__("datetime").timedelta(days=2))
    per = {}
    for s in summary["sources"]:
        if s["kind"] != "usuario-final" or not SOURCE_ID.match(s["source"]):
            continue
        d = get("/api/source/" + urllib.parse.quote(s["source"], safe=""))
        wh = d.get("weekday_hour") or []
        total = sum(wh)
        # index = weekday * 24 + hour, weekday 0 = Sunday, hour in Brasília (kya-icp src/index.ts)
        biz = sum(n for i, n in enumerate(wh) if 1 <= i // 24 <= 5 and 8 <= i % 24 < 18)
        first = max(iso(d["first_this_update"]), start) if d.get("first_this_update") else None
        window_h = (now - first).total_seconds() / 3600 if first else None
        delays = [float(x) for x in d.get("delays_h") or [] if x is not None and x >= 0]
        # entries that appeared with a revocation date older than the collection window are backlog, not flow
        flow = [x for x in delays if window_h is None or x <= window_h]
        validity_h = None
        if d.get("next_update") and d.get("last_this_update"):
            validity_h = round((iso(d["next_update"]) - iso(d["last_this_update"])).total_seconds() / 3600, 2)
        # "in force" with one week of slack: a 1 h list fetched at :23 is briefly past its nextUpdate at any instant
        in_force = bool(d.get("last_this_update")) and (now - iso(d["last_this_update"])).days < 7
        per[s["source"]] = {
            "ac": d["ac"], "entries": d["entries"], "in_force": in_force, "validity_h": validity_h,
            "business_share": round(biz / total, 4) if total else None, "weekday_hour_total": total,
            "first_this_update": d.get("first_this_update"), "versions": d.get("versions"), "window_h": round(window_h, 2) if window_h else None,
            "new_entries": len(flow), "delay_median_h": d.get("delay_median_h"), "delay_p95_h": d.get("delay_p95_h"),
        }
    rate_per_hour = sum(p["new_entries"] / p["window_h"] for p in per.values() if p["window_h"] and p["window_h"] > 0)
    out = {
        "collector": BASE, "fetched_at": now.isoformat().replace("+00:00", "Z"), "sources_total": status["sources"],
        "sources": all_sources,
        "end_user_sources": len(per), "collection_start": start.isoformat().replace("+00:00", "Z"),
        "window_h_max": round(max(p["window_h"] for p in per.values() if p["window_h"]), 1),
        "active": active, "new_entries_total": sum(p["new_entries"] for p in per.values()),
        "revocations_per_hour": round(rate_per_hour, 4),
        "lambda_flow_per_hour": rate_per_hour / active if active else None,
        "lambda_flow_per_year": rate_per_hour * 24 * 365 / active if active else None,
        "note": "lower bound: only the covered ACs count in the numerator; the denominator is the national active count",
        "per_source": per,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in out.items() if k != "per_source"}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
