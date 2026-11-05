#!/usr/bin/env python3
"""Aggregates the anonymous reports of the case study (H3) written by `kya-study report`.

Usage:  python3 -I analyze.py <reports-folder> [--out <folder>]

Reads every kya-study-report-*.json in the folder (non-recursive) and writes, to --out (default: <reports>/analysis):
  summary.md        completion per task, time to first success (median, p25, p75), attempts, error categories,
                    policy grades, revocation time, verification latency, lines/files changed, library changes
  participants.csv  one row per participant
  tasks.csv         one row per participant and task
  answers.md        the open answers grouped by question, for qualitative coding

Standard library only. Reports are data: nothing in them is executed.
"""
import argparse
import csv
import json
import statistics
import sys
from pathlib import Path

TASKS = ["t1", "t2", "t3", "t4"]
TASK_NAMES = {"t1": "T1 emitir", "t2": "T2 política", "t3": "T3 verificar", "t4": "T4 revogação"}
CATEGORIES = ["signature", "icp_chain", "mandate", "revocation", "freshness", "replay", "runtime", "timeout", "contract", "other"]
GRADES = ["correct", "permissive", "restrictive", "invalid"]
QUESTIONS = {
    "q1": "(1) Em qual tarefa você mais travou, e por quê?",
    "q2": "(2) O que no mandato (tetos, contrapartes, validade) foi confuso de expressar?",
    "q3": "(3) Que parte da documentação faltou ou atrapalhou?",
    "q4": "(4) Você usaria isto num sistema real? O que impediria?",
    "q5": "(5) Algo mais?",
}


def quantile(values, q):
    """Linear interpolation between closest ranks (the same rule as the kit's report)."""
    v = sorted(x for x in values if x is not None)
    if not v:
        return None
    pos = (len(v) - 1) * q
    lo, hi = int(pos), min(int(pos) + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (pos - lo)


def fmt(x, digits=1):
    if x is None:
        return "–"
    if isinstance(x, float):
        return f"{x:.{digits}f}"
    return str(x)


def _num(v):
    return v is None or (isinstance(v, (int, float)) and not isinstance(v, bool))


def problems(r):
    """Why a parsed JSON is not a usable report (structure and types), or [] when it is."""
    if not isinstance(r, dict):
        return ["not a JSON object"]
    if r.get("schema") != "kya-study-report/1":
        return ["not a kya-study-report/1"]
    out = []
    if not isinstance(r.get("participant_id"), str) or not r["participant_id"]:
        out.append("participant_id missing")
    tasks = r.get("tasks")
    if not isinstance(tasks, dict):
        out.append("tasks is not an object")
    else:
        for t in TASKS:
            m = tasks.get(t)
            if m is None:
                continue
            if not isinstance(m, dict):
                out.append(f"tasks.{t} is not an object")
                continue
            for k in ("attempts", "passes", "pass_rate", "first_success_s", "attempts_to_first_success", "not_implemented_attempts"):
                if not _num(m.get(k)):
                    out.append(f"tasks.{t}.{k} is not a number")
            if "errors" in m and not (isinstance(m["errors"], dict) and all(_num(v) for v in m["errors"].values())):
                out.append(f"tasks.{t}.errors is not an object of numbers")
            if "sub_cases" in m and not (isinstance(m["sub_cases"], dict) and all(isinstance(v, dict) and _num(v.get("attempts")) and _num(v.get("passes")) for v in m["sub_cases"].values())):
                out.append(f"tasks.{t}.sub_cases is malformed")
    for key in ("policy", "revocation", "verification_latency_ms", "changes", "library_change", "library_integrity", "answers", "library_versions", "ai_assistant"):
        if key in r and r[key] is not None and not isinstance(r[key], dict):
            out.append(f"{key} is not an object")
    if isinstance(r.get("policy"), dict):
        for k in ("first_deviations", "last_deviations"):
            v = r["policy"].get(k, [])
            if not (isinstance(v, list) and all(isinstance(d, dict) for d in v)):
                out.append(f"policy.{k} is not a list of objects")
    for key, fields in (("revocation", ("published_after_s", "time_to_effect_s")), ("verification_latency_ms", ("n", "median", "p25", "p75")), ("changes", ("files_changed", "lines_added", "lines_removed"))):
        if isinstance(r.get(key), dict):
            out += [f"{key}.{f} is not a number" for f in fields if not _num(r[key].get(f))]
    if isinstance(r.get("answers"), dict) and not all(isinstance(v, str) for v in r["answers"].values()):
        out.append("answers must be strings")
    if isinstance(r.get("library_change"), dict):
        lc = r["library_change"]
        if lc.get("changed") not in (True, False, None) or not isinstance(lc.get("where", ""), str) or not isinstance(lc.get("requested", ""), str):
            out.append("library_change is malformed")
    if isinstance(r.get("ai_assistant"), dict):
        ai = r["ai_assistant"]
        if ai.get("used") not in (True, False, None) or not (isinstance(ai.get("tasks", []), list) and all(isinstance(x, str) for x in ai.get("tasks", []))):
            out.append("ai_assistant is malformed")
    if not _num(r.get("total_s")):
        out.append("total_s is not a number")
    return out


def load(folder):
    reports, skipped = [], []
    for f in sorted(folder.glob("kya-study-report-*.json")):
        try:
            r = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            skipped.append(f"{f.name}: {e}")
            continue
        why = problems(r)
        if why:
            skipped.append(f"{f.name}: {'; '.join(why[:3])}")
            continue
        reports.append(r)
    # The same participant sent twice: keep the most complete one (finished, then most attempts).
    by_id = {}
    for r in reports:
        pid = r.get("participant_id")
        attempts = sum((r.get("tasks", {}).get(t) or {}).get("attempts", 0) for t in TASKS)
        key = (bool(r.get("finished")), attempts, r.get("total_s") or 0)
        if pid in by_id:
            skipped.append(f"a report of participant {pid}: duplicate id, kept the most complete one")
        if pid not in by_id or key > by_id[pid][0]:
            by_id[pid] = (key, r)
    return [r for _, r in by_id.values()], skipped


def task(r, t):
    return (r.get("tasks") or {}).get(t) or {}


def integrity_line(reports):
    """The measured counterpart of the self-report: library files changed after the first check (kit >= 0.1.0)."""
    li = [r.get("library_integrity") or {} for r in reports]
    checked = sum(1 for x in li if x.get("checked"))
    return (f"Measured (library files changed after the participant's first check): modified {sum(1 for x in li if x.get('modified'))}/{checked}, "
            f"other versions installed {sum(1 for x in li if x.get('versions_changed'))}/{checked}; not measured: {len(reports) - checked}.")


def ai_used(r):
    return ((r.get("ai_assistant") or {}).get("used"))


def ai_section(reports):
    """Completion, time to first success and policy grade, split by AI assistant used / not used / no answer."""
    groups = [("used AI", [r for r in reports if ai_used(r) is True]), ("no AI", [r for r in reports if ai_used(r) is False]), ("no answer", [r for r in reports if ai_used(r) is None])]
    L = ["## By AI assistant use", "", "Participants may use web search and AI assistants (ChatGPT, Copilot, Claude...); `finish` asks whether they did and in which tasks.", "",
         "| Group | N | " + " | ".join(f"{TASK_NAMES[t]}: completed, median s" for t in TASKS) + " | Policy (first): correct / permissive / restrictive / invalid |",
         "| --- | --- |" + " --- |" * (len(TASKS) + 1)]
    for name, rs in groups:
        if not rs:
            L.append(f"| {name} | 0 |" + " – |" * (len(TASKS) + 1))
            continue
        cells = []
        for t in TASKS:
            times = [task(r, t).get("first_success_s") for r in rs if task(r, t).get("first_success_s") is not None]
            cells.append(f"{len(times)}/{len(rs)}, {fmt(quantile(times, .5))}")
        grades = [sum(1 for r in rs if (r.get("policy") or {}).get("first_grade") == g) for g in GRADES]
        L.append(f"| {name} | {len(rs)} | " + " | ".join(cells) + " | " + " / ".join(str(g) for g in grades) + " |")
    per_task = {t: sum(1 for r in reports if ai_used(r) and t in ((r.get("ai_assistant") or {}).get("tasks") or [])) for t in TASKS}
    L += ["", "Tasks in which AI was used: " + ", ".join(f"{TASK_NAMES[t]} {c}" for t, c in per_task.items()) + ".", ""]
    return L


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("reports", type=Path)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    out = a.out or a.reports / "analysis"
    if not a.reports.is_dir():
        print(f"not a folder: {a.reports}", file=sys.stderr)
        return 2
    reports, skipped = load(a.reports)
    for s in skipped:
        print(f"skipped {s}", file=sys.stderr)
    if not reports:
        print(f"no valid kya-study-report-*.json in {a.reports}" + (f" ({len(skipped)} skipped, reasons above)" if skipped else ""), file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    n = len(reports)

    # ---- per participant / per task CSVs
    with open(out / "tasks.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["participant_id", "task", "attempts", "passes", "pass_rate", "first_success_s", "attempts_to_first_success", "not_implemented_attempts", *[f"err_{c}" for c in CATEGORIES]])
        for r in reports:
            for t in TASKS:
                m = task(r, t)
                errs = m.get("errors") or {}
                w.writerow([r["participant_id"], t, m.get("attempts", 0), m.get("passes", 0), m.get("pass_rate"), m.get("first_success_s"), m.get("attempts_to_first_success"), m.get("not_implemented_attempts", 0), *[errs.get(c, 0) for c in CATEGORIES]])

    with open(out / "participants.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["participant_id", "kit_version", "core", "agent_tools", "node", "os", "month", "finished", "total_s", "ai_used", "ai_tasks", "policy_first", "policy_last", "policy_first_deviations", "revocation_published_after_s", "revocation_time_to_effect_s", "latency_median_ms", "files_changed", "lines_added", "lines_removed", "diff_method", "library_changed", "library_where", "library_requested"])
        for r in reports:
            p, rev, lat, ch, lib = r.get("policy") or {}, r.get("revocation") or {}, r.get("verification_latency_ms") or {}, r.get("changes") or {}, r.get("library_change") or {}
            libs = r.get("library_versions") or {}
            w.writerow([r["participant_id"], r.get("kit_version"), libs.get("@kya-brasil/core"), libs.get("@kya-brasil/agent-tools"), r.get("node_version"), r.get("os_family"), r.get("study_month"), r.get("finished"), r.get("total_s"), ai_used(r), " ".join((r.get("ai_assistant") or {}).get("tasks") or []),
                        p.get("first_grade"), p.get("last_grade"), "; ".join(f"{d.get('field')}:{d.get('direction')}" for d in p.get("first_deviations") or []),
                        rev.get("published_after_s"), rev.get("time_to_effect_s"), lat.get("median"), ch.get("files_changed"), ch.get("lines_added"), ch.get("lines_removed"), ch.get("method"),
                        lib.get("changed"), lib.get("where"), lib.get("requested")])

    # ---- summary.md
    L = [f"# Case study (H3): aggregate of {n} report(s)", ""]
    if skipped:
        L += ["Skipped files: " + "; ".join(skipped), ""]
    finished = sum(1 for r in reports if r.get("finished"))
    L += [f"Finished the questionnaire: {finished}/{n}. Kit versions: {', '.join(sorted({str(r.get('kit_version')) for r in reports}))}.", ""]

    L += ["## Completion and time to first success", "",
          "| Task | Completed | Rate | Time to first success, s: median (p25–p75) | Attempts to first success: median | Attempts: median |",
          "| --- | --- | --- | --- | --- | --- |"]
    for t in TASKS:
        done = [r for r in reports if task(r, t).get("first_success_s") is not None]
        times = [task(r, t)["first_success_s"] for r in done]
        tries = [task(r, t).get("attempts_to_first_success") for r in done]
        all_tries = [task(r, t).get("attempts", 0) for r in reports]
        L.append(f"| {TASK_NAMES[t]} | {len(done)}/{n} | {fmt(len(done) / n * 100, 0)}% | {fmt(quantile(times, .5))} ({fmt(quantile(times, .25))}–{fmt(quantile(times, .75))}) | {fmt(quantile(tries, .5))} | {fmt(quantile(all_tries, .5))} |")
    all_four = sum(1 for r in reports if all(task(r, t).get("first_success_s") is not None for t in TASKS))
    L += ["", f"All four tasks completed: {all_four}/{n}.", ""]

    for t in ("t3", "t4"):
        subs = {}
        for r in reports:
            for sid, s in (task(r, t).get("sub_cases") or {}).items():
                agg = subs.setdefault(sid, [0, 0, 0])
                agg[0] += s.get("attempts", 0)
                agg[1] += s.get("passes", 0)
                agg[2] += 1 if s.get("passes", 0) else 0
        if subs:
            L += [f"### {TASK_NAMES[t]}: sub-cases", "", "| Sub-case | Participants who passed it | Attempts | Pass rate over attempts |", "| --- | --- | --- | --- |"]
            for sid, (att, ok, people) in subs.items():
                L.append(f"| {sid} | {people}/{n} | {att} | {fmt(ok / att * 100 if att else None, 0)}% |")
            L.append("")

    L += ["## Error categories (failed attempts)", "", "| Category | " + " | ".join(TASK_NAMES[t] for t in TASKS) + " | Total | Participants |", "| --- |" + " --- |" * (len(TASKS) + 2)]
    for c in CATEGORIES:
        per = [sum((task(r, t).get("errors") or {}).get(c, 0) for r in reports) for t in TASKS]
        people = sum(1 for r in reports if any((task(r, t).get("errors") or {}).get(c, 0) for t in TASKS))
        L.append(f"| {c} | " + " | ".join(str(x) for x in per) + f" | {sum(per)} | {people} |")
    L.append("")

    L += ["## Policy quality (T2)", "", "Grade of the first verifiable mandate each participant issued, and of the last one.", "",
          "| Grade | First | Last |", "| --- | --- | --- |"]
    for g in GRADES + [None]:
        first = sum(1 for r in reports if (r.get("policy") or {}).get("first_grade") == g)
        last = sum(1 for r in reports if (r.get("policy") or {}).get("last_grade") == g)
        L.append(f"| {g or 'not attempted'} | {first} | {last} |")
    fields = {}
    for r in reports:
        for d in (r.get("policy") or {}).get("first_deviations") or []:
            k = (d.get("field"), d.get("direction"))
            fields[k] = fields.get(k, 0) + 1
    if fields:
        L += ["", "Deviating fields in the first mandate:", "", "| Field | Direction | Participants |", "| --- | --- | --- |"]
        for (f, d), c in sorted(fields.items(), key=lambda x: -x[1]):
            L.append(f"| {f} | {d} | {c} |")
    L.append("")

    eff = [(r.get("revocation") or {}).get("time_to_effect_s") for r in reports]
    eff = [x for x in eff if x is not None]
    pub = [(r.get("revocation") or {}).get("published_after_s") for r in reports]
    pub = [x for x in pub if x is not None]
    L += ["## Time until the revocation takes effect (T4)", "",
          f"Revoked CRL published (pre-revocation purchase accepted): {len(pub)}/{n}. Revocation took effect: {len(eff)}/{n}.", "",
          f"Seconds from publication to the first passing run: median {fmt(quantile(eff, .5))}, p25 {fmt(quantile(eff, .25))}, p75 {fmt(quantile(eff, .75))}, max {fmt(max(eff) if eff else None)}.", ""]

    lat = [(r.get("verification_latency_ms") or {}).get("median") for r in reports]
    lat = [x for x in lat if x is not None]
    L += ["## Verification latency", "", f"Median of the participants' medians: {fmt(quantile(lat, .5), 2)} ms (p25 {fmt(quantile(lat, .25), 2)}, p75 {fmt(quantile(lat, .75), 2)}; {len(lat)} participants).", ""]

    ch = [r.get("changes") or {} for r in reports]
    L += ["## Code written (lines and files changed against the starter project)", "",
          "| Measure | Median | p25 | p75 |", "| --- | --- | --- | --- |"]
    for k in ("files_changed", "lines_added", "lines_removed"):
        v = [c.get(k) for c in ch if c.get(k) is not None]
        L.append(f"| {k} | {fmt(quantile(v, .5))} | {fmt(quantile(v, .25))} | {fmt(quantile(v, .75))} |")
    methods = sorted({str(c.get("method")) for c in ch})
    L += ["", f"Counting method: {', '.join(methods)} (snapshot = line-hash multiset when git was missing).", ""]

    L += ai_section(reports)

    changed = [r for r in reports if (r.get("library_change") or {}).get("changed") is True]
    L += ["## Changes to the library (pre-registered: \"alterações pedidas na biblioteca\")", "",
          f"Changed or worked around the library: {len(changed)}/{n} (no answer: {sum(1 for r in reports if (r.get('library_change') or {}).get('changed') is None)}).",
          integrity_line(reports), ""]
    for r in changed:
        L.append(f"- {r['participant_id']}: {(r.get('library_change') or {}).get('where') or '(no detail)'}")
    req = [r for r in reports if ((r.get("library_change") or {}).get("requested") or "").strip()]
    if req:
        L += ["", "Requested changes:", ""] + [f"- {r['participant_id']}: {r['library_change']['requested']}" for r in req]
    L.append("")
    (out / "summary.md").write_text("\n".join(L), encoding="utf-8")

    # ---- answers.md (qualitative coding)
    A = ["# Open answers, grouped by question", "", "One line per participant (anonymous id). Empty answers are omitted.", ""]
    for q, text in QUESTIONS.items():
        A += [f"## {text}", ""]
        for r in reports:
            ans = ((r.get("answers") or {}).get(q) or "").strip()
            if ans:
                A.append(f"- **{r['participant_id']}**: {ans}")
        A.append("")
    A += ["## Biblioteca: onde alterou / contornou", ""] + [f"- **{r['participant_id']}**: {r['library_change']['where']}" for r in reports if ((r.get("library_change") or {}).get("where") or "").strip()]
    A += ["", "## Biblioteca: alteração pedida", ""] + [f"- **{r['participant_id']}**: {r['library_change']['requested']}" for r in req] + [""]
    (out / "answers.md").write_text("\n".join(A), encoding="utf-8")

    print(f"{n} report(s) -> {out}/summary.md, participants.csv, tasks.csv, answers.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
