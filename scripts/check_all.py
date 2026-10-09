"""Automated checks of the running system (API, n8n, website). Needs START_DEMO to be running.

Usage:  .venv\\Scripts\\python.exe scripts\\check_all.py [--live]
  without --live : read-only checks (health, data, every website page renders, flags and labels on existing cases)
  with --live    : also sends E01 and E02 through the real n8n workflow with Llama and checks the routes (about 3 minutes;
                   uses up those two sample alerts until the next RESET_DEMO)
Prints PASS / FAIL per check and writes docs/demo/AUTOMATED_CHECK_RESULTS.md.
"""
import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
API, N8N = "http://127.0.0.1:8000", "http://127.0.0.1:5678"
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def get(path, **kw):
    return requests.get(API + path, timeout=30, **kw)


def api_checks():
    h = get("/health").json()
    check("API health and rules version is rules-v1.2", h.get("status") == "ok" and h.get("rules_version") == "rules-v1.2", str(h))
    samples = get("/sample-alerts").json()
    gold = [s["gold_case"] for s in samples if s["gold_case"]]
    check("Sample alerts: 20 gold + 2 extension + 100 background", len(samples) == 122 and sum(g.startswith("G") for g in gold) == 20 and {"E01", "E02"} <= set(gold), f"{len(samples)} alerts")
    for path in ("/cases", "/audit", "/analytics", "/decisions", "/register"):
        r = get(path)
        check(f"GET {path} answers 200", r.status_code == 200, str(r.status_code))
    for lt in ("deprioritised", "watchlist"):
        r = get("/lists", params={"list_type": lt})
        check(f"GET /lists ({lt}) answers 200", r.status_code == 200, str(r.status_code))
    r = requests.post(API + "/cases/CASE-99999/decision", json={"actor": "x", "decision": "dismiss", "reason": "x"}, timeout=30)
    check("Decision on an unknown case is refused (404)", r.status_code == 404, str(r.status_code))
    cases = get("/cases").json()
    if cases:
        cid = cases[0]["case_id"]
        r = requests.post(API + f"/cases/{cid}/decision", json={"actor": "check", "decision": "dismiss", "reason": "   "}, timeout=30)
        check("A decision with an empty reason is refused (422)", r.status_code == 422, str(r.status_code))
        r = requests.post(API + f"/cases/{cid}/decision", json={"actor": "check", "decision": "launch_missiles", "reason": "x"}, timeout=30)
        check("An unknown decision type is refused (422)", r.status_code == 422, str(r.status_code))
    r = requests.post(API + "/alerts", json={"alert_id": "AL-BAD", "ts": "not-a-time", "rule": "x", "host": "h"}, timeout=30)
    check("A malformed alert is rejected or handled without a server error", r.status_code < 500, str(r.status_code))


def n8n_checks():
    try:
        r = requests.get(N8N + "/healthz", timeout=10)
        check("n8n health answers 200", r.status_code == 200)
    except requests.RequestException as e:
        check("n8n health answers 200", False, str(e))
        return
    cases = get("/cases").json()
    if cases:
        alert = json.loads(get(f"/cases/{cases[0]['case_id']}").json()["alert_json"]) if "alert_json" in get(f"/cases/{cases[0]['case_id']}").json() else None
    samples = {s["alert_id"]: s for s in get("/sample-alerts").json()}
    used = [c["alert_id"] for c in cases if c["alert_id"] in samples]
    if used:
        r = requests.post(N8N + "/webhook/soc-triage", json={"alert": samples[used[0]], "model": "llama"}, timeout=30)
        body = r.json() if r.ok else {}
        check("n8n webhook accepts a repeated alert and flags it as a duplicate", r.ok and body.get("duplicate") is True, str(body))
    else:
        check("n8n webhook duplicate check (needs one earlier case)", False, "no earlier case in the database")


def live_checks():
    samples = {s["gold_case"]: s for s in get("/sample-alerts").json() if s["gold_case"]}
    used = {c["alert_id"] for c in get("/cases").json()}
    for cid, route, flag, key in (("E01", "queued", "slow_pattern", "slow"), ("E02", "escalated", "repeat_pattern", "repeat")):
        if samples[cid]["alert_id"] in used:
            check(f"Live run {cid}: alert still unused", False, "already sent; run RESET_DEMO first")
            continue
        t0 = time.time()
        r = requests.post(N8N + "/webhook/soc-triage", json={"alert": samples[cid], "model": "llama"}, timeout=60).json()
        case = r["case_id"]
        c = {}
        while time.time() - t0 < 400:
            c = get(f"/cases/{case}").json()
            if c["status"] in ("queued", "escalated", "deprioritised") and any(s["agent"] == "summary" and s["problems_json"] == "[]" for s in c["steps"]):
                break
            time.sleep(5)
        a = c.get("assessment") or {}
        check(f"Live run {cid} through n8n reaches status '{route}'", c.get("status") == route, f"status {c.get('status')} in {time.time() - t0:.0f}s")
        check(f"Live run {cid}: the {key} flag is set in the assessment", a.get(flag) is True, str(a.get("never_deprioritise")))
        check(f"Live run {cid}: summary step passed the code checks", any(s["agent"] == "summary" and s["problems_json"] == "[]" for s in c.get("steps", [])))
        ev = get("/audit", params={"case_id": case}).json()
        check(f"Live run {cid}: audit trail has the masking and the routing events", {"masked_and_scored"} <= {e["event"] for e in ev} and any(e["event"].startswith("routed_") for e in ev), f"{len(ev)} events")
        masked = json.dumps(c.get("masked", {}))
        check(f"Live run {cid}: the masked case holds no real user name", "r.khan" not in masked, "")


def ui_checks():
    from streamlit.testing.v1 import AppTest
    pages = ["Intake", "Analyst queue", "Escalations", "Deprioritised list", "Analytics", "Cost-benefit", "Case register", "Audit trail"]
    for p in pages:
        at = AppTest.from_file(str(ROOT / "ui" / "streamlit_app.py"), default_timeout=60)
        at.query_params["page"] = p
        at.run()
        text = " ".join([m.value for m in at.markdown] + [h.value for h in at.header] + [c.value for c in at.caption])
        check(f"Website page '{p}' renders without an error", not at.exception, "; ".join(str(e.value)[:80] for e in at.exception))
        if p == "Cost-benefit":
            check("Cost-benefit page shows the break-even message", any("Break-even" in i.value for i in at.info), "")
            at.number_input[1].set_value(1.0).run()
            net = [m for m in at.metric if m.label.startswith("Net")]
            check("Cost-benefit page: net turns negative at 1 minute saved", net and float(net[0].value) < 0, net[0].value if net else "")
        if p in ("Analyst queue", "Escalations") and at.selectbox:
            sb = at.selectbox[0]
            for opt in list(sb.options)[:8]:
                sb.select(opt).run()
                body = " ".join([m.value for m in at.markdown] + [c.value for c in at.caption] + [w.value for w in at.warning])
                if "Rule-based (deterministic)" in body:
                    check(f"Case screen {opt} shows the rule-based and model labels",
                          "Rule-based (deterministic)" in body and "Model output (probabilistic)" in body and not at.exception, "")
                    break


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    args = ap.parse_args()
    api_checks()
    n8n_checks()
    ui_checks()
    if args.live:
        live_checks()
    ok = sum(r[1] for r in results)
    lines = [f"# Automated check results ({datetime.now():%Y-%m-%d %H:%M})", "", f"{ok} of {len(results)} checks passed" + (" (with live runs)" if args.live else " (read-only)"), "", "| Result | Check | Detail |", "|---|---|---|"]
    lines += [f"| {'PASS' if o else '**FAIL**'} | {n} | {d.replace('|', '/')[:120]} |" for n, o, d in results]
    ((ROOT / "docs" / "demo") if (ROOT / "docs" / "demo").exists() else ROOT / "logs").mkdir(exist_ok=True)
    (((ROOT / "docs" / "demo") if (ROOT / "docs" / "demo").exists() else ROOT / "logs") / "AUTOMATED_CHECK_RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n{ok}/{len(results)} passed")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
