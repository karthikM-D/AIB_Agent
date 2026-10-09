"""Streamlit UI for the governed SOC triage PoC (synthetic data).

Talks to the system only over HTTP, as in the architecture: alerts go to the n8n webhook; reads and human decisions go to the
FastAPI services. Pages: Intake, Analyst queue (evidence-first case review), Escalations, Deprioritised list (spot-check gate),
Analytics, Audit trail. Run with scripts/start_ui.ps1 (http://localhost:8501).
"""
import json
import re
import os
import time

import pandas as pd
import requests
import streamlit as st

from safe import esc
from search import match_rows, resolve_case

API = os.getenv("SOC_API", "http://127.0.0.1:8000")
N8N = os.getenv("SOC_N8N", "http://127.0.0.1:5678/webhook/soc-triage")
MODELS = {"Llama 3.1 8B": "llama", "Qwen3 8B": "qwen", "Mistral 7B": "mistral"}
BAND_COLOUR = {"low": "green", "medium": "orange", "high": "red", "critical": "violet"}

st.set_page_config(page_title="Governed SOC Triage PoC", layout="wide")


def call(method, path, **kw):
    try:
        r = requests.request(method, API + path, timeout=30, **kw)
        if r.status_code >= 400:
            st.error(f"{path}: {r.status_code} {r.text[:300]}")
            return None
        return r.json()
    except requests.RequestException as e:
        st.error(f"API not reachable ({e.__class__.__name__}). Start it with scripts/start_api.ps1.")
        return None


FEATURE_LABELS = {
    "failed_logins_ge_10": "10 or more failed logins", "failed_logins_ge_5": "5 or more failed logins",
    "success_after_failures": "successful login after failures", "intel_malicious": "threat intelligence: malicious",
    "intel_suspicious": "threat intelligence: suspicious", "asset_critical": "asset criticality: critical",
    "asset_high": "asset criticality: high", "asset_medium": "asset criticality: medium",
    "asset_unknown_or_unavailable": "asset unknown or unavailable", "privileged_user": "privileged user",
    "inactive_user": "user on leave or terminated", "privilege_escalation": "privilege escalation",
    "data_exfiltration": "data exfiltration", "malware_detected": "malware detected", "production_environment": "production environment",
    "slow_failed_logins": "slow failed logins (24-hour look-back)", "repeat_pattern": "repeated pattern (60-day history)"}
SECTION_WORDS = [(r"\bRULE_ASSESSMENT\b", "the rule assessment"), (r"\bASSET_CONTEXT\b", "the asset context"),
                 (r"\bINTELLIGENCE\b", "the intelligence result"), (r"\bCORRELATION\b", "the correlation result"),
                 (r"\bINPUT\b", "the input"), (r"\bFINAL\b", "the final decision"), (r"\bRISK\b", "the risk result")]


def plain(text):
    """Model text names the sections of its input in capitals; show them in plain words to the analyst."""
    if not isinstance(text, str):
        return text
    for pat, word in SECTION_WORDS:
        text = re.sub(pat, word, text)
    return text.replace("the the ", "the ")


def unmask(text, mapping):
    """Show real names to the analyst; models only ever saw the pseudonyms."""
    if not isinstance(text, str):
        return text
    rev = {v: k for d in (mapping.get("users", {}), mapping.get("hosts", {})) for k, v in d.items()}
    for alias, real in sorted(rev.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(alias, real)
    return text


def valid_steps(case):
    """Latest passing output per agent, plus all passing risk outputs."""
    out, risks = {}, []
    for s in case["steps"]:
        if json.loads(s["problems_json"]):
            continue
        o = json.loads(s["output_json"])
        if s["agent"] == "risk":
            risks.append(o)
        else:
            out[s["agent"]] = o
    return out, risks


def badge(band):
    return f":{BAND_COLOUR.get(band, 'gray')}[**{(band or 'unknown').upper()}**]"


def render_case(case_id, actor, key):
    case = call("GET", f"/cases/{case_id}")
    if not case:
        return
    mapping, assessment, route = case.get("mapping", {}), case.get("assessment") or {}, case.get("route") or {}
    outs, risks = valid_steps(case)
    alert = case["alert"]
    st.subheader(f"{case_id} · {alert['alert_id']}  {badge(route.get('band') or case.get('band'))}  (rule score {case.get('score')})")
    st.caption(f"Status: **{case['status']}**")
    flags = []
    if assessment.get("reportable"):
        flags.append("⚠️ possibly reportable (six-hour windows) - the reporting decision is human")
    if assessment.get("injection"):
        flags.append("🛑 instruction-like text found in the log fields: treated as data, never followed")
    if assessment.get("slow_pattern"):
        flags.append("🕒 slow, spaced-out failed logins over the last 24 hours from one external address (long-window rule)")
    if assessment.get("repeat_pattern"):
        flags.append("🔁 the same alert has repeated on a privileged user or critical asset over recent weeks (history rule)")
    for g in assessment.get("gaps", []):
        flags.append(f"❓ {g.replace('_', ' ')}")
    for r in route.get("escalate_reasons", []):
        flags.append(f"⬆️ escalation reason: {r.replace('_', ' ')}")
    if flags:
        st.warning("\n\n".join(flags))

    left, right = st.columns(2)
    with left:
        st.markdown("**Alert**")
        st.write(f"**Rule:** {alert['rule']}  \n**Time:** {alert['ts']}  \n**Host:** {alert['host']}  \n**User:** {alert.get('user') or '-'}  \n"
                 f"**Source IP:** {alert.get('src_ip') or '-'}")
        st.write(alert["summary"])
        if alert.get("raw_log"):
            st.code(alert["raw_log"], language="text")
    with right:
        st.markdown("**Recommendation (proposal only - the bot never acts)**")
        st.caption("🎲 Model output (probabilistic): bounded by the rule score, run three times, checked by code")
        if risks:
            r0 = risks[0]
            st.write(f"**Band:** {badge(route.get('band'))}  \n**Proposed action:** `{r0['recommended_action']}`  \n**Model confidence:** {r0['confidence']:.2f}")
            st.write(plain(unmask(r0["rationale"], mapping)))
            st.caption(f"{len(risks)} valid risk runs; runs agree: **{route.get('runs_agree')}**; {route.get('floor_note', '')}")
        else:
            st.info("No valid recommendation: the model output failed the code checks, so the case was routed to a human.")

    st.markdown("**Why: rule-based score (transparent baseline, the model can only add caution)**")
    st.caption("📏 Rule-based (deterministic): the same input always gives the same score")
    feats = pd.DataFrame([{"factor": FEATURE_LABELS.get(f["feature"], f["feature"].replace("_", " ")), "points": f["points"],
                           "evidence": ", ".join(unmask(e, mapping) for e in f["evidence"])} for f in assessment.get("features", [])])
    if len(feats):
        st.dataframe(feats, hide_index=True, width="stretch")
    else:
        st.caption("No risk factors scored.")

    summ = outs.get("summary")
    st.markdown("**Summary and findings (evidence-linked)**")
    if summ:
        st.write(plain(unmask(summ["summary"], mapping)))
        for f in summ["key_findings"]:
            st.markdown(f"- {esc(plain(unmask(f['text'], mapping)))}  \n  <small>evidence: {esc(', '.join(unmask(e, mapping) for e in f['evidence']) or 'none cited')}</small>", unsafe_allow_html=True)
        if summ["unknowns"]:
            st.markdown("**Unknowns:** " + "; ".join(plain(unmask(u, mapping)) for u in summ["unknowns"]))
        st.caption(f"Summary confidence {summ['confidence']:.2f}")
    else:
        failed = [s for s in case["steps"] if s["agent"] == "summary" and json.loads(s["problems_json"])]
        if failed:
            why = "; ".join(json.loads(failed[-1]["problems_json"]))
            st.warning(f"No valid summary: the model's summary failed the code checks {len(failed)} time(s) ({why}), so it was not shown. "
                       "The rule score, the evidence and the recommendation above still stand, and a person decides.")
        else:
            st.caption("No summary available yet.")

    with st.expander("Agent trace (every step, attempt, seed, model, prompt version, check problems)"):
        rows = [{"agent": s["agent"], "attempt": s["attempt"], "model": s["model"], "prompt": s["prompt_version"],
                 "problems": "; ".join(json.loads(s["problems_json"])) or "-", "latency ms": s["latency_ms"]} for s in case["steps"]]
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    with st.expander("Audit trail"):
        a = call("GET", "/audit", params={"case_id": case_id}) or []
        st.dataframe(pd.DataFrame([{"time": x["ts"], "actor": x["actor"], "event": x["event"], "detail": x["detail_json"][:140]} for x in reversed(a)]),
                     hide_index=True, width="stretch")
    if case["decisions"]:
        st.markdown("**Human decisions so far**")
        st.dataframe(pd.DataFrame(case["decisions"])[["ts", "actor", "decision", "reason"]], hide_index=True, width="stretch")

    if case["status"] in ("queued", "escalated", "deprioritised", "watchlist"):
        st.markdown("**Your decision (a reason is required and is stored in the audit trail)**")
        with st.form(f"decide_{key}_{case_id}"):
            who = st.text_input("Your name / role", actor)
            reason = st.text_area("Reason")
            c = st.columns(5)
            choice = None
            for col, (label, code) in zip(c, [("Approve action", "approve_action"), ("Reject action", "reject_action"), ("Confirm threat, hand to Tier 2", "confirm_threat"),
                                              ("Dismiss", "dismiss"), ("Watchlist", "watchlist")]):
                if col.form_submit_button(label):
                    choice = code
            if choice:
                if not reason.strip():
                    st.error("Please write a reason.")
                else:
                    res = call("POST", f"/cases/{case_id}/decision", json={"actor": who, "decision": choice, "reason": reason})
                    if res:
                        st.success(f"Recorded: {choice}")
                        time.sleep(0.8)
                        st.rerun()


def case_picker(items, label, actor, key):
    if not items:
        st.info("Nothing waiting. Cases that a person has decided are listed below.")
        return
    df = pd.DataFrame(items)
    st.dataframe(df, hide_index=True, width="stretch")
    chosen = st.selectbox(label, [i["case_id"] for i in items], key=f"pick_{key}")
    render_case(chosen, actor, key)


# ----------------------------------------------------------------------------- pages
def page_intake():
    st.header("Intake: trigger a triage run")
    samples = call("GET", "/sample-alerts") or []
    if not samples:
        return
    gold = [s for s in samples if s["gold_case"]]
    labels = {f"{s['gold_case']} · {s['rule']} · {s['host']}": s for s in gold}
    c1, c2 = st.columns([3, 1])
    pick = c1.selectbox("Sample alert (synthetic)", list(labels))
    model = MODELS[c2.selectbox("Model", list(MODELS))]
    a = labels[pick]
    st.write(a["summary"])
    if st.button("Send to triage (n8n)", type="primary"):
        try:
            r = requests.post(N8N, json={"alert": a, "model": model}, timeout=30)
            body = r.json()
            if "case_id" in body:
                st.session_state["live_case"] = body["case_id"]
                st.success(f"Accepted as {body['case_id']} for {a['gold_case'] or a['alert_id']} ({a['alert_id']})" + (" (duplicate: already received)" if body.get("duplicate") else ""))
            else:
                st.error(f"n8n answered: {body}")
        except requests.RequestException as e:
            st.error(f"n8n not reachable ({e.__class__.__name__}). Start it with scripts/start_n8n.ps1 and wait about 20 seconds.")
    with st.expander("Batch loader: send background alerts (benign volume)"):
        bg = [s for s in samples if not s["gold_case"]]
        n = st.slider("How many", 1, 10, 3)
        if st.button("Send batch"):
            sent = 0
            known = {c["alert_id"] for c in (call("GET", "/cases") or [])}
            for s in [x for x in bg if x["alert_id"] not in known][:n]:
                try:
                    requests.post(N8N, json={"alert": s, "model": model}, timeout=30)
                    sent += 1
                except requests.RequestException:
                    break
            st.success(f"Sent {sent} alerts. They are processed one after another; watch the queue and the deprioritised list.")
    live_trace()


@st.fragment(run_every=3)
def live_trace():
    cid = st.session_state.get("live_case")
    if not cid:
        return
    case = call("GET", f"/cases/{cid}")
    if not case:
        return
    agents_done = [s for s in case["steps"] if not json.loads(s["problems_json"])]
    running = case["status"] in ("received", "processing") or (case["status"] in ("queued", "escalated", "deprioritised") and not any(s["agent"] == "summary" and not json.loads(s["problems_json"]) for s in case["steps"]))
    with st.status(f"Live trace for {cid}: {case['status']}", state="running" if running else "complete", expanded=True):
        for s in case["steps"]:
            p = json.loads(s["problems_json"])
            st.write(f"{'✅' if not p else '⚠️ retry/issue'} **{s['agent']}** attempt {s['attempt']} · {s['model']} · {s['latency_ms'] / 1000:.1f}s" + (f" · {'; '.join(p)[:120]}" if p else ""))
        st.caption(f"Route: {(case.get('route') or {}).get('route', 'pending')}")


def decided_table(routes, title):
    """Cases a person has already decided, so the page keeps a trace after a case leaves the queue."""
    rows = [d for d in (call("GET", "/decisions") or []) if d.get("route") in routes]
    st.subheader(title)
    if not rows:
        st.caption("Nothing has been decided yet on this page.")
        return
    st.dataframe(pd.DataFrame([{"time": d["ts"], "case": d["case_id"], "alert": d["alert_id"], "decision": d["decision"].replace("_", " "),
                                "by": d["actor"], "reason": d["reason"], "status now": d["status"]} for d in rows]), hide_index=True, width="stretch")


def page_queue():
    st.header("Analyst queue")
    st.caption("Ranked by risk band. Evidence first: alert, why, findings, unknowns, then your decision.")
    case_picker(call("GET", "/queue") or [], "Open a case", "analyst.demo", "queue")
    decided_table(("analyst_queue",), "Already decided by an analyst (kept as a trace)")
    ws = call("GET", "/cases", params={"status": "watchlist"}) or []
    if ws:
        with st.expander(f"Watchlist ({len(ws)})"):
            st.dataframe(pd.DataFrame(ws), hide_index=True, width="stretch")


def page_escalations():
    st.header("Escalations (senior analyst / SOC lead)")
    esc = call("GET", "/escalations") or []
    items = [{"case_id": e["case_id"], "alert_id": e["alert_id"], "band": e["band"], "score": e["score"],
              "reasons": ", ".join((json.loads(e["route_json"]) if e["route_json"] else {}).get("escalate_reasons", []))} for e in esc]
    case_picker(items, "Open an escalated case", "lead.demo", "esc")
    decided_table(("escalation",), "Already decided by a senior analyst or lead (kept as a trace)")


def page_deprioritised():
    st.header("Deprioritised alerts (not closed)")
    st.caption("Low risk by every rule. Nothing is closed silently: review a spot-check sample before bulk confirmation; untouched alerts are auto-closed after N days with a notice to the SOC lead.")
    items = call("GET", "/lists", params={"list_type": "deprioritised", "state": "saved"}) or []
    with st.expander(f"Deprioritised list ({len(items)} saved)", expanded=False):
        if items:
            st.dataframe(pd.DataFrame([{"case": i["case_id"], "alert": i["alert_id"], "band": i["band"], "score": i["score"],
                                        "why": " · ".join(json.loads(i["reasons_json"])), "saved": i["added_at"]} for i in items]), hide_index=True, width="stretch")
        else:
            st.info("The list is empty.")
    if not items:
        return
    st.subheader("Spot-check before bulk action")
    if st.button("Create spot-check sample (borderline + random)"):
        res = call("POST", "/lists/spotcheck")
        if res:
            st.session_state["batch"] = res
    batch = st.session_state.get("batch")
    if batch:
        done = 0
        for s in batch["sample"]:
            case = call("GET", f"/cases/{s['case_id']}")
            c1, c2, c3 = st.columns([4, 1, 1])
            c1.write(f"**{s['case_id']}** ({s['type']}) · {case['alert']['rule']} · {case['alert']['host']} · {case['alert']['summary']}")
            if c2.button("Agree", key=f"ag_{s['case_id']}"):
                call("POST", f"/lists/spotcheck/{batch['batch_id']}/verdict", json={"case_id": s["case_id"], "verdict": "agree", "actor": "analyst.demo"})
            if c3.button("Disagree (promote)", key=f"dis_{s['case_id']}"):
                call("POST", f"/lists/spotcheck/{batch['batch_id']}/verdict", json={"case_id": s["case_id"], "verdict": "disagree", "actor": "analyst.demo"})
                st.rerun()
        audit = call("GET", "/audit", params={"limit": 200}) or []
        reviewed = {a["case_id"] for a in audit if a["event"].startswith("spotcheck_") and a["event"] != "spotcheck_sample_created"}
        done = all(s["case_id"] in reviewed for s in batch["sample"])
        st.progress(sum(s["case_id"] in reviewed for s in batch["sample"]) / len(batch["sample"]), text="Sample reviewed")
        if st.button("Bulk confirm remaining list", disabled=not done, help="Enabled only after every sampled alert has been reviewed"):
            res = call("POST", "/lists/bulk-confirm", json={"batch_id": batch["batch_id"], "actor": "analyst.demo"})
            if res:
                st.success(f"Confirmed {len(res['confirmed'])} alerts; closed with an audit record.")
                st.session_state.pop("batch", None)
                st.rerun()


def page_analytics():
    st.header("Analytics")
    a = call("GET", "/analytics")
    if not a:
        return
    c1, c2, c3 = st.columns(3)
    c1.metric("Deprioritised alerts", a["deprioritised_total"])
    c2.metric("Promoted by analysts", a["promoted"])
    c3.metric("Promotion rate (how often the bot was wrong)", "-" if a["promotion_rate"] is None else f"{a['promotion_rate']:.0%}")
    st.caption("Analytics only: nothing here changes the bot's behaviour.")
    if a["cases_by_status"]:
        st.bar_chart(pd.Series(a["cases_by_status"], name="cases"))
    cases = call("GET", "/cases") or []
    if cases:
        st.dataframe(pd.DataFrame(cases), hide_index=True, width="stretch")


def page_costbenefit():
    st.header("Cost-benefit (illustrative: every input is an assumption)")
    st.caption("Nothing on this page is measured. Change the inputs to test the argument. A pilot would replace each assumption with a measured value.")
    c1, c2 = st.columns(2)
    alerts = c1.number_input("Alerts per day (assumption)", 10, 5000, 200, 10)
    saved = c1.number_input("Analyst minutes saved per alert by the prepared evidence (assumption)", 0.0, 60.0, 2.0, 0.5)
    fe_rate = c2.number_input("Share of alerts escalated that did not need it (our test set: 3 of 20 for the best model, a hard set)", 0.0, 1.0, 0.15, 0.05)
    fe_min = c2.number_input("Extra analyst minutes per unnecessary escalation (assumption)", 0.0, 60.0, 5.0, 0.5)
    run_h = st.number_input("Running and maintenance cost of the assistant, in analyst-hours per day (assumption: hardware, upkeep, evaluation)", 0.0, 24.0, 1.5, 0.5)
    gross = alerts * saved / 60
    over = alerts * fe_rate * fe_min / 60
    net = gross - over - run_h
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Analyst-hours saved per day", f"{gross:.1f}")
    k2.metric("Lost to unnecessary escalations", f"{over:.1f}")
    k3.metric("Running cost", f"{run_h:.1f}")
    k4.metric("Net analyst-hours per day", f"{net:.1f}")
    be = (over + run_h) * 60 / alerts if alerts else 0
    st.info(f"Break-even: the assistant pays for itself only if it saves more than **{be:.1f} minutes per alert**. Below that, the effort it adds is larger than the effort it removes.")
    st.caption("Measured for reference (evaluation, laptop with a 6 GB GPU): median 55 to 88 seconds of machine time per case, three runs of the risk step per case.")


def page_register():
    st.header("Case register (every alert received)")
    st.caption("One row per alert. Search is not case-sensitive: type 1 for CASE-00001 and G01, g01, AL-G01, a host, a rule, a status, a model or a word from the summary. "
               "The time matches the start time of the run in n8n's Executions list.")
    rows = call("GET", "/register") or []
    if not rows:
        st.info("No alert has been received yet.")
        return
    c1, c2, c3, c4 = st.columns([3, 1, 1, 1])
    q = c1.text_input("Search")
    status = c2.selectbox("Status", ["all"] + sorted({r["status"] for r in rows}))
    route = c3.selectbox("Route", ["all"] + sorted({r["route"] for r in rows if r.get("route")}))
    model = c4.selectbox("Model", ["all"] + sorted({r["model"] for r in rows if r.get("model")}))
    shown = [r for r in match_rows(q, rows) if status in ("all", r["status"]) and route in ("all", r.get("route")) and model in ("all", r.get("model"))]
    st.write(f"**{len(shown)}** of {len(rows)} alerts")
    st.dataframe(pd.DataFrame([{"case": r["case_id"], "alert": r["alert_id"], "test case": r["test_code"], "rule": r["rule"], "host": r["host"], "model": r["model"],
                                "band": r["band"], "score": r["score"], "route": r["route"], "status": r["status"], "received": r["created_at"],
                                "decision": (r["last_decision"] or "").replace("_", " "), "decided by": r["decided_by"], "decided at": r["decided_at"]} for r in shown]),
                 hide_index=True, width="stretch")
    if shown:
        st.subheader("Open a case")
        chosen = st.selectbox("Case", [r["case_id"] for r in shown], key="pick_register")
        render_case(chosen, "analyst.demo", "register")


def page_audit():
    st.header("Audit trail (append-only)")
    raw = st.text_input("Filter by case (blank = latest events). Not case-sensitive: 1, case-1, CASE-00001, G01 or AL-G01 all work")
    register = call("GET", "/register") or []
    cid = resolve_case(raw, register) if raw.strip() else None
    if raw.strip() and not cid:
        st.warning(f"No case matches '{raw}'. Showing the latest events instead.")
    elif cid:
        hit = next(r for r in register if r["case_id"] == cid)
        st.info(f"Showing {cid}: alert {hit['alert_id']} ({hit['test_code']}), {hit['rule']} on {hit['host']}, status {hit['status']}.")
    rows = call("GET", "/audit", params={"case_id": cid} if cid else {"limit": 100}) or []
    st.dataframe(pd.DataFrame([{"id": r["id"], "time": r["ts"], "case": r["case_id"], "actor": r["actor"], "event": r["event"], "detail": r["detail_json"][:200]} for r in rows]),
                 hide_index=True, width="stretch")


PAGES = {"Intake": page_intake, "Analyst queue": page_queue, "Escalations": page_escalations, "Deprioritised list": page_deprioritised,
         "Analytics": page_analytics, "Cost-benefit": page_costbenefit, "Case register": page_register, "Audit trail": page_audit}
st.sidebar.title("Governed SOC triage")
st.sidebar.caption("Synthetic data · recommendations only · human decisions · full audit")
_wanted = st.query_params.get("page", "Intake")
page = st.sidebar.radio("Page", list(PAGES), index=list(PAGES).index(_wanted) if _wanted in PAGES else 0)
health = call("GET", "/health")
if health:
    st.sidebar.success(f"API ok · {health['rules_version']}")
PAGES[page]()
