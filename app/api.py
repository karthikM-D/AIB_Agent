"""FastAPI services for the PoC: intake, deterministic orchestration helpers, mock tools, human decisions, lists, audit.

n8n calls: POST /alerts, POST /cases/{id}/prepare, POST /cases/{id}/checks, POST /cases/{id}/route.
Streamlit calls the read endpoints and the decision / list endpoints. The mock tool endpoints can simulate failure
(mode=timeout) so exception handling can be demonstrated and tested.
Run: .venv/Scripts/uvicorn app.api:app --port 8000   (or scripts/start_api.ps1)
"""
import json
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Body, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

import requests

from app import agents, checks, db, llm, masking, prompts, rules

ALLOWED_DECISIONS = {"confirm_threat", "approve_action", "reject_action", "dismiss", "watchlist"}


class AlertIn(BaseModel):
    alert_id: str = Field(min_length=1, max_length=64)
    ts: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")
    rule: str = Field(max_length=200)
    host: str = Field(min_length=1, max_length=100)
    user: Optional[str] = Field(default=None, max_length=100)
    src_ip: Optional[str] = Field(default=None, max_length=64)
    summary: str = Field(max_length=2000)
    raw_log: str = Field(default="", max_length=5000)
    sim: dict = Field(default_factory=dict)
    gold_case: Optional[str] = None


class DecisionIn(BaseModel):
    actor: str
    decision: str
    reason: str


class StepIn(BaseModel):
    agent: str
    attempt: int = 1
    model: str = ""
    prompt_version: str = ""
    output: dict = Field(default_factory=dict)
    problems: list = Field(default_factory=list)
    latency_ms: int = 0


def create_app(db_path=None, data_dir=None):
    app = FastAPI(title="Governed SOC triage PoC (synthetic data)")
    store = rules.Store(data_dir)
    conn = db.connect(db_path)

    def case_or_404(case_id):
        c = db.get_case(conn, case_id)
        if not c:
            raise HTTPException(404, "case not found")
        return c

    def parse(c):
        for k in ("alert_json", "masked_json", "mapping_json", "assessment_json", "route_json"):
            if c.get(k):
                c[k[:-5]] = json.loads(c[k])
            c.pop(k, None)
        return c

    @app.get("/sample-alerts")
    def sample_alerts():
        """Synthetic alerts for the UI intake page (gold cases and background alerts)."""
        return [{k: a.get(k) for k in ("alert_id", "ts", "rule", "host", "user", "src_ip", "summary", "raw_log", "sim", "gold_case")}
                for a in rules.load_json("alerts.json")]

    @app.get("/health")
    def health():
        return {"status": "ok", "rules_version": store.rules["version"]}

    # ---------------- mock tools (synthetic data; mode=timeout simulates an outage)
    def fail_if(mode):
        if mode == "timeout":
            raise HTTPException(504, "simulated tool timeout")

    @app.get("/tools/asset/{host}")
    def tool_asset(host: str, mode: str = "ok"):
        fail_if(mode)
        a = store.assets.get(host)
        return {"host": host, "found": bool(a), "record": a}

    @app.get("/tools/user/{user}")
    def tool_user(user: str, mode: str = "ok"):
        fail_if(mode)
        u = store.users.get(user)
        return {"user": user, "found": bool(u), "record": u}

    @app.get("/tools/intel")
    def tool_intel(indicator: str, mode: str = "ok"):
        fail_if(mode)
        rec = store.intel.get(indicator)
        return {"indicator": indicator, "evidence_id": f"INTEL:{indicator}",
                "record": rec or {"reputation": "unknown", "score": None, "reports": 0, "tags": []}}

    @app.get("/tools/events")
    def tool_events(host: str, start: str, end: str):
        return [e for e in store.events if e["host"] == host and start <= e["ts"] <= end]

    # ---------------- intake and orchestration helpers
    @app.post("/alerts")
    def intake(alert: AlertIn):
        case, dup = db.create_case(conn, alert.model_dump())
        return {"case_id": case["case_id"], "status": case["status"], "duplicate": dup}

    @app.post("/cases/{case_id}/prepare")
    def prepare(case_id: str):
        c = case_or_404(case_id)
        alert = json.loads(c["alert_json"])
        assessment = rules.triage(store, alert)
        events = rules.window_events(store, alert)
        masked, mapping = masking.mask_case(alert, events, {alert["host"]: store.assets[alert["host"]]} if assessment["asset_status"] == "ok" else {},
                                           {alert["user"]: store.users[alert["user"]]} if alert.get("user") in store.users else {})
        masked["assessment"] = masking.mask_assessment(assessment, mapping, masked)
        db.update_case(conn, case_id, "system", "prepared", status="processing", masked_json=json.dumps(masked),
                       mapping_json=json.dumps(mapping), assessment_json=json.dumps(assessment), band=assessment["band"], score=assessment["score"])
        db.audit(conn, case_id, "system", "masked_and_scored", {"score": assessment["score"], "band": assessment["band"],
                                                             "injection": assessment["injection"], "rules_version": assessment["rules_version"]})
        return {"case_id": case_id, "masked": masked, "assessment": assessment,
                "allowed_evidence_ids": sorted(checks.allowed_evidence_ids(masked["assessment"]))}

    def context_for(case_id):
        return agents.prepare_context(store, json.loads(case_or_404(case_id)["alert_json"]))

    @app.post("/cases/{case_id}/agent-input")
    def agent_input(case_id: str, agent: str = Body(...), model: str = Body(default="llama"), seed: int = Body(default=llm.BASE_SEED),
                    outputs: dict = Body(default={}), final: Optional[dict] = Body(default=None)):
        """The exact Ollama request for one agent (prompt, masked input, fixed settings, schema). n8n only forwards it."""
        if agent not in checks.SCHEMAS:
            raise HTTPException(422, "unknown agent")
        ctx = context_for(case_id)
        payload = agents.build_payload(agent, ctx, outputs, store.rules, final)
        body = llm.ollama_body(model, prompts.system_prompt(agent), prompts.user_prompt(payload), checks.SCHEMAS[agent], seed)
        return {"agent": agent, "model": body["model"], "seed": seed, "prompt_version": prompts.PROMPT_VERSION, "ollama_body": body}

    @app.post("/cases/{case_id}/checks")
    def run_checks(case_id: str, agent: str = Body(...), output: dict = Body(...)):
        if agent not in checks.SCHEMAS:
            raise HTTPException(422, "unknown agent")
        problems = agents.validate(agent, output, context_for(case_id), store.rules)
        return {"agent": agent, "passed": not problems, "problems": problems}

    @app.post("/cases/{case_id}/steps")
    def record_step(case_id: str, s: StepIn):
        case_or_404(case_id)
        db.add_step(conn, case_id, s.agent, s.attempt, s.model, s.prompt_version, s.output, s.problems, s.latency_ms)
        return {"ok": True}

    @app.post("/cases/{case_id}/route")
    def route(case_id: str, risk_outputs: list = Body(default=[]), failed_checks: int = Body(default=0)):
        c = case_or_404(case_id)
        a = json.loads(c["assessment_json"])
        d = checks.final_decision(a, risk_outputs, store.rules, failed_checks)
        if d["escalate"]:
            status, target = "escalated", "escalation"
        elif d["deprioritise_allowed"]:
            status, target = "deprioritised", "deprioritised_list"
        else:
            status, target = "queued", "analyst_queue"
        d["route"] = target
        db.update_case(conn, case_id, "system", f"routed_{target}", status=status, band=d["band"], route_json=json.dumps(d))
        if status == "deprioritised":
            db.add_to_list(conn, case_id, "deprioritised", [f"band {d['band']}", f"score {a['score']}", "intelligence clean or none",
                                                            "no never-deprioritise reason", f"runs agree: {d['runs_agree']}"])
        return d

    # ---------------- reads
    @app.get("/cases/{case_id}")
    def get_case(case_id: str):
        c = parse(case_or_404(case_id))
        c["steps"] = [dict(r) for r in conn.execute("SELECT * FROM steps WHERE case_id=? ORDER BY id", (case_id,))]
        c["decisions"] = [dict(r) for r in conn.execute("SELECT * FROM decisions WHERE case_id=? ORDER BY id", (case_id,))]
        return c

    @app.get("/cases")
    def list_cases(status: Optional[str] = None):
        q, args = "SELECT case_id, alert_id, status, band, score, created_at FROM cases", []
        if status:
            q += " WHERE status=?"; args.append(status)
        return [dict(r) for r in conn.execute(q + " ORDER BY created_at DESC", args)]

    @app.get("/decisions")
    def list_decisions(limit: int = 100):
        """Human decisions, newest first, with the case, its alert, its current status and the route it took."""
        rows = conn.execute("SELECT d.case_id, c.alert_id, c.status, c.band, c.route_json, d.actor, d.decision, d.reason, d.ts "
                            "FROM decisions d JOIN cases c ON c.case_id = d.case_id ORDER BY d.id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            rj = d.pop("route_json", None)
            d["route"] = (json.loads(rj).get("route") if rj else None)
            out.append(d)
        return out

    @app.get("/register")
    def register(limit: int = 1000):
        """One row per received alert: case number, alert, test-case code (G01, E01, B001), status, route, model, last decision."""
        rows = conn.execute("SELECT case_id, alert_id, status, band, score, route_json, alert_json, created_at, updated_at FROM cases "
                            "ORDER BY created_at DESC, case_id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            alert = json.loads(d.pop("alert_json"))
            rj = d.pop("route_json", None)
            step = conn.execute("SELECT model FROM steps WHERE case_id=? ORDER BY id LIMIT 1", (d["case_id"],)).fetchone()
            dec = conn.execute("SELECT decision, actor, reason, ts FROM decisions WHERE case_id=? ORDER BY id DESC LIMIT 1", (d["case_id"],)).fetchone()
            d.update(test_code=alert.get("gold_case") or d["alert_id"].replace("AL-", ""), rule=alert.get("rule"), host=alert.get("host"),
                     summary=alert.get("summary"), route=(json.loads(rj).get("route") if rj else None),
                     model=(step["model"].split(":")[0] if step else None),
                     last_decision=(dec["decision"] if dec else None), decided_by=(dec["actor"] if dec else None),
                     decision_reason=(dec["reason"] if dec else None), decided_at=(dec["ts"] if dec else None))
            out.append(d)
        return out

    @app.get("/queue")
    def get_queue():
        return [{k: c[k] for k in ("case_id", "alert_id", "band", "score", "created_at")} for c in db.queue(conn)]

    @app.get("/escalations")
    def escalations():
        return [dict(r) for r in conn.execute("SELECT case_id, alert_id, band, score, route_json FROM cases WHERE status='escalated' ORDER BY score DESC")]

    @app.get("/audit")
    def get_audit(case_id: Optional[str] = None, limit: int = 200):
        q, args = "SELECT * FROM audit_log", []
        if case_id:
            q += " WHERE case_id=?"; args.append(case_id)
        return [dict(r) for r in conn.execute(q + " ORDER BY id DESC LIMIT ?", (*args, limit))]

    @app.get("/analytics")
    def get_analytics():
        return db.analytics(conn)

    # ---------------- human decisions (G14), lists (G15, G16)
    @app.post("/cases/{case_id}/decision")
    def decide(case_id: str, d: DecisionIn):
        case_or_404(case_id)
        if d.decision not in ALLOWED_DECISIONS:
            raise HTTPException(422, f"decision must be one of {sorted(ALLOWED_DECISIONS)}")
        try:
            db.add_decision(conn, case_id, d.actor, d.decision, d.reason)
        except ValueError as e:
            raise HTTPException(422, str(e))
        resume_workflow(case_id)
        status = {"confirm_threat": "handed_over", "dismiss": "closed_dismissed", "watchlist": "watchlist",
                  "approve_action": "action_approved", "reject_action": "action_rejected"}.get(d.decision)
        if status:
            db.update_case(conn, case_id, d.actor, f"status_{status}", status=status)
            if d.decision == "watchlist":
                db.add_to_list(conn, case_id, "watchlist", ["needs more evidence"])
        return {"ok": True, "status": status}

    def resume_workflow(case_id):
        """Release the n8n Wait node for this case, if the workflow is waiting for the human decision."""
        c = db.get_case(conn, case_id)
        url = c and c.get("resume_url")
        if not url:
            return
        try:
            requests.post(url, json={"case_id": case_id}, timeout=5)
            db.audit(conn, case_id, "system", "workflow_resumed", {})
        except requests.RequestException as e:
            db.audit(conn, case_id, "system", "workflow_resume_failed", {"error": str(e)})
        conn.execute("UPDATE cases SET resume_url=NULL WHERE case_id=?", (case_id,))
        conn.commit()

    @app.post("/cases/{case_id}/awaiting")
    def awaiting(case_id: str, resume_url: str = Body(..., embed=True)):
        case_or_404(case_id)
        conn.execute("UPDATE cases SET resume_url=? WHERE case_id=?", (resume_url, case_id))
        conn.commit()
        db.audit(conn, case_id, "workflow", "awaiting_human_decision", {})
        return {"ok": True}

    @app.post("/workflow-errors")
    def workflow_error(execution_id: str = Body(default=""), workflow: str = Body(default=""), node: str = Body(default=""),
                       message: str = Body(default="")):
        """Error Trigger handler: cases stuck in processing go to a human instead of being lost (exception handling)."""
        stuck = [r["case_id"] for r in conn.execute("SELECT case_id FROM cases WHERE status='processing'")]
        for cid in stuck:
            db.update_case(conn, cid, "system", "workflow_error_escalated", status="escalated",
                           route_json=json.dumps({"route": "escalation", "escalate_reasons": ["workflow_error"], "band": None}))
            db.audit(conn, cid, "system", "workflow_error", {"execution_id": execution_id, "workflow": workflow, "node": node, "message": message[:300]})
        return {"escalated": stuck}

    @app.get("/lists")
    def lists(list_type: Optional[str] = None, state: Optional[str] = None):
        return db.list_items(conn, list_type, state)

    @app.post("/lists/spotcheck")
    def spotcheck_sample(seed: Optional[int] = None):
        batch, sample = db.make_spotcheck_sample(conn, seed=seed)
        return {"batch_id": batch, "sample": [{"case_id": c, "type": t} for c, t in sample]}

    @app.post("/lists/spotcheck/{batch_id}/verdict")
    def verdict(batch_id: str, case_id: str = Body(...), verdict: str = Body(...), actor: str = Body(...)):
        if verdict not in ("agree", "disagree"):
            raise HTTPException(422, "verdict must be agree or disagree")
        db.record_verdict(conn, batch_id, case_id, verdict, actor)
        return {"complete": db.spotcheck_complete(conn, batch_id)}

    @app.post("/lists/bulk-confirm")
    def bulk(batch_id: str = Body(...), actor: str = Body(...)):
        try:
            return {"confirmed": db.bulk_confirm(conn, batch_id, actor)}
        except PermissionError as e:
            raise HTTPException(409, str(e))

    @app.post("/cases/{case_id}/promote")
    def promote_case(case_id: str, actor: str = Body(...), reason: str = Body(default="")):
        case_or_404(case_id)
        db.promote(conn, case_id, actor, reason)
        return {"ok": True}

    @app.post("/admin/autoclose")
    def autoclose(now: Optional[str] = None):
        due = db.autoclose_due(conn, store.rules["auto_close_days"], now)
        return {"auto_closed": due, "notice_to_lead": bool(due)}

    return app


app = create_app()
