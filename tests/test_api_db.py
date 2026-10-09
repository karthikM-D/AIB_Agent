import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import db
from app.api import create_app

ROOT = Path(__file__).resolve().parent.parent
ALERTS = {a["alert_id"]: a for a in json.loads((ROOT / "data" / "alerts.json").read_text(encoding="utf-8"))}


@pytest.fixture()
def client(tmp_path):
    return TestClient(create_app(tmp_path / "t.db"))


def alert_body(aid):
    a = dict(ALERTS[aid])
    return a


def run_case(client, aid, risk_outputs=None, failed=0):
    cid = client.post("/alerts", json=alert_body(aid)).json()["case_id"]
    prep = client.post(f"/cases/{cid}/prepare").json()
    r = client.post(f"/cases/{cid}/route", json={"risk_outputs": risk_outputs or [], "failed_checks": failed}).json()
    return cid, prep, r


def test_audit_log_is_append_only(tmp_path):
    conn = db.connect(tmp_path / "a.db")
    db.audit(conn, "C1", "tester", "x")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE audit_log SET event='y'")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM audit_log")


def test_intake_validation_and_idempotence(client):
    bad = alert_body("AL-G01"); bad["ts"] = "yesterday"
    assert client.post("/alerts", json=bad).status_code == 422
    big = alert_body("AL-G01"); big["summary"] = "x" * 3000
    assert client.post("/alerts", json=big).status_code == 422
    first = client.post("/alerts", json=alert_body("AL-G01")).json()
    again = client.post("/alerts", json=alert_body("AL-G01")).json()
    assert again["duplicate"] and again["case_id"] == first["case_id"]


def test_prepare_masks_and_scores(client):
    cid = client.post("/alerts", json=alert_body("AL-G09")).json()["case_id"]
    prep = client.post(f"/cases/{cid}/prepare").json()
    assert "j.rao" not in json.dumps(prep["masked"]) and prep["assessment"]["band"] == "critical"
    assert prep["assessment"]["alert_id"] in prep["allowed_evidence_ids"]


def test_routing_normal_ambiguous_highrisk(client):
    risk = dict(band="low", recommended_action="no_action_recommended", rationale="r", cited_evidence=[], confidence=0.9)
    _, _, normal = run_case(client, "AL-G01", [risk] * 3)
    assert normal["route"] == "deprioritised_list"
    _, _, amb = run_case(client, "AL-G06", [risk] * 3)
    assert amb["route"] == "analyst_queue"                      # unknown asset blocks deprioritisation
    _, _, high = run_case(client, "AL-G09", [dict(risk, band="low")] * 3)
    assert high["route"] == "escalation" and high["band"] == "critical"
    _, _, inj = run_case(client, "AL-G13", [risk] * 3)
    assert inj["route"] == "escalation" and "injection_suspected" in inj["escalate_reasons"]


def test_checks_endpoint_catches_hallucination(client):
    cid = client.post("/alerts", json=alert_body("AL-G09")).json()["case_id"]
    client.post(f"/cases/{cid}/prepare")
    bad = dict(band="high", recommended_action="propose_account_disable", rationale="r", cited_evidence=["EV-ZZ-001"], confidence=0.5)
    res = client.post(f"/cases/{cid}/checks", json={"agent": "risk", "output": bad}).json()
    assert not res["passed"] and res["problems"] == ["hallucinated_evidence: EV-ZZ-001"]


def test_human_decision_requires_reason(client):
    cid, _, _ = run_case(client, "AL-G06")
    assert client.post(f"/cases/{cid}/decision", json={"actor": "analyst", "decision": "dismiss", "reason": "  "}).status_code == 422
    assert client.post(f"/cases/{cid}/decision", json={"actor": "analyst", "decision": "delete", "reason": "x"}).status_code == 422
    ok = client.post(f"/cases/{cid}/decision", json={"actor": "analyst", "decision": "dismiss", "reason": "benign test host"})
    assert ok.status_code == 200 and client.get(f"/cases/{cid}").json()["status"] == "closed_dismissed"


def test_decided_cases_stay_visible_in_the_decisions_list(client):
    cid, _, _ = run_case(client, "AL-G06")
    esc, _, _ = run_case(client, "AL-G09")
    assert client.get("/decisions").json() == []
    client.post(f"/cases/{cid}/decision", json={"actor": "analyst", "decision": "reject_action", "reason": "owner confirmed the test host"})
    client.post(f"/cases/{esc}/decision", json={"actor": "lead", "decision": "confirm_threat", "reason": "known bad address"})
    rows = {r["case_id"]: r for r in client.get("/decisions").json()}
    assert rows[cid]["route"] == "analyst_queue" and rows[cid]["decision"] == "reject_action" and rows[cid]["reason"].startswith("owner")
    assert rows[esc]["route"] == "escalation" and rows[esc]["alert_id"] == "AL-G09"


def test_register_maps_case_numbers_to_test_codes(client):
    cid, _, _ = run_case(client, "AL-G06")
    client.post(f"/cases/{cid}/decision", json={"actor": "analyst", "decision": "reject_action", "reason": "owner confirmed"})
    rows = {r["case_id"]: r for r in client.get("/register").json()}
    r = rows[cid]
    assert r["alert_id"] == "AL-G06" and r["test_code"] == "G06" and r["host"] == "tmp-host-99"
    assert r["route"] == "analyst_queue" and r["last_decision"] == "reject_action" and r["decided_by"] == "analyst"


def test_spotcheck_gate_promotion_and_bulk_confirm(client):
    risk = dict(band="low", recommended_action="no_action_recommended", rationale="r", cited_evidence=[], confidence=0.9)
    ids = [run_case(client, a, [risk] * 3)[0] for a in ("AL-G01", "AL-G02", "AL-G03", "AL-G04", "AL-G14")]
    assert len(client.get("/lists", params={"list_type": "deprioritised"}).json()) == 5
    batch = client.post("/lists/spotcheck", params={"seed": 1}).json()
    assert len(batch["sample"]) == 5
    assert client.post("/lists/bulk-confirm", json={"batch_id": batch["batch_id"], "actor": "analyst"}).status_code == 409
    first = True
    for s in batch["sample"]:
        client.post(f"/lists/spotcheck/{batch['batch_id']}/verdict",
                    json={"case_id": s["case_id"], "verdict": "disagree" if first else "agree", "actor": "analyst"})
        first = False
    res = client.post("/lists/bulk-confirm", json={"batch_id": batch["batch_id"], "actor": "analyst"})
    assert res.status_code == 200 and len(res.json()["confirmed"]) == 4
    a = client.get("/analytics").json()
    assert a["promoted"] == 1 and a["promotion_rate"] == pytest.approx(0.2)
    assert any(q["case_id"] == batch["sample"][0]["case_id"] for q in client.get("/queue").json())


def test_autoclose_notifies_lead(client, tmp_path):
    risk = dict(band="low", recommended_action="no_action_recommended", rationale="r", cited_evidence=[], confidence=0.9)
    cid, _, _ = run_case(client, "AL-G01", [risk] * 3)
    assert client.post("/admin/autoclose", params={"now": "2099-01-01T00:00:00"}).json()["auto_closed"] == [cid]
    assert client.get(f"/cases/{cid}").json()["status"] == "auto_closed"
    events = [a["event"] for a in client.get("/audit").json()]
    assert "lead_notice" in events and "auto_closed" in events


def test_mock_tools_can_fail(client):
    assert client.get("/tools/asset/web-prod-01").json()["found"] is True
    assert client.get("/tools/asset/nope").json()["found"] is False
    assert client.get("/tools/asset/web-prod-01", params={"mode": "timeout"}).status_code == 504
    assert client.get("/tools/intel", params={"indicator": "203.0.113.57", "mode": "timeout"}).status_code == 504
    assert client.get("/tools/intel", params={"indicator": "203.0.113.57"}).json()["record"]["reputation"] == "malicious"


def test_audit_trail_covers_the_case(client):
    cid, _, _ = run_case(client, "AL-G09")
    events = [a["event"] for a in client.get("/audit", params={"case_id": cid}).json()]
    for e in ("alert_received", "prepared", "masked_and_scored", "routed_escalation"):
        assert e in events


def test_agent_input_builds_the_exact_ollama_request(client):
    cid = client.post("/alerts", json=alert_body("AL-G09")).json()["case_id"]
    client.post(f"/cases/{cid}/prepare")
    r = client.post(f"/cases/{cid}/agent-input", json={"agent": "correlation", "model": "qwen", "seed": 7}).json()
    body = r["ollama_body"]
    assert body["model"] == "qwen3:8b" and body["options"]["seed"] == 7 and body["options"]["temperature"] == 0.2
    assert body["think"] is False and body["format"]["required"][0] == "related_event_ids"
    text = json.dumps(body["messages"])
    assert "j.rao" not in text and "fin-app-srv-03" not in text and "USER-01" in text
    assert r["prompt_version"]


def test_checks_endpoint_applies_consistency_rules(client):
    cid = client.post("/alerts", json=alert_body("AL-G01")).json()["case_id"]
    client.post(f"/cases/{cid}/prepare")
    over = dict(band="critical", recommended_action="propose_account_disable", rationale="r", cited_evidence=[], confidence=0.5)
    res = client.post(f"/cases/{cid}/checks", json={"agent": "risk", "output": over}).json()
    assert not res["passed"] and any(p.startswith("band_raise_over_one_level") for p in res["problems"])
    ok = dict(band="low", recommended_action="no_action_recommended", rationale="r", cited_evidence=["ASSET:HOST-01"], confidence=0.9)
    assert client.post(f"/cases/{cid}/checks", json={"agent": "risk", "output": ok}).json()["passed"]


def test_decision_resumes_the_waiting_workflow(client, monkeypatch):
    calls = []
    monkeypatch.setattr("app.api.requests.post", lambda url, **kw: calls.append(url))
    cid, _, _ = run_case(client, "AL-G06")
    client.post(f"/cases/{cid}/awaiting", json={"resume_url": "http://n8n.test/webhook-waiting/123"})
    client.post(f"/cases/{cid}/decision", json={"actor": "analyst", "decision": "dismiss", "reason": "test host"})
    assert calls == ["http://n8n.test/webhook-waiting/123"]
    events = [a["event"] for a in client.get("/audit", params={"case_id": cid}).json()]
    assert "awaiting_human_decision" in events and "workflow_resumed" in events


def test_workflow_error_escalates_stuck_cases(client):
    cid = client.post("/alerts", json=alert_body("AL-G06")).json()["case_id"]
    client.post(f"/cases/{cid}/prepare")                       # status: processing
    res = client.post("/workflow-errors", json={"execution_id": "9", "workflow": "SOC Triage", "node": "Ollama", "message": "timeout"}).json()
    assert res["escalated"] == [cid] and client.get(f"/cases/{cid}").json()["status"] == "escalated"


def test_concurrent_requests_do_not_corrupt_state(tmp_path):
    """Found in the first n8n runs: two alerts arriving in the same second broke a shared SQLite connection."""
    from concurrent.futures import ThreadPoolExecutor
    conn = db.connect(tmp_path / "c.db")
    alerts = [dict(ALERTS["AL-G01"], alert_id=f"AL-C{i:02d}") for i in range(24)]

    def work(a):
        case, dup = db.create_case(conn, a)
        db.audit(conn, case["case_id"], "tester", "x")
        return case["case_id"]
    with ThreadPoolExecutor(8) as ex:
        ids = list(ex.map(work, alerts))
    assert len(set(ids)) == 24 and not any(db.get_case(conn, i) is None for i in ids)
