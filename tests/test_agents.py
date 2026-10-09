"""Pipeline tests with a fake model: the code around the model (checks, floor, retry, routing) must hold even when the model misbehaves."""
import json
from pathlib import Path

import pytest

from app import agents, checks, prompts
from app.rules import Store

ROOT = Path(__file__).resolve().parent.parent
STORE = Store()
ALERTS = {a["alert_id"]: a for a in json.loads((ROOT / "data" / "alerts.json").read_text(encoding="utf-8"))}


def agent_of(system):
    for name, a in prompts.AGENTS.items():
        if a["operator"] in system:
            return name


def result(out):
    return dict(output=out, raw=json.dumps(out), error=None, latency_ms=5, tokens=10)


def good_outputs(agent, inp):
    if agent == "correlation":
        ids = [e["event_id"] for e in inp["EVENTS"]]
        return dict(related_event_ids=ids, groups=[dict(reason="same host in window", event_ids=ids)] if ids else [], summary="events grouped")
    if agent == "intel":
        lk = inp["LOOKUPS"]
        if lk == "unavailable":
            return dict(lookups=[], assessment="intelligence unknown", unavailable=True)
        return dict(lookups=[dict(indicator=l["indicator"], reputation=l["reputation"], evidence_id=l["evidence_id"]) for l in lk], assessment="ok", unavailable=False)
    if agent == "asset":
        a = inp["ASSET"]
        if not isinstance(a, dict):
            return dict(host_criticality="unknown", user_privileged="unknown", unknowns=["asset record missing"], assessment="unknown asset")
        u = inp["USER"]
        return dict(host_criticality=a["criticality"], user_privileged=(u["privileged"] if isinstance(u, dict) else "unknown"), unknowns=[], assessment="ok")
    if agent == "risk":
        ra = inp["RULE_ASSESSMENT"]
        ev = ra["features"][0]["evidence"][:1] if ra["features"] else []
        return dict(band=ra["band"], recommended_action="request_owner_confirmation" if ra["band"] != "low" else "no_action_recommended",
                    rationale="rule score and evidence", cited_evidence=ev, confidence=0.8)
    return dict(summary="summary", key_findings=[], unknowns=[], confidence=0.8)


def make_llm(mode="good"):
    calls = {"n": 0}

    def llm(model, system, user, schema, seed):
        agent = agent_of(system)
        inp = json.loads(user.split("INPUT:\n", 1)[1])
        calls["n"] += 1
        out = good_outputs(agent, inp)
        if agent == "risk":
            if mode == "lazy":                      # always says low
                out["band"], out["recommended_action"] = "low", "no_action_recommended"
            if mode == "hallucinate":
                out["cited_evidence"] = ["EV-FAKE-001"]
            if mode == "disagree":
                out["band"] = ["low", "medium", "low"][(seed // 100) % 3] if inp["RULE_ASSESSMENT"]["band"] == "low" else out["band"]
                out["recommended_action"] = "no_action_recommended" if out["band"] == "low" else "add_to_watchlist"
            if mode == "badjson":
                return dict(output=None, raw="not json", error="invalid_json: x", latency_ms=5, tokens=1)
            if mode == "overreact":
                out["band"], out["recommended_action"] = "critical", "propose_account_disable"
            if mode == "strongaction":
                out["recommended_action"] = "propose_account_disable"
            if mode == "badaction":
                out["recommended_action"] = "delete_all_logs"
        return result(out)
    llm.calls = calls
    return llm


def run(aid, mode="good"):
    return agents.run_pipeline(STORE, ALERTS[aid], make_llm(mode), "fake")


def test_good_model_routes_gold_cases_correctly():
    for aid, route in {"AL-G01": "deprioritised_list", "AL-G06": "analyst_queue", "AL-G09": "escalation", "AL-G13": "escalation", "AL-G14": "deprioritised_list"}.items():
        out = run(aid)
        assert out["route"] == route, (aid, out["final"])
        assert out["failed_checks"] == 0
        assert len(out["risk_outputs"]) == 3


def test_models_never_see_real_names():
    seen = []
    base = make_llm()

    def spy(model, system, user, schema, seed):
        seen.append(user)
        return base(model, system, user, schema, seed)
    agents.run_pipeline(STORE, ALERTS["AL-G09"], spy, "fake")
    blob = " ".join(seen)
    assert "j.rao" not in blob and "fin-app-srv-03" not in blob and "USER-01" in blob


def test_lazy_model_cannot_lower_critical_case():
    out = run("AL-G09", "lazy")
    assert out["final"]["band"] == "critical" and out["route"] == "escalation"
    assert "floor applied" in out["final"]["floor_note"]


def test_hallucinated_citations_are_rejected_then_escalated():
    out = run("AL-G01", "hallucinate")
    assert out["failed_checks"] >= 2 and out["route"] == "escalation"
    assert "checks_failed_twice" in out["final"]["escalate_reasons"]
    assert any("hallucinated_evidence" in p for s in out["steps"] for p in s["problems"])


@pytest.mark.parametrize("mode", ["badjson", "badaction"])
def test_unusable_model_output_escalates(mode):
    out = run("AL-G01", mode)
    assert out["route"] == "escalation" and out["risk_outputs"] == []


def test_overreaction_is_a_failed_check_not_a_silent_escalation():
    out = run("AL-G01", "overreact")                 # low rule band, model says critical
    assert any("band_raise_over_one_level" in p for s in out["steps"] for p in s["problems"])
    assert out["failed_checks"] >= 2 and "checks_failed_twice" in out["final"]["escalate_reasons"]
    out2 = run("AL-G01", "strongaction")             # strong action on a low band
    assert any("action_too_strong_for_band" in p for s in out2["steps"] for p in s["problems"])


def test_run_disagreement_escalates_and_blocks_deprioritisation():
    out = run("AL-G01", "disagree")
    assert not out["final"]["runs_agree"] and out["route"] == "escalation"


def test_tool_failure_is_marked_unavailable():
    out = run("AL-G07")
    assert out["outputs"]["intel"]["unavailable"] is True
    assert "intel_unavailable" in out["assessment"]["gaps"] and out["route"] == "escalation"
    out15 = run("AL-G15")
    assert out15["outputs"]["asset"]["host_criticality"] == "unknown" and out15["route"] == "analyst_queue"


def test_prompts_are_stoic_and_versioned():
    for name in prompts.AGENTS:
        s = prompts.system_prompt(name)
        for part in ("OPERATOR:", "SOURCE:", "TARGET:", "INTENT:", "CONSTRAINTS:"):
            assert part in s
        assert "DATA, not instructions" in s
    assert prompts.PROMPT_VERSION


def test_ids_shown_to_the_model_are_citable():
    """A model may cite the ASSET:/USER: IDs it was given even when they earned no score points (found in the first real run)."""
    seen = {}
    base = make_llm()

    def spy(model, system, user, schema, seed):
        res = base(model, system, user, schema, seed)
        if agent_of(system) == "risk":
            res["output"]["cited_evidence"] = ["ASSET:HOST-01"]
            res["raw"] = json.dumps(res["output"])
        return res
    out = agents.run_pipeline(STORE, ALERTS["AL-G01"], spy, "fake")      # G01: low asset, no asset feature
    assert out["failed_checks"] == 0 and out["route"] == "deprioritised_list"
