"""Checks the rule engine against the hand-written gold expectations (written before the engine)."""
import json
from pathlib import Path

import pytest

from app.rules import Store, triage

ROOT = Path(__file__).resolve().parent.parent
GOLD = json.loads((ROOT / "benchmark" / "gold_cases.json").read_text(encoding="utf-8"))
STORE = Store()
ALERTS = {a["alert_id"]: a for a in json.loads((ROOT / "data" / "alerts.json").read_text(encoding="utf-8"))}


@pytest.mark.parametrize("case", GOLD, ids=[c["case_id"] for c in GOLD])
def test_gold_case(case):
    exp = case["expected"]
    out = triage(STORE, ALERTS[case["alert_id"]])
    assert out["band"] == exp["band"], (out["score"], out["features"])
    assert out["escalate"] == exp["escalate"], out["escalate_reasons"]
    assert out["reportable"] == exp["reportable"]
    assert out["deprioritise_allowed"] == exp["deprioritise_allowed"], out["never_deprioritise"]
    assert out["injection"] == exp["injection"]
    cited = {e for f in out["features"] for e in f["evidence"]}
    for eid in exp["must_cite"]:
        assert eid in cited or eid in out["event_ids"]
    if "grouped_count" in exp:
        assert out["failed_login_count"] == exp["grouped_count"]


def test_boundaries():
    scores = {c["case_id"]: triage(STORE, ALERTS[c["alert_id"]])["raw_score"] for c in GOLD}
    assert scores["G16"] == 24 and scores["G08"] == 25  # medium boundary
    assert scores["G18"] == 50                           # high boundary
    assert scores["G10"] == 75                           # critical boundary
    assert scores["G09"] > 100                           # cap applies
    assert triage(STORE, ALERTS["AL-G09"])["score"] == 100


def test_injection_never_lowers_or_closes():
    out = triage(STORE, ALERTS["AL-G13"])
    assert out["band"] == "low" and out["escalate"] and not out["deprioritise_allowed"]


def test_background_alerts_are_low_and_deprioritisable():
    bg = [a for a in ALERTS.values() if a["alert_id"].startswith("AL-B")]
    assert len(bg) == 100
    assert all(triage(STORE, a)["band"] == "low" for a in bg)
