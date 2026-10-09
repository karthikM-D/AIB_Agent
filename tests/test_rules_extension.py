"""Rules v1.2 (added after expert feedback): slow failed logins and repeated pattern over weeks."""
import copy
import json
from pathlib import Path

import pytest

from app.rules import Store, triage

ROOT = Path(__file__).resolve().parent.parent
EXT = json.loads((ROOT / "benchmark" / "extension_cases.json").read_text(encoding="utf-8"))
STORE = Store()
ALERTS = {a["alert_id"]: a for a in json.loads((ROOT / "data" / "alerts.json").read_text(encoding="utf-8"))}


@pytest.mark.parametrize("case", EXT, ids=[c["case_id"] for c in EXT])
def test_extension_case(case):
    exp = case["expected"]
    out = triage(STORE, ALERTS[f"AL-{case['case_id']}"])
    assert out["band"] == exp["band"] and out["escalate"] == exp["escalate"]
    assert out["deprioritise_allowed"] == exp["deprioritise_allowed"]
    assert set(exp["features"]) <= {f["feature"] for f in out["features"]}


def test_v1_2_does_not_change_existing_alerts():
    old = [a for a in ALERTS.values() if not a["alert_id"].startswith("AL-E")]
    assert len(old) == 120
    for a in old:
        out = triage(STORE, a)
        assert not out["slow_pattern"] and not out["repeat_pattern"] and out["extended_ids"] == []


def _store_with(**changes):
    s = Store()
    for k, v in changes.items():
        setattr(s, k, v)
    return s


def test_slow_rule_needs_six_spaced_failures_from_one_external_address():
    alert = ALERTS["AL-E01"]
    fewer = [e for e in STORE.events if e["event_id"] != "EV-E01-002"]          # six failures: still fires
    assert triage(_store_with(events=fewer), alert)["slow_pattern"]
    fewer = [e for e in fewer if e["event_id"] != "EV-E01-003"]                 # five failures: does not
    out = triage(_store_with(events=fewer), alert)
    assert not out["slow_pattern"] and out["band"] == "low" and out["deprioritise_allowed"]


def test_slow_rule_ignores_internal_sources():
    alert = ALERTS["AL-E01"]
    events = [dict(e, src_ip="10.20.1.9") if e["event_id"].startswith("EV-E01") else e for e in STORE.events]
    assert not triage(_store_with(events=events), dict(alert, src_ip="10.20.1.9"))["slow_pattern"]


def test_slow_rule_does_not_double_count_a_burst():
    """Five or more failures inside the ten-minute window use the existing burst rule, not the slow rule."""
    out = triage(STORE, ALERTS["AL-G15"])
    assert not out["slow_pattern"] and any(f["feature"] == "failed_logins_ge_10" for f in out["features"])


def test_repeat_rule_needs_three_prior_alerts_and_a_privileged_user_or_critical_asset():
    alert = ALERTS["AL-E02"]
    assert triage(STORE, alert)["repeat_pattern"]
    two = [h for h in STORE.history if h["history_id"] != "HIST-E02-004"][:2]
    assert not triage(_store_with(history=two), alert)["repeat_pattern"]
    users = copy.deepcopy(STORE.users)
    users["r.khan"]["privileged"] = False
    assert not triage(_store_with(users=users), alert)["repeat_pattern"]


def test_repeat_rule_ignores_history_older_than_the_window():
    old = [dict(h, ts="2025-01-0%dT01:00:00" % (i + 1)) for i, h in enumerate(STORE.history)]
    assert not triage(_store_with(history=old), ALERTS["AL-E02"])["repeat_pattern"]


def test_extended_evidence_section_reference_is_accepted_but_invented_ids_are_not():
    from app import checks
    assert checks.is_section_reference("EXTENDED_EVIDENCE:history:HIST-E02-001")
    assert not checks.is_section_reference("EV-E02-003")
