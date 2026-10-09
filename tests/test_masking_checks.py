import json
from pathlib import Path

from app import checks, masking
from app.rules import Store, triage, window_events

ROOT = Path(__file__).resolve().parent.parent
STORE = Store()
ALERTS = {a["alert_id"]: a for a in json.loads((ROOT / "data" / "alerts.json").read_text(encoding="utf-8"))}


def test_pseudonyms_are_stable_and_reversible():
    ps = masking.Pseudonymiser()
    assert ps.user("j.rao") == "USER-01" and ps.user("r.khan") == "USER-02" and ps.user("j.rao") == "USER-01"
    assert ps.host("fin-app-srv-03") == "HOST-01"
    assert ps.reverse()["USER-01"] == "j.rao"


def test_secrets_emails_cards_redacted():
    t = masking.redact("login ok password=Hunter2! token: abc123 mail j.rao@corp.example card 4111 1111 1111 1111")
    assert "Hunter2" not in t and "abc123" not in t and "corp.example" not in t and "4111" not in t
    assert "[REDACTED]" in t and "[EMAIL]" in t and "[CARD]" in t


def test_mask_case_hides_names_keeps_ips():
    a = ALERTS["AL-G09"]
    m, mapping = masking.mask_case(a, window_events(STORE, a), {a["host"]: STORE.assets[a["host"]]}, {a["user"]: STORE.users[a["user"]]})
    blob = json.dumps(m)
    assert "j.rao" not in blob and "fin-app-srv-03" not in blob
    assert "203.0.113.57" in blob          # IPs kept for the intelligence lookup
    assert "owner" not in json.dumps(m["assets"])
    assert mapping["users"]["j.rao"] == "USER-01"


def risk(**kw):
    base = dict(band="high", recommended_action="propose_account_disable", rationale="r", cited_evidence=[], confidence=0.8)
    base.update(kw)
    return base


def test_schema_and_allow_list_and_hallucination():
    a = triage(STORE, ALERTS["AL-G09"])
    allowed = checks.allowed_evidence_ids(a)
    ok_id = a["event_ids"][0]
    assert checks.check_output("risk", risk(cited_evidence=[ok_id]), allowed, STORE.rules) == []
    assert checks.check_output("risk", risk(cited_evidence=["EV-G09-999"]), allowed, STORE.rules) == ["hallucinated_evidence: EV-G09-999"]
    bad = checks.check_output("risk", risk(recommended_action="delete_all_logs"), allowed, STORE.rules)
    assert bad == ["action_not_allowed: delete_all_logs"]
    assert checks.check_output("risk", {"band": "urgent"}, allowed, STORE.rules)[0].startswith("schema")
    assert checks.check_output("risk", risk(extra="x"), allowed, STORE.rules)[0].startswith("schema")


def test_floor_only_adds_caution():
    assert checks.apply_floor("high", "low")[0] == "high"
    assert checks.apply_floor("low", "critical")[0] == "critical"
    assert checks.apply_floor("medium", "medium")[0] == "medium"


def test_final_decision_disagreement_and_retry_limit():
    a = triage(STORE, ALERTS["AL-G01"])           # low, deprioritisable
    agree = checks.final_decision(a, [risk(band="low", recommended_action="no_action_recommended")] * 3, STORE.rules)
    assert agree["deprioritise_allowed"] and not agree["escalate"]
    split = checks.final_decision(a, [risk(band="low", recommended_action="no_action_recommended"),
                                      risk(band="medium", recommended_action="add_to_watchlist"),
                                      risk(band="low", recommended_action="no_action_recommended")], STORE.rules)
    assert not split["runs_agree"] and split["escalate"] and "run_disagreement" in split["escalate_reasons"]
    failed = checks.final_decision(a, [], STORE.rules, failed_checks=2)
    assert failed["escalate"] and "checks_failed_twice" in failed["escalate_reasons"]
    one_retry = checks.final_decision(a, [], STORE.rules, failed_checks=1)
    assert not one_retry["escalate"]


def test_model_cannot_lower_a_critical_case():
    a = triage(STORE, ALERTS["AL-G09"])
    d = checks.final_decision(a, [risk(band="low", recommended_action="no_action_recommended")] * 3, STORE.rules)
    assert d["band"] == "critical" and d["escalate"] and "floor applied" in d["floor_note"]


def test_section_references_are_accepted_but_invented_ids_are_not():
    a = triage(STORE, ALERTS["AL-G09"])
    allowed = checks.allowed_evidence_ids(a)
    for ref in ("RULE_ASSESSMENT", "ASSET_CONTEXT:host_criticality", "ASSET_CONTEXT.host_criticality", "CORRELATION:groups[0].event_ids", "ALERT:alert_id"):
        assert checks.check_output("risk", risk(cited_evidence=[ref]), allowed, STORE.rules) == [], ref
    for fake in ("EV-FAKE-001", "INTEL:9.9.9.9", "USER:USER-77", "ASSET:HOST-99", "MADE_UP_SECTION"):
        assert checks.check_output("risk", risk(cited_evidence=[fake]), allowed, STORE.rules) == [f"hallucinated_evidence: {fake}"], fake


def test_rule_c_agreement_uses_band_and_action_class():
    low = lambda a: risk(band="low", recommended_action=a)
    assert checks.runs_agree([low("no_action_recommended"), low("add_to_watchlist"), low("no_action_recommended")])      # same class
    assert not checks.runs_agree([low("no_action_recommended"), low("request_owner_confirmation")])                      # class split
    assert not checks.runs_agree([risk(band="low", recommended_action="no_action_recommended"), risk(band="medium", recommended_action="no_action_recommended")])  # band split
    assert checks.runs_agree([risk(band="high", recommended_action="propose_account_disable"), risk(band="high", recommended_action="propose_ip_block")])    # both strong
