"""Case register search: numbers, case-insensitive codes, free text."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ui"))
from search import match_rows, resolve_case  # noqa: E402

ROWS = [
    dict(case_id="CASE-00001", alert_id="AL-G13", test_code="G13", rule="Multiple failed logins", host="test-srv-08", status="escalated", route="escalation", model="llama", band="low", last_decision=None, summary="12 failed logins"),
    dict(case_id="CASE-00002", alert_id="AL-G06", test_code="G06", rule="Multiple failed logins", host="tmp-host-99", status="queued", route="analyst_queue", model="qwen", band="low", last_decision=None, summary="12 failed logins"),
    dict(case_id="CASE-00010", alert_id="AL-B003", test_code="B003", rule="Failed login", host="dev-build-01", status="closed_deprioritised", route="deprioritised_list", model="llama", band="low", last_decision=None, summary="routine"),
    dict(case_id="CASE-00011", alert_id="AL-G01", test_code="G01", rule="Multiple failed logins", host="test-srv-07", status="queued", route="analyst_queue", model="llama", band="low", last_decision=None, summary="6 failed logins"),
]


def test_a_bare_number_finds_the_case_number():
    assert resolve_case("1", ROWS) == "CASE-00001"
    assert resolve_case("case-1", ROWS) == "CASE-00001"
    assert resolve_case("00002", ROWS) == "CASE-00002"
    assert resolve_case("99", ROWS) is None


def test_test_case_codes_are_not_case_sensitive():
    for q in ("g13", "G13", "g013", "AL-G13", "al-g13"):
        assert resolve_case(q, ROWS) == "CASE-00001"
    assert resolve_case("b3", ROWS) == "CASE-00010"
    assert resolve_case("g20", ROWS) is None


def test_a_number_matches_both_the_case_and_the_code_with_that_number():
    ids = {r["case_id"] for r in match_rows("1", ROWS)}
    assert ids == {"CASE-00001", "CASE-00011"}          # CASE-00001 and G01, not CASE-00010 or CASE-00011 by substring


def test_free_text_search_is_case_insensitive():
    assert {r["case_id"] for r in match_rows("QWEN", ROWS)} == {"CASE-00002"}
    assert {r["case_id"] for r in match_rows("dev-build", ROWS)} == {"CASE-00010"}
    assert len(match_rows("", ROWS)) == 4
