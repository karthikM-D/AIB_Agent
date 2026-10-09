"""Add the two extension cases (E01, E02) that answer the expert feedback, without touching the 20 gold cases or the 100 background alerts.

E01  slow, spaced-out failed logins from one external address (the ten-minute window alone would not see them)
E02  a single failed login by a privileged user who has had the same alert repeatedly over the last weeks (history)

Idempotent: running it twice changes nothing. Writes to data/assets.json, events.json, alerts.json, history.json and
benchmark/extension_cases.json.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA, BENCH = ROOT / "data", ROOT / "benchmark"


def load(p, default):
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default


def save(p, obj):
    p.write_text(json.dumps(obj, indent=2), encoding="utf-8")


assets = load(DATA / "assets.json", {})
assets.setdefault("ext-web-04", dict(criticality="medium", environment="production", data_class="internal", owner="web-ops", role="customer portal web server"))
assets.setdefault("dev-build-02", dict(criticality="low", environment="development", data_class="internal", owner="app-dev", role="build server"))
save(DATA / "assets.json", assets)

events = load(DATA / "events.json", [])
have = {e["event_id"] for e in events}
new_events = []
for i, hhmm in enumerate(["04:10", "06:40", "09:15", "11:50", "14:20", "17:05", "19:35"], 1):
    new_events.append(dict(event_id=f"EV-E01-{i:03d}", ts=f"2026-10-03T{hhmm}:00", host="ext-web-04", user=None, src_ip="203.0.113.140",
                           dest_ip=None, file_hash=None, type="failed_login", details="authentication failure"))
new_events.append(dict(event_id="EV-E02-001", ts="2026-10-03T21:08:00", host="dev-build-02", user="r.khan", src_ip="10.20.4.12",
                       dest_ip=None, file_hash=None, type="failed_login", details="authentication failure"))
events += [e for e in new_events if e["event_id"] not in have]
save(DATA / "events.json", events)

alerts = load(DATA / "alerts.json", [])
have = {a["alert_id"] for a in alerts}
new_alerts = [
    dict(alert_id="AL-E01", ts="2026-10-03T19:35:00", rule="Failed login", host="ext-web-04", user=None, src_ip="203.0.113.140",
         summary="1 failed login on ext-web-04 from 203.0.113.140", raw_log="", sim={}, gold_case="E01"),
    dict(alert_id="AL-E02", ts="2026-10-03T21:10:00", rule="Failed login", host="dev-build-02", user="r.khan", src_ip="10.20.4.12",
         summary="1 failed login for r.khan on dev-build-02 from 10.20.4.12", raw_log="", sim={}, gold_case="E02"),
]
alerts += [a for a in new_alerts if a["alert_id"] not in have]
save(DATA / "alerts.json", alerts)

history = load(DATA / "history.json", [])
have = {h["history_id"] for h in history}
for i, ts in enumerate(["2026-08-14T01:42:00", "2026-08-29T02:05:00", "2026-09-12T01:30:00", "2026-09-27T02:15:00"], 1):
    if f"HIST-E02-{i:03d}" not in have:
        history.append(dict(history_id=f"HIST-E02-{i:03d}", ts=ts, user="r.khan", host="dev-build-02", rule="Failed login"))
save(DATA / "history.json", history)

save(BENCH / "extension_cases.json", [
    dict(case_id="E01", category="slow_attack", description="Seven failed logins over 15 hours from one external address; only one in the ten-minute window",
         expected=dict(band="medium", escalate=False, deprioritise_allowed=False, features=["slow_failed_logins"], rules_v1_1_would_give="band low, deprioritised list")),
    dict(case_id="E02", category="repeat_pattern", description="One failed login by a privileged user who had the same alert four times in the last two months",
         expected=dict(band="medium", escalate=True, deprioritise_allowed=False, features=["repeat_pattern", "privileged_user"], rules_v1_1_would_give="band low, analyst queue")),
])
print("extension data written:", len(new_events), "events,", len(new_alerts), "alerts, history", len(history))
