"""Deterministic triage rules: evidence features, additive risk score, band, flags.

This is the transparent baseline (G7: rule-based score floor) that the model may only add caution to.
Pure Python, no model calls, so it is fully testable. Weights live in data/rules.json.
"""
import json
import re
from datetime import datetime, timedelta
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
FMT = "%Y-%m-%dT%H:%M:%S"
HIT = ("malicious", "suspicious")


def load_json(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


class Store:
    """In-memory view of the synthetic data (the API serves the same files in Stage 3c)."""

    def __init__(self, data_dir=None):
        global DATA
        if data_dir:
            DATA = Path(data_dir)
        self.assets = load_json("assets.json")
        self.users = load_json("users.json")
        self.intel = load_json("intel.json")
        self.events = load_json("events.json")
        self.rules = load_json("rules.json")
        self.history = load_json("history.json") if (DATA / "history.json").exists() else []


def band_for(score, bands):
    name = "low"
    for b, floor in sorted(bands.items(), key=lambda kv: kv[1]):
        if score >= floor:
            name = b
    return name


def is_internal(ip):
    return bool(ip) and ip.startswith(("10.", "192.168."))


def window_events(store, alert):
    end = datetime.strptime(alert["ts"], FMT)
    start = end - timedelta(minutes=store.rules["window_minutes"])
    return [e for e in store.events
            if e["host"] == alert["host"] and start <= datetime.strptime(e["ts"], FMT) <= end]


def slow_failed_events(store, alert):
    """Failed logins on the host over the long look-back window (for slow, spaced-out attempts)."""
    end = datetime.strptime(alert["ts"], FMT)
    start = end - timedelta(hours=store.rules.get("slow_window_hours", 24))
    return [e for e in store.events if e["host"] == alert["host"] and e["type"] == "failed_login"
            and start <= datetime.strptime(e["ts"], FMT) <= end]


def history_matches(store, alert):
    """Earlier alerts of the same kind for the same user (or host, if the alert has no user) in the history window."""
    end = datetime.strptime(alert["ts"], FMT)
    start = end - timedelta(days=store.rules.get("history_days", 60))
    out = []
    for h in getattr(store, "history", []):
        when = datetime.strptime(h["ts"], FMT)
        same = (h["user"] == alert["user"]) if alert.get("user") else (h["host"] == alert["host"])
        if same and h["rule"] == alert["rule"] and start <= when < end:
            out.append(h)
    return out


def detect_injection(alert, rules):
    text = f'{alert.get("summary", "")} {alert.get("raw_log", "")}'.lower()
    return [p for p in rules["injection_patterns"] if re.search(p, text)]


def triage(store, alert):
    """Return the rule-based assessment for one alert (a dict, JSON-serialisable)."""
    R, P = store.rules, store.rules["points"]
    sim = alert.get("sim") or {}
    events = window_events(store, alert)
    feats, gaps = [], []

    def add(name, pts, evidence):
        feats.append(dict(feature=name, points=pts, evidence=evidence))

    # --- failed logins and success after failures
    fails = [e for e in events if e["type"] == "failed_login"]
    if len(fails) >= 10:
        add("failed_logins_ge_10", P["failed_logins_ge_10"], [e["event_id"] for e in fails][:5])
    elif len(fails) >= 5:
        add("failed_logins_ge_5", P["failed_logins_ge_5"], [e["event_id"] for e in fails][:5])
    # slow, spaced-out attempts: many failures over the long window from one external address, but fewer than five in the short window
    slow_ids, slow_hit = [], False
    if len(fails) < 5:
        long_fails = slow_failed_events(store, alert)
        per_source = {}
        for e in long_fails:
            if e.get("src_ip") and not is_internal(e["src_ip"]):     # slow guessing from one external address
                per_source.setdefault(e["src_ip"], []).append(e)
        biggest = max(per_source.values(), key=len, default=[])
        if len(biggest) >= R.get("slow_min_failures", 6):
            slow_hit = True
            slow_ids = [e["event_id"] for e in biggest]
            add("slow_failed_logins", P["slow_failed_logins"], slow_ids[:5])
    successes = [e for e in events if e["type"] == "successful_login"]
    indicators = []
    for s in successes:
        prior = [f for f in fails if f["ts"] < s["ts"]]
        if len(prior) >= R["success_after_failures_min_failures"]:
            add("success_after_failures", P["success_after_failures"], [s["event_id"]])
            indicators.append("success_after_failures")
            break

    # --- event types
    for etype, feat in (("privilege_escalation", "privilege_escalation"), ("data_exfiltration", "data_exfiltration"),
                        ("malware_detected", "malware_detected")):
        hit = [e["event_id"] for e in events if e["type"] == etype]
        if hit:
            add(feat, P[feat], hit)
            indicators.append(feat)

    # --- threat intelligence (worst reputation over src IP, destination IPs, file hashes)
    iocs = {alert.get("src_ip")} | {e.get("dest_ip") for e in events} | {e.get("file_hash") for e in events}
    iocs = sorted(i for i in iocs if i and not is_internal(i))
    intel_status, worst = "ok", "none"
    if sim.get("intel") == "timeout":
        intel_status = "unavailable"
        gaps.append("intel_unavailable")
    else:
        for i in iocs:
            rep = store.intel.get(i, {}).get("reputation", "unknown")
            if rep == "malicious" or (rep == "suspicious" and worst != "malicious"):
                worst = rep
        if worst == "malicious":
            add("intel_malicious", P["intel_malicious"], [f"INTEL:{i}" for i in iocs if store.intel.get(i, {}).get("reputation") == "malicious"])
        elif worst == "suspicious":
            add("intel_suspicious", P["intel_suspicious"], [f"INTEL:{i}" for i in iocs if store.intel.get(i, {}).get("reputation") == "suspicious"])

    # --- asset context
    asset, asset_status = store.assets.get(alert["host"]), "ok"
    if sim.get("asset") == "timeout":
        asset, asset_status = None, "unavailable"
        gaps.append("asset_unavailable")
    elif asset is None:
        asset_status = "unknown"
        gaps.append("asset_unknown")
    if asset is None:
        add("asset_unknown_or_unavailable", P["asset_unknown_or_unavailable"], [f"ASSET:{alert['host']}"])
    else:
        crit = asset["criticality"]
        if f"asset_{crit}" in P:
            add(f"asset_{crit}", P[f"asset_{crit}"], [f"ASSET:{alert['host']}"])
        if asset["environment"] == "production":
            add("production_environment", P["production_environment"], [f"ASSET:{alert['host']}"])

    # --- user context
    user = store.users.get(alert.get("user") or "")
    if user:
        if user["privileged"]:
            add("privileged_user", P["privileged_user"], [f"USER:{alert['user']}"])
        if user["status"] in ("on_leave", "terminated"):
            add("inactive_user", P["inactive_user"], [f"USER:{alert['user']}"])
            if successes:
                indicators.append("inactive_user_login")

    # --- repeated pattern over weeks on a privileged user or critical asset
    hist = history_matches(store, alert)
    repeat_hit = bool((user and user["privileged"]) or (asset and asset["criticality"] == "critical")) and len(hist) >= R.get("repeat_min_prior", 3)
    if repeat_hit:
        add("repeat_pattern", P["repeat_pattern"], [h["history_id"] for h in hist][:5])

    score = min(R["score_cap"], sum(f["points"] for f in feats))
    band = band_for(score, R["bands"])

    # --- flags
    rr = R["reportable_requires"]
    on_prod = bool(asset) and asset["environment"] == rr["environment"]
    reportable = bool(on_prod and (
        (set(indicators) & set(R["compromise_indicators"])
         and (asset["criticality"] in rr["criticality_in"] or asset["data_class"] in rr["data_class_in"]))
        or set(indicators) & set(R["reportable_any_production"])))
    injection = detect_injection(alert, R)
    never = []
    if asset and asset["criticality"] == "critical":
        never.append("critical_asset")
    if worst in HIT:
        never.append("intel_hit")
    if user and user["privileged"]:
        never.append("privileged_user")
    if reportable:
        never.append("possibly_reportable")
    if injection:
        never.append("injection_suspected")
    if gaps:
        never.append("tool_or_data_gap")
    if slow_hit:
        never.append("slow_pattern")
    if repeat_hit:
        never.append("repeat_pattern")
    escalate_reasons = []
    if band in ("high", "critical"):
        escalate_reasons.append("band_high_or_critical")
    if reportable:
        escalate_reasons.append("possibly_reportable")
    if injection:
        escalate_reasons.append("injection_suspected")
    if repeat_hit:
        escalate_reasons.append("repeat_pattern")
    return dict(
        alert_id=alert["alert_id"], score=score, raw_score=sum(f["points"] for f in feats), band=band, features=feats,
        indicators=sorted(set(indicators)), reportable=reportable, injection=bool(injection), injection_patterns=injection,
        gaps=gaps, intel_status=intel_status, asset_status=asset_status, never_deprioritise=never,
        escalate=bool(escalate_reasons), escalate_reasons=escalate_reasons,
        deprioritise_allowed=(band == "low" and not never and not escalate_reasons),
        failed_login_count=len(fails), event_ids=[e["event_id"] for e in events], rules_version=R["version"],
        slow_pattern=slow_hit, repeat_pattern=repeat_hit,
        extended_ids=(slow_ids if slow_hit else []) + ([h["history_id"] for h in hist] if repeat_hit else []))
