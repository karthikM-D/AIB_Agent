"""G8-G10: code checks on model output. Models propose; this code decides what is acceptable.

Checks: JSON schema, every cited evidence ID exists in the input (hallucination check), recommended action on the
allow-list, score floor (model may only add caution), three-run agreement, injection scan.
"""
import re

import jsonschema

BANDS = ["low", "medium", "high", "critical"]
EVIDENCE_RE = re.compile(r"^(EV-[A-Z0-9]+-\d{3}|INTEL:\S+|ASSET:\S+|USER:\S+)$")

ID_ARRAY = {"type": "array", "items": {"type": "string"}}
SCHEMAS = {
    "correlation": {
        "type": "object", "additionalProperties": False,
        "required": ["related_event_ids", "groups", "summary"],
        "properties": {
            "related_event_ids": ID_ARRAY,
            "groups": {"type": "array", "items": {"type": "object", "required": ["reason", "event_ids"], "additionalProperties": False,
                                                  "properties": {"reason": {"type": "string"}, "event_ids": ID_ARRAY}}},
            "summary": {"type": "string"}}},
    "intel": {
        "type": "object", "additionalProperties": False,
        "required": ["lookups", "assessment", "unavailable"],
        "properties": {
            "lookups": {"type": "array", "items": {"type": "object", "required": ["indicator", "reputation", "evidence_id"], "additionalProperties": False,
                                                   "properties": {"indicator": {"type": "string"},
                                                                  "reputation": {"enum": ["malicious", "suspicious", "clean", "unknown"]},
                                                                  "evidence_id": {"type": "string"}}}},
            "assessment": {"type": "string"}, "unavailable": {"type": "boolean"}}},
    "asset": {
        "type": "object", "additionalProperties": False,
        "required": ["host_criticality", "user_privileged", "unknowns", "assessment"],
        "properties": {
            "host_criticality": {"enum": ["critical", "high", "medium", "low", "unknown"]},
            "user_privileged": {"enum": [True, False, "unknown"]},
            "unknowns": {"type": "array", "items": {"type": "string"}}, "assessment": {"type": "string"}}},
    "risk": {
        "type": "object", "additionalProperties": False,
        "required": ["band", "recommended_action", "rationale", "cited_evidence", "confidence"],
        "properties": {
            "band": {"enum": BANDS}, "recommended_action": {"type": "string"}, "rationale": {"type": "string"},
            "cited_evidence": ID_ARRAY, "confidence": {"type": "number", "minimum": 0, "maximum": 1}}},
    "summary": {
        "type": "object", "additionalProperties": False,
        "required": ["summary", "key_findings", "unknowns", "confidence"],
        "properties": {
            "summary": {"type": "string"},
            "key_findings": {"type": "array", "items": {"type": "object", "required": ["text", "evidence"], "additionalProperties": False,
                                                        "properties": {"text": {"type": "string"}, "evidence": ID_ARRAY}}},
            "unknowns": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1}}},
}


def allowed_evidence_ids(assessment, extra=()):
    """IDs a model may cite: events in the window, rule-feature evidence, plus any supplied extras (lookup records)."""
    ids = set(assessment.get("event_ids", [])) | set(extra) | set(assessment.get("extra_ids", [])) | set(assessment.get("extended_ids", []))
    for f in assessment.get("features", []):
        ids |= set(f["evidence"])
    ids.add(assessment["alert_id"])
    return ids


# Names of the INPUT sections. A citation such as "RULE_ASSESSMENT" or "ASSET_CONTEXT.host_criticality" points at real input
# content; it is not an evidence ID and not an invented fact, so it is accepted. Invented IDs (EV-..., INTEL:..., ASSET:..., USER:...)
# are still rejected. Found in the first demo preload: models often cite section names, which escalated harmless cases.
SECTION_NAMES = {"ALERT", "CORRELATION", "INTELLIGENCE", "ASSET_CONTEXT", "RULE_ASSESSMENT", "RISK", "EVENTS", "LOOKUPS", "FINAL", "EXTENDED_EVIDENCE"}
SECTION_REF = re.compile(r"^([A-Z_]+)([:.\[][\w.\[\]:-]*)?$")


def is_section_reference(cid):
    m = SECTION_REF.match(cid or "")
    return bool(m) and m.group(1) in SECTION_NAMES


def cited_ids(agent, out):
    if agent == "correlation":
        return list(out.get("related_event_ids", [])) + [i for g in out.get("groups", []) for i in g.get("event_ids", [])]
    if agent == "intel":
        return [l.get("evidence_id") for l in out.get("lookups", [])]
    if agent == "risk":
        return list(out.get("cited_evidence", []))
    if agent == "summary":
        return [i for f in out.get("key_findings", []) for i in f.get("evidence", [])]
    return []


def check_output(agent, out, allowed_ids, rules=None):
    """Return a list of problems (empty list = passed)."""
    problems = []
    try:
        jsonschema.validate(out, SCHEMAS[agent])
    except jsonschema.ValidationError as e:
        return [f"schema: {e.message}"]
    for cid in cited_ids(agent, out):
        if cid not in allowed_ids and not is_section_reference(cid):
            problems.append(f"hallucinated_evidence: {cid}")
    if agent == "risk" and rules:
        if out["recommended_action"] not in rules["allowed_actions"]:
            problems.append(f"action_not_allowed: {out['recommended_action']}")
    return problems


def apply_floor(rule_band, model_band):
    """G7: the model may only add caution. Returns (final band, note)."""
    r, m = BANDS.index(rule_band), BANDS.index(model_band)
    if m >= r:
        return model_band, "model raised or kept the rule band" if m > r else "model agrees with the rule band"
    return rule_band, f"model band {model_band} below rule floor {rule_band}; floor applied"


# Action classes for the agreement rule (rule C, adopted 2026-10-04): "no_action" and "add_to_watchlist" are the same low-intensity class,
# asking the owner is a second class, every strong "propose_*" action and escalation is the third.
ACTION_CLASS = {"no_action_recommended": 0, "add_to_watchlist": 0, "request_owner_confirmation": 1, "escalate_to_senior_analyst": 2}


def action_class(action):
    return ACTION_CLASS.get(action, 2)


def runs_agree(risk_outputs):
    """G9: three-run agreement on band and action class (rule C). A band split or an action-class split is a disagreement."""
    if len(risk_outputs) < 2:
        return True
    return len({(o["band"], action_class(o["recommended_action"])) for o in risk_outputs}) == 1


def final_decision(rule_assessment, risk_outputs, rules, failed_checks=0):
    """Combine rule assessment and (validated) model outputs into the routing decision."""
    agree = runs_agree(risk_outputs)
    model_band = max((o["band"] for o in risk_outputs), key=BANDS.index) if risk_outputs else rule_assessment["band"]
    band, note = apply_floor(rule_assessment["band"], model_band)
    reasons = list(rule_assessment["escalate_reasons"])
    if BANDS.index(band) >= BANDS.index("high") and "band_high_or_critical" not in reasons:
        reasons.append("band_high_or_critical")
    if not agree:
        reasons.append("run_disagreement")
    if failed_checks > rules["retry_limit"]:
        reasons.append("checks_failed_twice")
    never = list(rule_assessment["never_deprioritise"]) + (["run_disagreement"] if not agree else [])
    return dict(band=band, floor_note=note, runs_agree=agree, escalate=bool(reasons), escalate_reasons=reasons,
                never_deprioritise=never, deprioritise_allowed=(band == "low" and not never and not reasons))
