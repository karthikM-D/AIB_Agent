"""Orchestration of the five agents: shared building blocks plus a reference pipeline.

The building blocks (prepare_context, build_payload, extra_checks) are used by the FastAPI service that the n8n workflow
calls and by run_pipeline, the all-Python reference used by the evaluation harness (3g) and by tests with a fake model.
Flow: mask and score (code) -> Correlation -> Threat Intelligence -> Asset Context -> Risk (three runs) -> code checks on
every output (retry once) -> routing decision -> Summary. Models only see masked data; every output is validated.
"""
from app import checks, masking, prompts, rules
from app.llm import BASE_SEED

AGENT_ORDER = ["correlation", "intel", "asset", "risk", "summary"]
STRONG_ACTIONS = {"propose_account_disable", "propose_host_isolation", "propose_ip_block", "propose_credential_reset", "propose_password_reset"}


def intel_lookups(store, alert, events):
    """Deterministic tool call. Returns a list of records, or None if the source is unavailable."""
    if (alert.get("sim") or {}).get("intel") == "timeout":
        return None
    iocs = {alert.get("src_ip")} | {e.get("dest_ip") for e in events} | {e.get("file_hash") for e in events}
    out = []
    for i in sorted(x for x in iocs if x and not rules.is_internal(x)):
        rec = store.intel.get(i, {"reputation": "unknown", "score": None, "reports": 0, "tags": []})
        out.append(dict(indicator=i, evidence_id=f"INTEL:{i}", **rec))
    return out


def clean_alert(a):
    return {k: a[k] for k in ("alert_id", "ts", "rule", "host", "user", "src_ip", "summary", "raw_log")}


def prepare_context(store, alert):
    """Everything derived from the alert by code: rule assessment, masked data, lookups, allowed evidence IDs."""
    assessment = rules.triage(store, alert)
    events = rules.window_events(store, alert)
    masked, mapping = masking.mask_case(
        alert, events,
        {alert["host"]: store.assets[alert["host"]]} if assessment["asset_status"] == "ok" else {},
        {alert["user"]: store.users[alert["user"]]} if alert.get("user") in store.users else {})
    m_assessment = masking.mask_assessment(assessment, mapping, masked)
    lookups = intel_lookups(store, alert, events)
    allowed = checks.allowed_evidence_ids(m_assessment) | {l["evidence_id"] for l in (lookups or [])}
    extended = extended_evidence(store, alert, assessment, mapping)
    return dict(assessment=assessment, events=events, masked=masked, mapping=mapping, m_assessment=m_assessment, lookups=lookups, extended=extended,
                allowed=allowed, check_ctx=dict(intel_unavailable=lookups is None, asset_status=assessment["asset_status"], rule_band=assessment["band"]))


def extended_evidence(store, alert, assessment, mapping):
    """Evidence outside the ten-minute window that supports a rule feature (slow attempts, repeated history), masked. Empty for most alerts."""
    out = {}
    if assessment.get("slow_pattern"):
        ids = set(assessment["extended_ids"])
        out["slow_failed_logins"] = [{k: e[k] for k in ("event_id", "ts", "type", "src_ip", "details")}
                                     for e in rules.slow_failed_events(store, alert) if e["event_id"] in ids]
    if assessment.get("repeat_pattern"):
        users, hosts = mapping.get("users", {}), mapping.get("hosts", {})
        out["history"] = [{"history_id": h["history_id"], "ts": h["ts"], "rule": h["rule"], "user": users.get(h["user"], "USER-X"),
                           "host": hosts.get(h["host"], "HOST-X")} for h in rules.history_matches(store, alert)]
    return out


def build_payload(agent, c, outputs, rules_cfg, final=None):
    """The INPUT object an agent receives. `outputs` holds the earlier agents' validated outputs (risk: a list under 'risk_outputs')."""
    m_alert, m_events = clean_alert(c["masked"]["alert"]), c["masked"]["events"]
    if agent == "correlation":
        return {"ALERT": m_alert, "EVENTS": [{k: e[k] for k in ("event_id", "ts", "type", "user", "src_ip", "dest_ip", "file_hash", "details")} for e in m_events]}
    if agent == "intel":
        return {"LOOKUPS": c["lookups"] if c["lookups"] is not None else "unavailable"}
    if agent == "asset":
        host, user = list(c["masked"].get("assets", {}).items()), list(c["masked"].get("users", {}).items())
        return {"ASSET": (dict(host[0][1], id=f"ASSET:{host[0][0]}") if host else c["assessment"]["asset_status"]),
                "USER": (dict(user[0][1], id=f"USER:{user[0][0]}") if user else "none")}
    base = {"ALERT": m_alert, "CORRELATION": outputs.get("correlation"), "INTELLIGENCE": outputs.get("intel"), "ASSET_CONTEXT": outputs.get("asset")}
    if agent == "risk":
        ma = c["m_assessment"]
        payload = base | {"RULE_ASSESSMENT": {k: ma[k] for k in ("score", "band", "features", "indicators", "gaps")} | {"possibly_reportable": c["assessment"]["reportable"]},
                          "ALLOWED_ACTIONS": rules_cfg["allowed_actions"]}
        if c.get("extended"):                       # only alerts that trigger a v1.2 feature get this extra section
            payload["EXTENDED_EVIDENCE"] = c["extended"]
        return payload
    risk_outputs = outputs.get("risk_outputs") or []
    return base | {"RISK": risk_outputs[0] if risk_outputs else None,
                   "FINAL": {"band": final["band"], "escalate": final["escalate"], "escalate_reasons": final["escalate_reasons"]}}


def extra_checks(agent, out, ctx):
    """Code-level consistency checks that go beyond the schema."""
    problems = []
    if agent == "intel":
        if ctx["intel_unavailable"] and out.get("unavailable") is not True:
            problems.append("intel_status_mismatch: lookup was unavailable")
        if not ctx["intel_unavailable"] and out.get("unavailable") is True:
            problems.append("intel_status_mismatch: lookup was available")
    if agent == "risk":
        jump = checks.BANDS.index(out.get("band", "low")) - checks.BANDS.index(ctx["rule_band"])
        if jump > 1:
            problems.append(f"band_raise_over_one_level: {ctx['rule_band']} -> {out['band']}")
        if out.get("recommended_action") in STRONG_ACTIONS and checks.BANDS.index(out["band"]) < checks.BANDS.index("high"):
            problems.append(f"action_too_strong_for_band: {out['recommended_action']} at {out['band']}")
    if agent == "asset" and ctx["asset_status"] != "ok" and out.get("host_criticality") not in ("unknown",):
        problems.append("asset_status_mismatch: asset record was not available")
    return problems


def validate(agent, out, c, rules_cfg):
    """All code checks for one agent output (schema, citations, allow-list, consistency). Empty list = passed."""
    problems = checks.check_output(agent, out, c["allowed"], rules_cfg)
    return problems if problems and problems[0].startswith("schema") else problems + extra_checks(agent, out, c["check_ctx"])


def run_agent(llm, model, agent, payload, c, rules_cfg, seed, steps):
    """Run one agent with up to 1 + retry_limit attempts. Returns (output or None, failed_attempts)."""
    system, user = prompts.system_prompt(agent), prompts.user_prompt(payload)
    failed = 0
    for attempt in range(1, rules_cfg["retry_limit"] + 2):
        s = seed + (attempt - 1) * 1000
        res = llm(model, system, user, checks.SCHEMAS[agent], s)
        problems = [res["error"] or "no_output"] if res["output"] is None else validate(agent, res["output"], c, rules_cfg)
        steps.append(dict(agent=agent, attempt=attempt, seed=s, model=model, prompt_version=prompts.PROMPT_VERSION, problems=problems,
                          latency_ms=res["latency_ms"], tokens=res["tokens"], output=res["output"], raw=res["raw"]))
        if not problems:
            return res["output"], failed
        failed += 1
    return None, failed


def run_pipeline(store, alert, llm, model, runs=3, base_seed=BASE_SEED):
    R = store.rules
    c = prepare_context(store, alert)
    steps, outputs, failed_by_agent = [], {}, {}

    def go(agent, seed, final=None):
        out, failed = run_agent(llm, model, agent, build_payload(agent, c, outputs, R, final), c, R, seed, steps)
        failed_by_agent[agent] = failed
        return out

    for agent in ("correlation", "intel", "asset"):
        outputs[agent] = go(agent, base_seed)
    risk_outputs, risk_failed = [], 0
    for k in range(runs):
        out = go("risk", base_seed + 100 * k)
        risk_failed = max(risk_failed, failed_by_agent["risk"])
        if out is not None:
            risk_outputs.append(out)
    outputs["risk_outputs"] = risk_outputs
    failed_checks = max(risk_failed, *(failed_by_agent[a] for a in ("correlation", "intel", "asset")))
    if len(risk_outputs) < min(2, runs):
        failed_checks = max(failed_checks, R["retry_limit"] + 1)
    final = checks.final_decision(c["assessment"], risk_outputs, R, failed_checks)
    outputs["summary"] = go("summary", base_seed, final)
    route = "escalation" if final["escalate"] else "deprioritised_list" if final["deprioritise_allowed"] else "analyst_queue"
    return dict(alert_id=alert["alert_id"], model=model, prompt_version=prompts.PROMPT_VERSION, assessment=c["assessment"], final=final, route=route,
                steps=steps, outputs=outputs, risk_outputs=risk_outputs, failed_checks=failed_checks, mapping=c["mapping"],
                latency_ms=sum(s["latency_ms"] for s in steps), tokens=sum(s["tokens"] for s in steps))
