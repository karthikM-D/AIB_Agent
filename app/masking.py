"""G1: mask sensitive fields before any model sees them.

Users and hosts become stable pseudonyms (USER-01, HOST-01) with a per-case mapping kept by the orchestrator,
so the UI can show real names while models never do. Secrets, e-mail addresses and card numbers are redacted.
IP addresses are kept because the threat-intelligence lookup needs them (the PoC uses reserved documentation
ranges, so no real address is involved).
"""
import re

SECRET_PATTERNS = [
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s*[=:]\s*\S+"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+[a-z0-9._\-]{10,}"), "Bearer [REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-KEY]"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[EMAIL]"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[CARD]"),
]


class Pseudonymiser:
    def __init__(self):
        self.users, self.hosts = {}, {}

    def user(self, name):
        if not name:
            return name
        return self.users.setdefault(name, f"USER-{len(self.users) + 1:02d}")

    def host(self, name):
        if not name:
            return name
        return self.hosts.setdefault(name, f"HOST-{len(self.hosts) + 1:02d}")

    def mapping(self):
        return {"users": dict(self.users), "hosts": dict(self.hosts)}

    def reverse(self):
        return {v: k for d in (self.users, self.hosts) for k, v in d.items()}


def redact(text):
    for pat, rep in SECRET_PATTERNS:
        text = pat.sub(rep, text or "")
    return text


def mask_text(text, ps):
    text = redact(text)
    for name in sorted(list(ps.users) + list(ps.hosts), key=len, reverse=True):
        alias = ps.users.get(name) or ps.hosts.get(name)
        text = re.sub(rf"(?<![\w-]){re.escape(name)}(?![\w-])", alias, text)
    return text


def mask_case(alert, events, assets=None, users=None, ps=None):
    """Mask an alert, its events and (optional) asset and user records. Returns (masked dict, mapping)."""
    ps = ps or Pseudonymiser()
    ps.host(alert.get("host"))
    ps.user(alert.get("user"))
    for e in events:
        ps.host(e.get("host"))
        ps.user(e.get("user"))
    m_alert = dict(alert)
    m_alert["host"], m_alert["user"] = ps.host(alert.get("host")), ps.user(alert.get("user"))
    m_alert["summary"] = mask_text(alert.get("summary", ""), ps)
    m_alert["raw_log"] = mask_text(alert.get("raw_log", ""), ps)
    m_events = []
    for e in events:
        me = dict(e)
        me["host"], me["user"] = ps.host(e.get("host")), ps.user(e.get("user"))
        me["details"] = mask_text(e.get("details", ""), ps)
        m_events.append(me)
    out = dict(alert=m_alert, events=m_events)
    if assets is not None:
        out["assets"] = {ps.host(h): {k: v for k, v in a.items() if k != "owner"} for h, a in assets.items()}
    if users is not None:
        out["users"] = {ps.user(u): {k: v for k, v in rec.items() if k != "department"} for u, rec in users.items()}
    return out, ps.mapping()


def mask_assessment(assessment, mapping, masked_case=None):
    """Rewrite ASSET:/USER: evidence IDs in a rule assessment so no real host or user name reaches a model."""
    def one(s):
        if s.startswith("ASSET:"):
            return "ASSET:" + mapping["hosts"].get(s[6:], s[6:])
        if s.startswith("USER:"):
            return "USER:" + mapping["users"].get(s[5:], s[5:])
        return s
    out = dict(assessment)
    out["features"] = [dict(f, evidence=[one(e) for e in f["evidence"]]) for f in assessment["features"]]
    if masked_case is not None:       # IDs of the asset and user records shown to the models are citable
        out["extra_ids"] = [f"ASSET:{h}" for h in masked_case.get("assets", {})] + [f"USER:{u}" for u in masked_case.get("users", {})]
    return out
