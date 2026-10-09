"""Search helpers for the case register and the audit trail (no Streamlit, so they can be tested)."""
import re


def resolve_case(query, rows):
    """Turn what a person types into a case: '1' or 'case-1' or '00001' -> CASE-00001; 'g01', 'G1' or 'AL-G01' -> the case of that alert."""
    q = (query or "").strip().upper()
    if not q:
        return None
    m = re.fullmatch(r"(?:CASE-?)?0*(\d+)", q)
    if m:
        want = f"CASE-{int(m.group(1)):05d}"
        return want if any(r["case_id"] == want for r in rows) else None
    m = re.fullmatch(r"(?:AL-)?([GEB])0*(\d+)", q)
    if m:
        for r in rows:
            code = (r.get("test_code") or "").upper()
            m2 = re.fullmatch(r"([GEB])0*(\d+)", code)
            if m2 and m2.groups() == (m.group(1), m.group(2)):
                return r["case_id"]
    return None


def match_rows(query, rows):
    """Case-insensitive search over every identifying field. A bare number also matches the case number and the G/E/B code with that number."""
    q = (query or "").strip().lower()
    if not q:
        return rows
    hit = resolve_case(query, rows)
    if q.isdigit() or hit:
        num = int(q) if q.isdigit() else None
        out = []
        for r in rows:
            code = (r.get("test_code") or "").lower()
            m = re.fullmatch(r"[geb]0*(\d+)", code)
            if r["case_id"] == hit or (num is not None and (r["case_id"] == f"CASE-{num:05d}" or (m and int(m.group(1)) == num))):
                out.append(r)
        if out:
            return out
    fields = ("case_id", "alert_id", "test_code", "rule", "host", "status", "route", "model", "band", "last_decision", "summary")
    return [r for r in rows if any(q in str(r.get(f) or "").lower() for f in fields)]
