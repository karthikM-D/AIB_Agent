"""SQLite store: cases, agent steps, human decisions, lists, spot-checks and an append-only audit log (G18).

Every mutating function writes an audit row. UPDATE and DELETE on audit_log are blocked by triggers.
Runtime state lives in data/soc.db (git-ignored); evaluation runs use their own database file.
"""
import json
import random
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path

FMT = "%Y-%m-%dT%H:%M:%S"
DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "soc.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY, alert_id TEXT UNIQUE, alert_json TEXT, masked_json TEXT, mapping_json TEXT,
  assessment_json TEXT, status TEXT, band TEXT, score INTEGER, route_json TEXT, created_at TEXT, updated_at TEXT, resume_url TEXT);
CREATE TABLE IF NOT EXISTS steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, agent TEXT, attempt INTEGER, model TEXT, prompt_version TEXT,
  output_json TEXT, problems_json TEXT, latency_ms INTEGER, ts TEXT);
CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, actor TEXT, decision TEXT, reason TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS lists (
  case_id TEXT PRIMARY KEY, list_type TEXT, reasons_json TEXT, state TEXT, added_at TEXT, closed_at TEXT);
CREATE TABLE IF NOT EXISTS spotchecks (
  id INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT, case_id TEXT, sample_type TEXT, verdict TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, case_id TEXT, actor TEXT, event TEXT, detail_json TEXT);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""


def now_iso(now=None):
    return now or datetime.now().strftime(FMT)


class Pool:
    """One SQLite connection per thread (FastAPI runs sync endpoints in a thread pool; n8n calls arrive concurrently)."""

    def __init__(self, path):
        self.path, self.local = str(path), threading.local()

    def _conn(self):
        c = getattr(self.local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA busy_timeout=30000")
            self.local.conn = c
        return c

    def __getattr__(self, name):
        return getattr(self._conn(), name)


_ID_LOCK = threading.Lock()


def connect(path=None):
    conn = Pool(path or DEFAULT_DB)
    conn.executescript(SCHEMA)
    try:                                # databases created before resume_url existed
        conn.execute("ALTER TABLE cases ADD COLUMN resume_url TEXT")
    except sqlite3.OperationalError:
        pass
    return conn


def audit(conn, case_id, actor, event, detail=None, now=None):
    conn.execute("INSERT INTO audit_log (ts, case_id, actor, event, detail_json) VALUES (?,?,?,?,?)",
                 (now_iso(now), case_id, actor, event, json.dumps(detail or {})))
    conn.commit()


def row(r):
    return dict(r) if r else None


def create_case(conn, alert, now=None):
    with _ID_LOCK:                      # case IDs are assigned one at a time
        existing = conn.execute("SELECT * FROM cases WHERE alert_id=?", (alert["alert_id"],)).fetchone()
        if existing:
            return row(existing), True
        n = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0] + 1
        case_id = f"CASE-{n:05d}"
        t = now_iso(now)
        conn.execute("INSERT INTO cases (case_id, alert_id, alert_json, status, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                     (case_id, alert["alert_id"], json.dumps(alert), "received", t, t))
        conn.commit()
    audit(conn, case_id, "system", "alert_received", {"alert_id": alert["alert_id"]}, now)
    return row(conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()), False


def get_case(conn, case_id):
    return row(conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone())


def update_case(conn, case_id, actor="system", event="case_updated", now=None, **fields):
    t = now_iso(now)
    cols = ", ".join(f"{k}=?" for k in fields) + (", " if fields else "") + "updated_at=?"
    conn.execute(f"UPDATE cases SET {cols} WHERE case_id=?", (*fields.values(), t, case_id))
    audit(conn, case_id, actor, event, {k: v for k, v in fields.items() if k.endswith("_json") is False}, now)


def add_step(conn, case_id, agent, attempt, model, prompt_version, output, problems, latency_ms=0, now=None):
    conn.execute("INSERT INTO steps (case_id, agent, attempt, model, prompt_version, output_json, problems_json, latency_ms, ts) VALUES (?,?,?,?,?,?,?,?,?)",
                 (case_id, agent, attempt, model, prompt_version, json.dumps(output), json.dumps(problems), latency_ms, now_iso(now)))
    audit(conn, case_id, f"agent:{agent}", "agent_step", {"attempt": attempt, "model": model, "prompt_version": prompt_version,
                                                          "problems": problems, "latency_ms": latency_ms}, now)


def add_decision(conn, case_id, actor, decision, reason, now=None):
    if not (reason or "").strip():
        raise ValueError("a reason is required for every human decision")
    conn.execute("INSERT INTO decisions (case_id, actor, decision, reason, ts) VALUES (?,?,?,?,?)",
                 (case_id, actor, decision, reason.strip(), now_iso(now)))
    audit(conn, case_id, actor, f"decision:{decision}", {"reason": reason.strip()}, now)


def add_to_list(conn, case_id, list_type, reasons, now=None):
    conn.execute("INSERT OR REPLACE INTO lists (case_id, list_type, reasons_json, state, added_at) VALUES (?,?,?,?,?)",
                 (case_id, list_type, json.dumps(reasons), "saved", now_iso(now)))
    audit(conn, case_id, "system", f"added_to_{list_type}", {"reasons": reasons}, now)


def list_items(conn, list_type=None, state=None):
    q, args = "SELECT l.*, c.band, c.score, c.alert_id FROM lists l JOIN cases c USING(case_id) WHERE 1=1", []
    if list_type:
        q += " AND l.list_type=?"; args.append(list_type)
    if state:
        q += " AND l.state=?"; args.append(state)
    return [row(r) for r in conn.execute(q + " ORDER BY c.score DESC, l.added_at", args)]


def promote(conn, case_id, actor, reason, now=None):
    """Analyst promotes a deprioritised alert to the queue; counted for the promotion rate."""
    conn.execute("UPDATE lists SET state='promoted', closed_at=? WHERE case_id=?", (now_iso(now), case_id))
    update_case(conn, case_id, actor, "promoted_to_queue", now, status="queued")
    add_decision(conn, case_id, actor, "promote", reason or "promoted after review", now)


def make_spotcheck_sample(conn, n_random=3, n_borderline=2, seed=None, now=None):
    items = list_items(conn, "deprioritised", "saved")
    batch = f"SC-{now_iso(now).replace(':', '').replace('-', '')}"
    border = items[:n_borderline]
    rest = [i for i in items if i not in border]
    rnd = random.Random(seed)
    rand = rnd.sample(rest, min(n_random, len(rest)))
    sample = [(i["case_id"], "borderline") for i in border] + [(i["case_id"], "random") for i in rand]
    for cid, kind in sample:
        conn.execute("INSERT INTO spotchecks (batch_id, case_id, sample_type, verdict, ts) VALUES (?,?,?,?,?)", (batch, cid, kind, None, now_iso(now)))
    conn.commit()
    audit(conn, None, "system", "spotcheck_sample_created", {"batch": batch, "cases": [c for c, _ in sample]}, now)
    return batch, sample


def record_verdict(conn, batch_id, case_id, verdict, actor, now=None):
    conn.execute("UPDATE spotchecks SET verdict=?, ts=? WHERE batch_id=? AND case_id=?", (verdict, now_iso(now), batch_id, case_id))
    conn.commit()
    audit(conn, case_id, actor, f"spotcheck_{verdict}", {"batch": batch_id}, now)
    if verdict == "disagree":
        promote(conn, case_id, actor, "spot-check disagreed with deprioritisation", now)


def spotcheck_complete(conn, batch_id):
    rows = conn.execute("SELECT verdict FROM spotchecks WHERE batch_id=?", (batch_id,)).fetchall()
    return bool(rows) and all(r["verdict"] for r in rows)


def bulk_confirm(conn, batch_id, actor, now=None):
    if not spotcheck_complete(conn, batch_id):
        raise PermissionError("spot-check sample must be fully reviewed before bulk confirmation")
    ids = [i["case_id"] for i in list_items(conn, "deprioritised", "saved")]
    for cid in ids:
        conn.execute("UPDATE lists SET state='confirmed', closed_at=? WHERE case_id=?", (now_iso(now), cid))
        update_case(conn, cid, actor, "bulk_confirmed", now, status="closed_deprioritised")
    audit(conn, None, actor, "bulk_confirm", {"batch": batch_id, "count": len(ids)}, now)
    return ids


def autoclose_due(conn, days, now=None):
    """G16: saved deprioritised alerts untouched after N days are closed; returns the ids for the lead's notice."""
    cutoff = (datetime.strptime(now_iso(now), FMT) - timedelta(days=days)).strftime(FMT)
    due = [r["case_id"] for r in conn.execute("SELECT case_id FROM lists WHERE list_type='deprioritised' AND state='saved' AND added_at<=?", (cutoff,))]
    for cid in due:
        conn.execute("UPDATE lists SET state='auto_closed', closed_at=? WHERE case_id=?", (now_iso(now), cid))
        update_case(conn, cid, "system", "auto_closed", now, status="auto_closed")
    if due:
        audit(conn, None, "system", "lead_notice", {"auto_closed": due, "days": days}, now)
    return due


def queue(conn):
    order = "CASE band WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, score DESC, created_at"
    return [row(r) for r in conn.execute(f"SELECT * FROM cases WHERE status='queued' ORDER BY {order}")]


def analytics(conn):
    total = conn.execute("SELECT COUNT(*) FROM lists WHERE list_type='deprioritised'").fetchone()[0]
    promoted = conn.execute("SELECT COUNT(*) FROM lists WHERE list_type='deprioritised' AND state='promoted'").fetchone()[0]
    by_status = {r["status"]: r["n"] for r in conn.execute("SELECT status, COUNT(*) n FROM cases GROUP BY status")}
    return dict(deprioritised_total=total, promoted=promoted, promotion_rate=(promoted / total if total else None), cases_by_status=by_status)
