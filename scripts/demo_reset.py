"""Reset the demo to empty: delete the case database and n8n's execution history. Stop the API and n8n first.
Usage: python scripts/demo_reset.py
"""
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for name in ("soc.db", "soc.db-wal", "soc.db-shm"):
    (ROOT / "data" / name).unlink(missing_ok=True)
db = ROOT / "n8n" / "data" / ".n8n" / "database.sqlite"
if db.exists():
    c = sqlite3.connect(db)
    for t in ("execution_data", "execution_metadata", "execution_annotations", "execution_entity"):
        try:
            c.execute(f"delete from {t}")
        except sqlite3.Error:
            pass
    c.commit()
    print("n8n executions left:", c.execute("select count(*) from execution_entity").fetchone()[0])
print("Demo reset: case database deleted.")
