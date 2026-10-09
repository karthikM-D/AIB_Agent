"""List the gold sample alerts that have NOT been sent yet in this database (safe to use live)."""
import requests

API = "http://127.0.0.1:8000"
alerts = requests.get(f"{API}/sample-alerts", timeout=30).json()
used = {c["alert_id"] for c in requests.get(f"{API}/cases", timeout=30).json()}
print("Not yet sent:", ", ".join(a["gold_case"] for a in alerts if a["gold_case"] and a["alert_id"] not in used))
print("Already sent:", ", ".join(a["gold_case"] or a["alert_id"] for a in alerts if a["alert_id"] in used))
