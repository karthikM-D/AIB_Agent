"""Send one sample alert to n8n, for the live demo.

Usage:
  python scripts/demo_send_live.py G10                 # production webhook: run is visible in Executions after it ends
  python scripts/demo_send_live.py G10 --test          # test webhook: the editor canvas animates live (click 'Execute workflow' in the editor first)
Options: --model llama|qwen|mistral (default llama). Each sample alert can be sent only once (duplicates stop at once).
"""
import argparse
import time

import requests

API = "http://127.0.0.1:8000"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("case")
    ap.add_argument("--model", default="llama")
    ap.add_argument("--test", action="store_true")
    a = ap.parse_args()
    alerts = {x["gold_case"] or x["alert_id"].replace("AL-", ""): x for x in requests.get(f"{API}/sample-alerts", timeout=30).json()}
    url = "http://127.0.0.1:5678/" + ("webhook-test" if a.test else "webhook") + "/soc-triage"
    r = requests.post(url, json={"alert": alerts[a.case], "model": a.model}, timeout=60)
    print(r.status_code, r.text[:200])
    if r.ok and not a.test:
        print("Sent. Watch the website Live trace; the n8n run appears in Executions and finishes at the Wait box.")


if __name__ == "__main__":
    main()
