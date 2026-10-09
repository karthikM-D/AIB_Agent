"""Pre-load the demo: send the chosen gold cases through the real n8n workflow, one after another, and wait for each to finish.

Usage: python scripts/demo_preload.py [--model llama] [--cases G01,G02,G03,G04,G14,G13,G06,G07]
Leaves G09 (the live high-risk case) for the presenter. Each case takes about a minute with Llama on the demo laptop.
Cases that wait for a human (queue or escalation) stay in the Wait state on purpose: the presenter decides them live.
"""
import argparse
import time

import requests

API = "http://127.0.0.1:8000"
N8N = "http://127.0.0.1:5678/webhook/soc-triage"
DONE = ("deprioritised", "queued", "escalated")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="llama")
    ap.add_argument("--cases", default="G01,G02,G03,G04,G14,G13,G06,G07")
    args = ap.parse_args()
    alerts = {}
    for a in requests.get(f"{API}/sample-alerts", timeout=30).json():
        alerts[a["gold_case"] or a["alert_id"].replace("AL-", "")] = a        # G01.. for gold cases, B001.. for background alerts
    for cid in args.cases.split(","):
        t = time.time()
        r = requests.post(N8N, json={"alert": alerts[cid], "model": args.model}, timeout=60).json()
        case = r["case_id"]
        while time.time() - t < 400:
            c = requests.get(f"{API}/cases/{case}", timeout=30).json()
            steps = [s for s in c["steps"] if s["agent"] == "summary" and s["problems_json"] == "[]"]
            if c["status"] in DONE and steps:
                break
            time.sleep(5)
        print(f"{cid} -> {case}: {c['status']} ({time.time() - t:.0f}s)", flush=True)


if __name__ == "__main__":
    main()
