"""Evaluation harness (3g): run the full pipeline for model x case x repeat and save every run. Resumable.

Usage:
  python scripts/stage3_evaluate.py --tag quick --models llama,qwen,mistral --cases G01,G07,G09,G13 --repeats 1
  python scripts/stage3_evaluate.py --tag full  --models llama,qwen,mistral --cases all --repeats 3
Each run is saved to benchmark/results/<tag>/<model>_<case>_r<rep>.json (steps, raw outputs, seeds, latency). A run that
already exists is skipped, so an interrupted overnight run continues where it stopped. Identical prompts, data and
settings for every model (app/llm.py); only the model name and the repeat's base seed change.
"""
import argparse
import json
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import agents  # noqa: E402
from app.llm import ollama_chat  # noqa: E402
from app.rules import Store  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="quick")
    ap.add_argument("--models", default="llama,qwen,mistral")
    ap.add_argument("--cases", default="G01,G07,G09,G13")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--gold-file", default="gold_cases.json", help="benchmark file with the cases (extension_cases.json for E01, E02)")
    args = ap.parse_args()
    store = Store()
    alerts = {a["alert_id"]: a for a in json.loads((ROOT / "data" / "alerts.json").read_text(encoding="utf-8"))}
    gold = json.loads((ROOT / "benchmark" / args.gold_file).read_text(encoding="utf-8"))
    ids = [g["case_id"] for g in gold] if args.cases == "all" else args.cases.split(",")
    by_id = {g["case_id"]: g for g in gold}
    out = ROOT / "benchmark" / "results" / args.tag
    out.mkdir(parents=True, exist_ok=True)
    total = len(args.models.split(",")) * args.repeats * len(ids)
    done = 0
    t0 = time.time()
    for model in args.models.split(","):                    # models outermost: one model load per model
        for rep in range(args.repeats):
            for cid in ids:
                path = out / f"{model}_{cid}_r{rep}.json"
                done += 1
                if path.exists():
                    print(f"[{done}/{total}] skip {path.name}", flush=True)
                    continue
                t = time.time()
                try:
                    r = agents.run_pipeline(store, alerts[by_id[cid].get("alert_id") or f"AL-{cid}"], ollama_chat, model, base_seed=42 + 17 * rep)
                    r.update(case_id=cid, repeat=rep, finished=datetime.now().isoformat(timespec="seconds"))
                    path.write_text(json.dumps(r, indent=1, default=str), encoding="utf-8")
                    print(f"[{done}/{total}] {path.name}: route={r['route']} band={r['final']['band']} failed_checks={r['failed_checks']} "
                          f"{time.time() - t:.0f}s (elapsed {(time.time() - t0) / 60:.1f} min)", flush=True)
                except Exception:
                    print(f"[{done}/{total}] {path.name}: ERROR\n{traceback.format_exc()}", flush=True)


if __name__ == "__main__":
    main()
