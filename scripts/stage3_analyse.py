"""Compute the model-comparison metrics from benchmark/results/<tag>/ and write docs/stage3/results/<tag>_summary.md (+ CSV).

Metrics (KB section 6.2): classification quality (band), escalation accuracy with missed escalations reported separately,
false escalations, hallucination (cited IDs not in the input), structured-output compliance (first attempt), latency (median, p95),
task completion (pipeline finished without two failed checks), stability (three risk runs agree) under rules A / B / C,
injection resistance (G13). Explanation quality is a manual blind rubric: a sheet is generated, scored by two team members.
Usage: python scripts/stage3_analyse.py --tag quick
"""
import argparse
import json
import random
from pathlib import Path

import sys

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from app.checks import action_class  # noqa: E402  (same action classes as the live rule)
BANDS = ["low", "medium", "high", "critical"]
SHAPE_PROBLEMS = ("schema", "invalid_json", "ollama_error", "no_output")




def agreement(risks):
    """Stability under three rules: A band+action, B band only, C band + action class (current)."""
    if len(risks) < 2:
        return dict(A=True, B=True, C=True)
    return dict(A=len({(r["band"], r["recommended_action"]) for r in risks}) == 1,
                B=len({r["band"] for r in risks}) == 1,
                C=len({(r["band"], action_class(r["recommended_action"])) for r in risks}) == 1)


def load(tag):
    gold = {g["case_id"]: g for g in json.loads((ROOT / "benchmark" / "gold_cases.json").read_text(encoding="utf-8"))}
    runs = []
    for p in sorted((ROOT / "benchmark" / "results" / tag).glob("*.json")):
        r = json.loads(p.read_text(encoding="utf-8"))
        exp = gold[r["case_id"]]["expected"]
        exp_route = "escalation" if exp["escalate"] else "deprioritised_list" if exp["deprioritise_allowed"] else "analyst_queue"
        first = [s for s in r["steps"] if s["attempt"] == 1]
        ag = agreement(r["risk_outputs"])
        runs.append(dict(
            model=r["model"], case=r["case_id"], category=gold[r["case_id"]]["category"], repeat=r["repeat"],
            route=r["route"], expected_route=exp_route, route_ok=r["route"] == exp_route,
            escalated=r["final"]["escalate"], expected_escalate=exp["escalate"],
            missed_escalation=exp["escalate"] and not r["final"]["escalate"], false_escalation=r["final"]["escalate"] and not exp["escalate"],
            band=r["final"]["band"], expected_band=exp["band"], band_ok=r["final"]["band"] == exp["band"],
            band_not_below=BANDS.index(r["final"]["band"]) >= BANDS.index(exp["band"]),
            steps_first=len(first), shape_fail_first=sum(any(p.startswith(SHAPE_PROBLEMS) for p in s["problems"]) for s in first),
            halluc_first=sum(any(p.startswith("hallucinated_evidence") for p in s["problems"]) for s in first),
            any_problem_first=sum(bool(s["problems"]) for s in first),
            completed=r["failed_checks"] < 2, latency_s=r["latency_ms"] / 1000, tokens=r["tokens"],
            agree_A=ag["A"], agree_B=ag["B"], agree_C=ag["C"], risk_runs=len(r["risk_outputs"]),
            injection_flagged_by_model=any("inject" in json.dumps(s["output"]).lower() for s in r["steps"] if s["output"]) if r["case_id"] == "G13" else None,
            _raw=r))
    return pd.DataFrame(runs)


def summarise(df):
    g = df.groupby("model")
    out = pd.DataFrame({
        "runs": g.size(),
        "route correct %": g["route_ok"].mean() * 100,
        "escalation correct %": g.apply(lambda d: (d["escalated"] == d["expected_escalate"]).mean() * 100),
        "missed escalations": g["missed_escalation"].sum(),
        "false escalations": g["false_escalation"].sum(),
        "band exact %": g["band_ok"].mean() * 100,
        "band not below expected %": g["band_not_below"].mean() * 100,
        "schema compliance, first try %": g.apply(lambda d: 100 - d["shape_fail_first"].sum() / d["steps_first"].sum() * 100),
        "hallucinated IDs, first try (steps)": g["halluc_first"].sum(),
        "any check problem, first try %": g.apply(lambda d: d["any_problem_first"].sum() / d["steps_first"].sum() * 100),
        "task completion %": g["completed"].mean() * 100,
        "stable runs, rule A %": g["agree_A"].mean() * 100,
        "stable runs, rule B %": g["agree_B"].mean() * 100,
        "stable runs, rule C %": g["agree_C"].mean() * 100,
        "latency median s": g["latency_s"].median(),
        "latency p95 s": g["latency_s"].quantile(0.95),
    })
    return out.round(1)


def blind_sheet(df, tag):
    """Explanation-quality rubric sheet: model names hidden, shuffled; the key stays in a separate file."""
    rnd = random.Random(7)
    rows = []
    for _, d in df.iterrows():
        r = d["_raw"]
        mapping = r["mapping"]
        rev = {v: k for dd in (mapping.get("users", {}), mapping.get("hosts", {})) for k, v in dd.items()}
        text = (r["outputs"].get("summary") or {}).get("summary", "")
        rat = r["risk_outputs"][0]["rationale"] if r["risk_outputs"] else ""
        for a, b in rev.items():
            text, rat = text.replace(a, b), rat.replace(a, b)
        rows.append(dict(model=d["model"], case=d["case"], repeat=d["repeat"], summary=text, rationale=rat))
    rnd.shuffle(rows)
    sheet = [dict(sample_id=f"S{i + 1:03d}", case=r["case"], summary=r["summary"], rationale=r["rationale"],
                  faithful_1to5="", complete_1to5="", actionable_1to5="", clear_1to5="") for i, r in enumerate(rows)]
    key = [dict(sample_id=s["sample_id"], model=r["model"], repeat=r["repeat"]) for s, r in zip(sheet, rows)]
    out = (ROOT / "docs" / "stage3" / "results") if (ROOT / "docs" / "stage3").exists() else (ROOT / "benchmark" / "summary")
    pd.DataFrame(sheet).to_csv(out / f"{tag}_rubric_blind.csv", index=False)
    pd.DataFrame(key).to_csv(ROOT / "benchmark" / "results" / tag / "rubric_key.csv", index=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="quick")
    args = ap.parse_args()
    out = (ROOT / "docs" / "stage3" / "results") if (ROOT / "docs" / "stage3").exists() else (ROOT / "benchmark" / "summary")
    out.mkdir(parents=True, exist_ok=True)
    df = load(args.tag)
    summ = summarise(df)
    cols = [c for c in df.columns if c != "_raw"]
    df[cols].to_csv(out / f"{args.tag}_runs.csv", index=False)
    summ.to_csv(out / f"{args.tag}_summary.csv")
    percase = df.pivot_table(index=["case", "category", "expected_route"], columns="model", values="route", aggfunc=lambda s: "/".join(sorted(set(s))))
    inj = df[df["case"] == "G13"][["model", "route", "injection_flagged_by_model"]]
    md = [f"# Model comparison results: run set `{args.tag}`\n",
          f"{len(df)} pipeline runs ({df['model'].nunique()} models, {df['case'].nunique()} cases, up to {df['repeat'].max() + 1} repeat(s)). Identical prompts (version v3), data, settings and code checks for every model; each run includes five agents and three risk runs.\n",
          "## Metrics by model\n", summ.T.to_markdown(), "\n",
          "## Route per case (expected route in the index)\n", percase.to_markdown(), "\n",
          "## Injection case (G13)\n", inj.to_markdown(index=False), "\n",
          "Stability rules: A = same band and action, B = same band, C = same band and action class (current since 2026-10-04). "
          "Missed escalations (expected escalation, bot did not escalate) are the dangerous error and are reported separately from false escalations. "
          "Explanation quality is scored manually on the blind sheet (`" + f"{args.tag}_rubric_blind.csv" + "`) by two team members.\n"]
    (out / f"{args.tag}_summary.md").write_text("\n".join(md), encoding="utf-8")
    blind_sheet(df, args.tag)
    print(summ.T.to_string())


if __name__ == "__main__":
    main()
