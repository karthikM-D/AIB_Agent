# Governed Agentic AI for SOC Alert Triage

A prototype that helps a Tier 1 security analyst triage alerts. Five single-purpose AI agents prepare each alert (correlation, threat intelligence, asset context, risk and prioritisation, incident summary), an n8n workflow orchestrates them, code checks every model answer, and a person makes every consequential decision. **AI prepares, a human decides, every step is checked and logged.**

> **Scope and limits.** All data is synthetic and the services are mocks. The system recommends and never acts: it has no containment or response tool. It is a governed prototype and a design pattern, not a production product.

## How it works
1. An alert arrives (website, or a POST to the n8n webhook).
2. Sensitive names are replaced by aliases and a transparent rule-based score is computed (the model may only add caution, never lower it).
3. Five agents run in turn on a local open model (Ollama). The risk agent runs three times.
4. Code checks every answer: JSON schema, every cited evidence ID must exist, actions must be on an allow-list, the three risk runs must agree. A failed check is retried once, then the case goes to a person.
5. Rules route the case: escalation, analyst queue, or a deprioritised list with reasons (nothing is closed silently).
6. A person reads the evidence and decides, with a mandatory reason. Every step is written to an append-only audit log.

## Requirements
- Windows with PowerShell (the launchers are `.bat` and `.ps1` files), Python 3.11 or newer, Node.js 20 or newer.
- [Ollama](https://ollama.com) with the models you want to use. A laptop GPU with 6 GB runs 7 to 8B models partly on the CPU.
  ```
  ollama pull llama3.1:8b-instruct-q4_K_M
  ollama pull qwen3:8b
  ollama pull mistral:7b-instruct-q4_K_M
  ```

## Install
```
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
cd n8n
npm install
cd ..
powershell -ExecutionPolicy Bypass -File scripts\n8n_setup.ps1
```
`n8n_setup.ps1` generates the four workflows (`workflows/`), imports them into the project-local n8n and publishes them. Run it with n8n stopped.

## Run
Double-click `START_DEMO.bat`. It starts three programs (keep their windows open) and opens two browser tabs after about a minute:
- the website, http://localhost:8501
- n8n, http://localhost:5678

Then:
- `PRELOAD_DEMO.bat` sends a set of sample alerts through the real system so the screens have content (about 10 minutes).
- `RESET_DEMO.bat` deletes all cases and n8n's run history; `STOP_DEMO.bat` stops the programs.
- `python scripts/warm_models.py qwen` loads a model into memory before a live run.
- Each sample alert can be sent only once; a repeat is recognised as a duplicate.

## The website
Eight pages: Intake (with a live trace), Analyst queue, Escalations, Deprioritised list (with a spot-check before any bulk action), Analytics, Cost-benefit (illustrative, every input is an assumption), Case register (every alert, searchable by case number or test-case code) and Audit trail.

## Tests
```
.venv\Scripts\python.exe -m pytest -q                      # unit tests, no services needed
.venv\Scripts\python.exe scripts\check_all.py              # checks of the running system (start it first)
.venv\Scripts\python.exe scripts\check_all.py --live       # also sends two alerts through n8n (about 3 minutes)
```

## Evaluation
`benchmark/gold_cases.json` holds 20 gold cases with expected answers written before any run, and `benchmark/extension_cases.json` two further cases. `scripts/stage3_evaluate.py` runs the full pipeline for several models on identical cases, prompts, settings and checks; `scripts/stage3_analyse.py` computes the comparison metrics.

## Layout
`app/` services, rules, checks, agents and prompts · `ui/` website · `workflows/` n8n workflows · `data/` synthetic data · `benchmark/` gold cases · `scripts/` run and test helpers · `tests/` unit tests · `n8n/` n8n package files.

## Governance
Nineteen controls (masking, injection scan, narrow agents, rule floor, code checks, three-run agreement, retry then escalate, propose-only actions, escalation and never-deprioritise rules, human approval with a reason, spot-check, no silent closure, reportability flag, audit trail, evaluation) are mapped to the NIST AI Risk Management Framework, with ISO/IEC 27001 Annex A and the OWASP Top 10 for LLM Applications as supporting references. This is a mapping, not a certification.
