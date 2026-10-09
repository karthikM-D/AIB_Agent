"""Thin Ollama client: identical settings for every model (G6), JSON-schema constrained output, latency and token counts."""
import json
import time

import requests

OLLAMA = "http://localhost:11434"
MODELS = {
    "llama": "llama3.1:8b-instruct-q4_K_M",
    "qwen": "qwen3:8b",
    "mistral": "mistral:7b-instruct-q4_K_M",
}
# Fixed for all models and runs; only the seed changes between the repeated runs.
OPTIONS = {"temperature": 0.2, "top_p": 0.9, "num_ctx": 4096, "num_predict": 700}
BASE_SEED = 42


def ollama_body(model, system, user, schema, seed=BASE_SEED):
    """The exact /api/chat request body. Built here so n8n and the Python pipeline use identical settings (G6)."""
    body = {"model": MODELS.get(model, model), "stream": False, "format": schema,
            "options": dict(OPTIONS, seed=seed),
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    if "qwen3" in body["model"]:
        body["think"] = False          # no reasoning trace; keeps latency and output format comparable
    return body


def ollama_chat(model, system, user, schema, seed=BASE_SEED, timeout=300):
    """Returns dict(output, raw, error, latency_ms, tokens). output is the parsed JSON or None."""
    body = ollama_body(model, system, user, schema, seed)
    t = time.time()
    try:
        r = requests.post(f"{OLLAMA}/api/chat", json=body, timeout=timeout)
        r.raise_for_status()
        data = r.json()
    except Exception as e:             # model server down, timeout, HTTP error
        return dict(output=None, raw="", error=f"{type(e).__name__}: {e}", latency_ms=int((time.time() - t) * 1000), tokens=0)
    raw = data.get("message", {}).get("content", "")
    ms = int((time.time() - t) * 1000)
    tokens = data.get("eval_count", 0)
    try:
        return dict(output=json.loads(raw), raw=raw, error=None, latency_ms=ms, tokens=tokens)
    except json.JSONDecodeError as e:
        return dict(output=None, raw=raw, error=f"invalid_json: {e}", latency_ms=ms, tokens=tokens)
