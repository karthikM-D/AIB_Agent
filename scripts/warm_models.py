"""Load a model into memory and keep it there, so the first live alert is not slow (a cold load took about 56 seconds in testing).

Usage:  .venv\Scripts\python.exe scripts\warm_models.py qwen          # warm the model used first in the demo
        .venv\Scripts\python.exe scripts\warm_models.py llama qwen    # several in order; the last one stays loaded
On a 6 GB GPU only one 8B model fits at a time, so switching model between alerts costs a reload (up to a minute).
"""
import sys
import time

import requests

TAGS = {"llama": "llama3.1:8b-instruct-q4_K_M", "qwen": "qwen3:8b", "mistral": "mistral:7b-instruct-q4_K_M"}
for name in sys.argv[1:] or ["llama"]:
    t = time.time()
    body = {"model": TAGS[name], "prompt": "ok", "stream": False, "keep_alive": "30m", "options": {"num_predict": 1}}
    if name == "qwen":
        body["think"] = False
    r = requests.post("http://127.0.0.1:11434/api/generate", json=body, timeout=300)
    print(f"{name}: {'loaded' if r.ok else 'FAILED ' + r.text[:100]} in {time.time() - t:.0f}s (kept for 30 minutes)")
