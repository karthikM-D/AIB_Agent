# Quick health check of the whole toolchain.
$p = Split-Path $PSScriptRoot -Parent
"Ollama : " + (ollama --version 2>$null | Select-Object -First 1)
ollama list
"Python venv : " + (& "$p\.venv\Scripts\python.exe" --version)
"n8n : " + (& "$p\n8n\node_modules\.bin\n8n.cmd" --version)
nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv,noheader
