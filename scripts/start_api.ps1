# Starts the FastAPI services (app\api.py) using the project venv. API: http://localhost:8000  (docs at /docs)
$p = Split-Path $PSScriptRoot -Parent
Set-Location $p
& "$p\.venv\Scripts\uvicorn.exe" app.api:app --port 8000
