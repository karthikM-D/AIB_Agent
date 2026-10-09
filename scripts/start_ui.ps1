# Starts the Streamlit UI (ui\streamlit_app.py) using the project venv. UI: http://localhost:8501
$p = Split-Path $PSScriptRoot -Parent
Set-Location $p
& "$p\.venv\Scripts\streamlit.exe" run "$p\ui\streamlit_app.py"
