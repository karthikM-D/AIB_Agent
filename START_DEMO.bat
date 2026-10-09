@echo off
rem Starts everything for the demo. Double-click this file. Three black windows will open: leave them open.
cd /d "%~dp0"
title Demo launcher
echo Starting the API, n8n and the website. Do NOT close the three new black windows.
start "SOC API" cmd /k ".venv\Scripts\python.exe -m uvicorn app.api:app --port 8000"
start "SOC n8n" cmd /k "set N8N_USER_FOLDER=%cd%\n8n\data&& set N8N_PORT=5678&& set N8N_DIAGNOSTICS_ENABLED=false&& set N8N_PERSONALIZATION_ENABLED=false&& n8n\node_modules\.bin\n8n.cmd start"
start "SOC website" cmd /k ".venv\Scripts\streamlit.exe run ui\streamlit_app.py --server.headless true --server.port 8501"
echo Waiting 50 seconds for everything to start...
timeout /t 50 /nobreak >nul
start "" http://localhost:8501
start "" http://localhost:5678
echo.
echo Ready. Two browser tabs opened: the website (8501) and n8n (5678).
echo Next: double-click PRELOAD_DEMO.bat if the demo cases are not loaded yet.
pause
