@echo off
rem Stops the API, n8n and the website.
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000,5678,8501 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"
taskkill /F /T /FI "WINDOWTITLE eq SOC API*" >nul 2>&1
taskkill /F /T /FI "WINDOWTITLE eq SOC n8n*" >nul 2>&1
taskkill /F /T /FI "WINDOWTITLE eq SOC website*" >nul 2>&1
echo Demo stopped.
