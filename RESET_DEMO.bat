@echo off
rem Wipes all demo cases and starts from empty. Stops the services first. Then run START_DEMO.bat and PRELOAD_DEMO.bat again.
cd /d "%~dp0"
call STOP_DEMO.bat
.venv\Scripts\python.exe scripts\demo_reset.py
echo.
echo Reset done. Now double-click START_DEMO.bat, then PRELOAD_DEMO.bat.
pause
