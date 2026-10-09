@echo off
rem Sends the demo cases through the real system so the screens have content. Takes about 9 minutes. Leave the window open until it says Done.
cd /d "%~dp0"
.venv\Scripts\python.exe scripts\demo_preload.py --cases G01,G03,G13,G07,G06,B001,B002,B003,B004,B005,B006
echo.
echo Done. The demo is loaded. (G09, the high-risk case, is left for you to send live.)
pause
