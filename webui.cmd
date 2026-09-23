@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0webui.ps1" %*
exit /b %errorlevel%
