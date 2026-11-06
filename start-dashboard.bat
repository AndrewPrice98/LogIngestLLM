@echo off
cd /d "%~dp0"
if not exist logagent.toml copy config.example.toml logagent.toml >nul
python -m logagent ui
pause
