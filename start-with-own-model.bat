@echo off
cd /d "%~dp0"
set HF_HUB_DISABLE_SYMLINKS_WARNING=1
start "logagent model" .venv-train\Scripts\python -W ignore trainer\serve.py
if not exist logagent.toml copy config.example.toml logagent.toml >nul
python -m logagent ui
pause
