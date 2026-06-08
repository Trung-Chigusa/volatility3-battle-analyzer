@echo off
setlocal
cd /d "%~dp0"
py -3 battle_cli.py %*
if errorlevel 9009 (
    python battle_cli.py %*
)
