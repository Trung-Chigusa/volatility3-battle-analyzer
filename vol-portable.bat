@echo off
setlocal
cd /d "%~dp0"
set VOL_CACHE=%~dp0.vol3_cache
set VOL_OUT=%~dp0battle_out
set VOL_SYMBOLS=%~dp0volatility3\symbols;%~dp0volatility3\framework\symbols;%~dp0volatility3-2.26.2\volatility3\symbols;%~dp0volatility3-2.26.2\volatility3\framework\symbols
if not exist "%VOL_CACHE%" mkdir "%VOL_CACHE%"
if not exist "%VOL_OUT%" mkdir "%VOL_OUT%"
py -3 vol.py --cache-path "%VOL_CACHE%" -s "%VOL_SYMBOLS%" -o "%VOL_OUT%" --offline %*
if errorlevel 9009 (
    python vol.py --cache-path "%VOL_CACHE%" -s "%VOL_SYMBOLS%" -o "%VOL_OUT%" --offline %*
)
