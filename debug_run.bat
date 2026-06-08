@echo off
echo Running Volatility3Analyzer in debug mode...
echo Output will be saved to debug_log.txt
dist\Volatility3Analyzer.exe > debug_log.txt 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Application crashed with exit code %ERRORLEVEL%
    echo Check debug_log.txt for details.
    type debug_log.txt
) else (
    echo Application exited normally.
)
pause

