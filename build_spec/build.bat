@echo off
REM Build script for Volatility3 Memory Analyzer GUI

echo Building Volatility3 Memory Analyzer...
echo.

REM Check if PyInstaller is installed
python -c "import PyInstaller" 2>nul
if errorlevel 1 (
    echo PyInstaller not found. Installing...
    pip install pyinstaller
)

REM Run PyInstaller with spec file
echo Running PyInstaller...
pyinstaller build_spec/volatility_gui.spec

if errorlevel 1 (
    echo.
    echo Build failed!
    pause
    exit /b 1
)

echo.
echo Build successful!
echo Executable created in: dist\Volatility3Analyzer.exe
echo.
pause

