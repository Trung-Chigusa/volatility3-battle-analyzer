# Quick Start Guide

## Prerequisites

- Python 3.8 or later
- Windows 10/11 x64
- Volatility3 in `volatility3-2.26.2/` directory (already present)

## Installation (5 minutes)

### Step 1: Create Virtual Environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 2: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 3: Run the Application

```powershell
python app/main.py
```

## Building Executable

### Option 1: Using Build Script (Recommended)

```powershell
.\build_spec\build.bat
```

The executable will be created in `dist\Volatility3Analyzer.exe`

### Option 2: Manual PyInstaller

```powershell
pyinstaller build_spec/volatility_gui.spec
```

## First Use

1. **Launch the application**
2. **Load a memory dump**:
   - Drag & drop a `.dmp`, `.raw`, `.vmem`, `.img`, or `.dump` file
   - Or click "Select File" button
3. **Start Analysis**:
   - Click "Start Full Analysis" for complete analysis
   - Or choose specific analysis (Processes, Network)
4. **Explore Results**:
   - Use sidebar to navigate between views
   - Filter and search within each view
5. **Generate Report**:
   - Go to Reports view
   - Configure options
   - Click "Generate Report"
   - Save as HTML, Markdown, or JSON

## Troubleshooting

### "Volatility3 not found" Error

- Verify `volatility3-2.26.2/` directory exists
- Check Settings → Volatility3 Path
- Ensure Volatility3 is properly installed

### Plugin Errors

- Some plugins may fail if memory dump format is unsupported
- Check Advanced view for detailed error messages
- Try different plugins manually in Advanced view

### Performance

- Reduce "Max Parallel Workers" in Settings if system is slow
- Use targeted analysis instead of full analysis
- Close other applications to free memory

## Tips

- **Suspicious Items**: Items with high suspicion scores are highlighted in red/yellow
- **Filtering**: Use filter boxes in each view to narrow down results
- **Advanced Mode**: Use Advanced view to run any Volatility3 plugin manually
- **Reports**: Generate reports after analysis for documentation

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Explore the code in `app/` directory
- Customize heuristics in `app/core/analysis.py`
- Add new views in `app/ui/views/`

