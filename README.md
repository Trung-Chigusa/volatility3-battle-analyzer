# Volatility3 Memory Analyzer GUI

A modern, production-ready GUI application for offline memory dump analysis using Volatility3. This tool provides a beautiful, intuitive interface for memory forensics with advanced features like suspicious process detection, network analysis, string search, and comprehensive reporting.

## Features

- **Modern GUI**: Dark-themed, responsive interface built with PySide6 (Qt)
- **Drag & Drop**: Easy file loading with drag & drop support
- **Multi-threaded Analysis**: Parallel processing for faster analysis
- **Process Analysis**: 
  - Process tree visualization
  - Suspicious process detection
  - Command line analysis
  - Path and location analysis
- **Network Analysis**:
  - Connection listing
  - Suspicious port detection
  - External IP identification
- **String Search**: Search for strings in process memory with regex support
- **Suspicious Artifact Detection**: Automatic detection of:
  - Unusual executables
  - Suspicious URLs
  - Malware indicators
- **Advanced Plugin Runner**: Run any Volatility3 plugin manually
- **Comprehensive Reporting**: Export reports in HTML, Markdown, or JSON format

## Requirements

- Python 3.8 or later
- Windows 10/11 x64
- Volatility3 (included in `volatility3-2.26.2/` directory)

## Installation

### 1. Set up Python Virtual Environment

```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1
```

### 2. Install Dependencies

```powershell
pip install -r requirements.txt
```

### 3. Verify Volatility3

The application expects Volatility3 to be in the `volatility3-2.26.2/` directory. If it's located elsewhere, you can:

- Update the path in `app/core/vol_runner.py`
- Or set the path in Settings dialog after running the app

## Running the Application

### Development Mode

```powershell
# Make sure virtual environment is activated
python app/main.py
```

### Building a Standalone Executable

#### Using PyInstaller

1. **Create the spec file** (already provided in `build_spec/volatility_gui.spec`):

```powershell
# The spec file is already created, but you can regenerate it:
pyinstaller --name="Volatility3Analyzer" ^
    --onefile ^
    --windowed ^
    --icon=assets/account.png ^
    --add-data "volatility3-2.26.2;volatility3-2.26.2" ^
    --add-data "assets;assets" ^
    --hidden-import=volatility3 ^
    --hidden-import=volatility3.framework ^
    --hidden-import=volatility3.plugins ^
    app/main.py
```

2. **Or use the provided spec file**:

```powershell
pyinstaller build_spec/volatility_gui.spec
```

3. **The executable will be created in** `dist/Volatility3Analyzer.exe`

#### Build Script

A build script is provided for convenience:

```powershell
.\build_spec\build.bat
```

## Usage

### Basic Workflow

1. **Launch the application**
2. **Load a memory dump**:
   - Click "Select File" or drag & drop a `.dmp`, `.raw`, `.vmem`, `.img`, or `.dump` file
3. **Start analysis**:
   - Click "Start Full Analysis" for complete analysis
   - Or choose specific analysis types (Processes, Network)
4. **Explore results**:
   - Navigate through different views using the sidebar
   - Filter and search within each view
5. **Generate reports**:
   - Go to Reports view
   - Configure options and generate report
   - Export as HTML, Markdown, or JSON

### Views

- **Overview**: File selection and analysis controls
- **Processes**: Process tree with suspicious process highlighting
- **Network**: Network connections with suspicious connection detection
- **Strings Search**: Search for strings in memory
- **Suspicious Artifacts**: View all detected suspicious items
- **Advanced**: Run Volatility3 plugins manually
- **Reports**: Generate and export analysis reports

### Settings

Access settings via the "Settings" button in the top bar:

- **Max Parallel Workers**: Number of parallel analysis threads
- **Uncommon Port Threshold**: Port number threshold for suspicious detection
- **Volatility3 Path**: Custom path to Volatility3 (if not in default location)

## Project Structure

```
.
├── app/
│   ├── __init__.py
│   ├── main.py                 # Application entry point
│   ├── core/                   # Core analysis logic
│   │   ├── __init__.py
│   │   ├── models.py           # Data models
│   │   ├── vol_runner.py       # Volatility3 wrapper
│   │   └── analysis.py         # Suspicion scoring
│   └── ui/                     # GUI components
│       ├── __init__.py
│       ├── main_window.py      # Main window
│       ├── sidebar.py          # Navigation sidebar
│       ├── views/              # View components
│       │   ├── overview_view.py
│       │   ├── processes_view.py
│       │   ├── network_view.py
│       │   ├── strings_view.py
│       │   ├── suspicious_view.py
│       │   ├── advanced_view.py
│       │   └── reports_view.py
│       ├── workers/             # Background workers
│       │   └── analysis_worker.py
│       └── dialogs/            # Dialog windows
│           └── settings_dialog.py
├── assets/
│   └── account.png             # Application icon
├── build_spec/
│   ├── volatility_gui.spec    # PyInstaller spec file
│   └── build.bat              # Build script
├── volatility3-2.26.2/         # Volatility3 framework
├── requirements.txt
└── README.md
```

## Troubleshooting

### Volatility3 Not Found

If you get errors about Volatility3 not being found:

1. Verify `volatility3-2.26.2/` directory exists
2. Check the path in Settings dialog
3. Ensure Volatility3 is properly installed

### Plugin Errors

Some plugins may fail if:
- The memory dump format is not supported
- Required symbol files are missing
- The OS profile doesn't match

Check the Advanced view output for detailed error messages.

### Performance Issues

- Reduce "Max Parallel Workers" in Settings
- Close other applications to free up memory
- Use targeted analysis instead of full analysis

## Development

### Adding New Heuristics

Edit `app/core/analysis.py` to add new suspicion detection rules.

### Adding New Views

1. Create a new view class in `app/ui/views/`
2. Add it to the sidebar in `app/ui/sidebar.py`
3. Register it in `app/ui/main_window.py`

### Extending Volatility3 Integration

Modify `app/core/vol_runner.py` to add new plugin wrappers or analysis methods.

## License

This application uses Volatility3, which is licensed under the Volatility Software License (VSL).

## Contributing

This is a production-ready tool. Feel free to extend and customize it for your needs.

## Support

For issues related to:
- **This GUI**: Check the code and modify as needed
- **Volatility3**: See [Volatility3 Documentation](https://volatility3.readthedocs.io/)

