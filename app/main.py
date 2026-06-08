"""Main entry point for the application"""
import sys
import os
from pathlib import Path
import logging

# Add volatility3 to path
project_root = Path(__file__).parent.parent
volatility3_path = project_root / "volatility3-2.26.2"
for import_path in (project_root, volatility3_path):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))


def setup_logging():
    log_dir = Path.home() / "Volatility3Analyzer"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "volatility_gui.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
        ],
    )
    logging.info("Logging initialized at %s", log_path)


def exception_hook(exctype, value, tb):
    """Global exception handler to catch crashes"""
    import traceback
    logger = logging.getLogger(__name__)
    logger.critical("UNCAUGHT EXCEPTION:", exc_info=(exctype, value, tb))
    
    # Print to stderr as well
    print("=" * 80, file=sys.stderr)
    print("FATAL ERROR - Application crashed:", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    traceback.print_exception(exctype, value, tb, file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    
    # Call the default handler
    sys.__excepthook__(exctype, value, tb)


def extract_cli_args(argv):
    """Return Battle CLI args when the executable is launched in CLI mode."""
    markers = {"--cli", "--battle-cli", "cli", "battle"}
    for index, arg in enumerate(argv[1:], start=1):
        if arg in markers:
            return argv[index + 1 :]
    return None


def run_cli_mode(args):
    from battle_cli import main as battle_main

    sys.exit(battle_main(args))


def run_gui_mode():
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt
    from app.ui.main_window import MainWindow

    setup_logging()

    # Install global exception hook
    sys.excepthook = exception_hook

    # Enable high DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)

    app = QApplication(sys.argv)
    app.setApplicationName("Volatility3 Memory Analyzer")
    app.setOrganizationName("Volatility3")

    # Set application style
    app.setStyle("Fusion")

    try:
        # Create and show main window
        window = MainWindow()
        window.show()

        sys.exit(app.exec())
    except Exception:
        logging.exception("Fatal error in main()")
        raise


def main():
    """Main function"""
    
    # Check if running as worker process
    if "--worker" in sys.argv:
        try:
            idx = sys.argv.index("--worker")
            if idx + 2 < len(sys.argv):
                dump_file = sys.argv[idx+1]
                analysis_type = sys.argv[idx+2]
                from app.worker_process import run_worker
                run_worker(dump_file, analysis_type)
                return
        except Exception as e:
            print(f"Worker failed to start: {e}", file=sys.stderr)
            sys.exit(1)

    cli_args = extract_cli_args(sys.argv)
    if cli_args is not None:
        run_cli_mode(cli_args)

    run_gui_mode()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.exception("Application crashed")
        import traceback
        traceback.print_exc()
        if sys.stdin.isatty():
            input("Press Enter to exit...")

