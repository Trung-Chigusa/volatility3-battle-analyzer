"""Main application window"""
import os
import sys
import logging
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QStatusBar,
    QProgressBar,
    QSplitter,
    QMessageBox,
    QFileDialog,
    QTextEdit,
)
from PySide6.QtCore import Qt, QThread, Signal, QSize, QObject
from PySide6.QtGui import QIcon, QDragEnterEvent, QDropEvent

from .sidebar import Sidebar
from .views.overview_view import OverviewView
from .views.processes_view import ProcessesView
from .views.network_view import NetworkView
from .views.strings_view import StringsView
from .views.suspicious_view import SuspiciousView
from .views.advanced_view import AdvancedView
from .views.reports_view import ReportsView
from .views.battle_console_view import BattleConsoleView
from .views.file_tree_view import FileTreeView
from .views.image_dump_view import ImageDumpView
from .views.virustotal_view import VirusTotalView
from ..core.vol_runner import VolatilityRunner
from ..core.models import AnalysisReport


class LogEmitter(QObject):
    log_message = Signal(str)


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.vol_runner: Optional[VolatilityRunner] = None
        self.current_dump_file: Optional[str] = None
        self.analysis_report = AnalysisReport(
            dump_file="",
            dump_size=0,
            analysis_timestamp=datetime.now()
        )
        
        self.setWindowTitle("Volatility3 Memory Analyzer - Battle Edition")
        self.setMinimumSize(1200, 800)
        
        # Set window icon
        icon_path = Path(__file__).parent.parent.parent / "assets" / "account.png"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        
        self._setup_ui()
        self._apply_styles()
        
        # Enable drag and drop
        self.setAcceptDrops(True)
    
    def _setup_ui(self):
        """Setup the UI components"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Top bar
        top_bar = self._create_top_bar()
        main_layout.addWidget(top_bar)
        
        # Main content area with sidebar
        outer_splitter = QSplitter(Qt.Horizontal)
        
        # Sidebar
        self.sidebar = Sidebar()
        self.sidebar.view_changed.connect(self._on_view_changed)
        outer_splitter.addWidget(self.sidebar)
        
        # Main content splitter (content + log view)
        self.main_content_splitter = QSplitter(Qt.Horizontal)
        
        # Content area
        self.content_stack = QWidget()
        self.content_layout = QVBoxLayout(self.content_stack)
        self.content_layout.setContentsMargins(10, 10, 10, 10)
        
        # Create views
        self.overview_view = OverviewView()
        self.overview_view.file_selected.connect(self._on_file_selected)
        self.overview_view.analyze_clicked.connect(self._on_analyze_clicked)
        
        self.processes_view = ProcessesView()
        self.processes_view.dump_requested.connect(self._on_process_dump_requested)
        self.battle_console_view = BattleConsoleView()
        self.file_tree_view = FileTreeView()
        self.image_dump_view = ImageDumpView()
        self.virustotal_view = VirusTotalView()
        self.image_dump_view.output_ready.connect(self.virustotal_view.set_target_path)
        self.network_view = NetworkView()
        self.strings_view = StringsView()
        from .views.decoded_view import DecodedView
        self.decoded_view = DecodedView()
        self.suspicious_view = SuspiciousView()
        self.advanced_view = AdvancedView()
        self.reports_view = ReportsView()
        
        # Add views to layout (only show overview initially)
        self.content_layout.addWidget(self.overview_view)
        self.current_view = self.overview_view
        
        self.main_content_splitter.addWidget(self.content_stack)
        
        # Log panel
        self.log_panel = self._create_log_panel()
        self.main_content_splitter.addWidget(self.log_panel)
        self.main_content_splitter.setStretchFactor(0, 5)
        self.main_content_splitter.setStretchFactor(1, 2)
        self.main_content_splitter.setSizes([800, 300])
        
        outer_splitter.addWidget(self.main_content_splitter)
        outer_splitter.setStretchFactor(0, 0)
        outer_splitter.setStretchFactor(1, 1)
        outer_splitter.setSizes([200, 1000])
        
        main_layout.addWidget(outer_splitter)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)
        
        # Setup logging to log view
        self.log_emitter = LogEmitter()
        self.log_emitter.log_message.connect(self._append_log)
        gui_handler = logging.Handler()
        def emit(record):
            msg = gui_handler.format(record)
            self.log_emitter.log_message.emit(msg)
        gui_handler.emit = emit
        gui_handler.setLevel(logging.INFO)
        gui_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%H:%M:%S"))
        logging.getLogger().addHandler(gui_handler)
        self.logger.info("GUI initialized")
    
    def _create_top_bar(self) -> QWidget:
        """Create the top bar with title and buttons"""
        top_bar = QWidget()
        top_bar.setFixedHeight(50)
        layout = QHBoxLayout(top_bar)
        layout.setContentsMargins(10, 5, 10, 5)
        
        # Title and icon
        title_layout = QHBoxLayout()
        icon_path = Path(__file__).parent.parent.parent / "assets" / "account.png"
        if icon_path.exists():
            icon_label = QLabel()
            icon_label.setPixmap(QIcon(str(icon_path)).pixmap(32, 32))
            title_layout.addWidget(icon_label)
        
        title_label = QLabel("Volatility3 Memory Analyzer | Battle Edition")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        layout.addLayout(title_layout)
        
        # Buttons
        settings_btn = QPushButton("Settings")
        settings_btn.clicked.connect(self._on_settings_clicked)
        layout.addWidget(settings_btn)
        
        help_btn = QPushButton("Help")
        help_btn.clicked.connect(self._on_help_clicked)
        layout.addWidget(help_btn)
        
        return top_bar
    
    def _apply_styles(self):
        """Apply dark theme styles"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QPushButton {
                background-color: #3c3c3c;
                border: 1px solid #555555;
                border-radius: 4px;
                padding: 5px 15px;
                min-height: 25px;
            }
            QPushButton:hover {
                background-color: #4c4c4c;
            }
            QPushButton:pressed {
                background-color: #2c2c2c;
            }
            QLineEdit, QComboBox, QSpinBox {
                background-color: #1e1e1e;
                border: 1px solid #555555;
                border-radius: 4px;
                padding: 5px;
                min-height: 24px;
                color: #ffffff;
            }
            QCheckBox {
                color: #ffffff;
                spacing: 6px;
            }
            QStatusBar {
                background-color: #1e1e1e;
                color: #ffffff;
                border-top: 1px solid #555555;
            }
            QLabel {
                color: #ffffff;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 3px;
                text-align: center;
                min-width: 200px;
            }
            QProgressBar::chunk {
                background-color: #0078d4;
                border-radius: 2px;
            }
            QTextEdit#CliLogView {
                background-color: #101010;
                color: #00ff00;
                font-family: Consolas, "Courier New", monospace;
                font-size: 12px;
            }
            QTextEdit#AppLogView {
                background-color: #1e1e1e;
                color: #d0d0d0;
                font-family: Consolas, "Courier New", monospace;
                font-size: 12px;
            }
        """)

    def _create_log_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(6)
        
        cli_label = QLabel("Worker CLI Output")
        layout.addWidget(cli_label)
        
        self.cli_log_view = QTextEdit()
        self.cli_log_view.setObjectName("CliLogView")
        self.cli_log_view.setReadOnly(True)
        self.cli_log_view.setLineWrapMode(QTextEdit.NoWrap)
        self.cli_log_view.setPlaceholderText("Volatility3 console output...")
        layout.addWidget(self.cli_log_view, stretch=2)
        
        app_label = QLabel("Application Log")
        layout.addWidget(app_label)
        
        self.app_log_view = QTextEdit()
        self.app_log_view.setObjectName("AppLogView")
        self.app_log_view.setReadOnly(True)
        self.app_log_view.setLineWrapMode(QTextEdit.NoWrap)
        self.app_log_view.setPlaceholderText("GUI events and diagnostics...")
        layout.addWidget(self.app_log_view, stretch=1)
        
        return panel
    
    def _append_log(self, message: str):
        if hasattr(self, "app_log_view") and self.app_log_view:
            self.app_log_view.append(message)
    
    def _append_cli_log(self, message: str):
        if hasattr(self, "cli_log_view") and self.cli_log_view:
            self.cli_log_view.append(message)
    
    def _on_view_changed(self, view_name: str):
        """Handle view change from sidebar"""
        # Remove current view
        if self.current_view:
            self.content_layout.removeWidget(self.current_view)
            self.current_view.setParent(None)
        
        # Show new view
        view_map = {
            "overview": self.overview_view,
            "battle": self.battle_console_view,
            "filetree": self.file_tree_view,
            "images": self.image_dump_view,
            "virustotal": self.virustotal_view,
            "processes": self.processes_view,
            "network": self.network_view,
            "strings": self.strings_view,
            "decoded": self.decoded_view,
            "suspicious": self.suspicious_view,
            "advanced": self.advanced_view,
            "reports": self.reports_view,
        }
        
        self.current_view = view_map.get(view_name, self.overview_view)
        self.content_layout.addWidget(self.current_view)

        if view_name in {"battle", "filetree", "images"} and self.current_dump_file:
            self.current_view.set_dump_file(self.current_dump_file)
        
        # Update view with current data if available
        if view_name == "advanced" and self.vol_runner:
            self.advanced_view.set_vol_runner(self.vol_runner)
        elif view_name == "reports":
            self.reports_view.set_analysis_report(self.analysis_report)
        elif view_name == "decoded":
            decoded = getattr(self.analysis_report, 'decoded_strings', [])
            self.decoded_view.update_data(decoded)
        elif self.vol_runner and view_name != "overview":
            self._update_view_data(view_name)
    
    def _update_view_data(self, view_name: str):
        """Update a view with current analysis data"""
        if view_name == "processes":
            self.processes_view.update_data(self.analysis_report.processes)
        elif view_name == "network":
            self.network_view.update_data(self.analysis_report.connections)
        elif view_name == "strings":
            self.strings_view.update_data(self.analysis_report.string_matches)
        elif view_name == "suspicious":
            self.suspicious_view.update_data(self.analysis_report.suspicious_artifacts)
    
    def _on_file_selected(self, file_path: str):
        """Handle file selection"""
        self.current_dump_file = file_path
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        self.status_label.setText(f"File: {os.path.basename(file_path)} ({file_size / (1024*1024):.2f} MB)")
        self.logger.info("Selected memory file: %s (%.2f MB)", file_path, file_size / (1024 * 1024))
        
        try:
            self.vol_runner = VolatilityRunner(file_path, self._on_progress)
            self.vol_runner.initialize()
            self.battle_console_view.set_dump_file(file_path)
            self.file_tree_view.set_dump_file(file_path)
            self.image_dump_view.set_dump_file(file_path)
            self.status_label.setText(f"Initialized: {os.path.basename(file_path)}")
            self.logger.info("Volatility initialized successfully for %s", file_path)
        except Exception as e:
            self.logger.exception("Failed to initialize Volatility")
            QMessageBox.critical(self, "Error", f"Failed to initialize Volatility3:\n{str(e)}")
    
    def _on_analyze_clicked(self, analysis_type: str):
        """Handle analyze button click"""
        if not self.vol_runner:
            QMessageBox.warning(self, "No File", "Please select a memory dump file first.")
            return
        self.logger.info("Analysis requested: %s", analysis_type)
        
        # Start analysis in background thread
        self._start_analysis(analysis_type)
    
    def _start_analysis(self, analysis_type: str):
        """Start analysis in background thread"""
        self.logger.info("_start_analysis() called with type: %s", analysis_type)
        
        try:
            from .workers import AnalysisWorker
            self.logger.info("AnalysisWorker imported successfully")
        except Exception as e:
            self.logger.exception("Failed to import AnalysisWorker")
            QMessageBox.critical(self, "Error", f"Failed to import worker:\n{str(e)}")
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Starting {analysis_type} analysis...")
        self.overview_view.set_buttons_enabled(False)
        self.logger.info("UI updated, creating worker...")
        
        try:
            self.logger.info("Creating AnalysisWorker instance...")
            self.worker = AnalysisWorker(self.vol_runner, analysis_type)
            self.logger.info("Worker created, connecting signals...")
            self.worker.progress.connect(self._on_progress)
            self.logger.info("Progress signal connected")
            self.worker.finished.connect(self._on_analysis_finished)
            self.logger.info("Finished signal connected")
            self.worker.error.connect(self._on_analysis_error)
            self.logger.info("Error signal connected")
            self.worker.cli_log.connect(self._append_cli_log)
            self.logger.info("CLI log signal connected")
            self.logger.info("Starting worker thread...")
            self.worker.start()  # Start the worker thread!
            self.logger.info("Worker thread started successfully for %s analysis", analysis_type)
        except Exception as e:
            self.progress_bar.setVisible(False)
            self.status_label.setText("Failed to start analysis")
            self.overview_view.set_buttons_enabled(True)
            self.logger.exception("Failed to start worker")
            QMessageBox.critical(self, "Error", f"Failed to start analysis:\n{str(e)}")
    
    def _on_process_dump_requested(self, pid: int):
        """Dump executable modules for a selected process"""
        if not self.vol_runner or not self.current_dump_file:
            QMessageBox.warning(self, "No Memory Image", "Please load a memory dump before dumping processes.")
            return

        # Try to find process object for nicer naming
        proc_obj = next((p for p in self.analysis_report.processes if p.pid == pid), None)
        proc_name = proc_obj.name if proc_obj else f"pid_{pid}"

        self.logger.info("Dump executable requested for PID %s (%s)", pid, proc_name)
        dump_root = Path(self.current_dump_file).parent / "extracted_processes"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_dir = dump_root / f"{proc_name}_{pid}_{timestamp}"
        file_handler_cls = VolatilityRunner.create_disk_file_handler(str(target_dir))
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.status_label.setText(f"Dumping process {pid} modules...")
        
        try:
            self.vol_runner.run_plugin_to_list(
                "windows.dlllist.DllList",
                plugin_args={"pid": [pid], "dump": True},
                file_handler_cls=file_handler_cls
            )
            dumped_files = list(file_handler_cls.created_files)

            # Prefer files that look like the main executable
            from pathlib import Path as _Path
            base_name = _Path(proc_name).name.lower()
            exe_candidates = [
                f for f in dumped_files
                if base_name in _Path(f).name.lower() or _Path(f).suffix.lower() in [".exe", ".dll", ".sys"]
            ]
            primary_files = exe_candidates or dumped_files

            # Keep only primary file(s), delete noisy bins
            if primary_files and dumped_files:
                for f in dumped_files:
                    if f not in primary_files:
                        try:
                            _Path(f).unlink(missing_ok=True)
                        except Exception:
                            pass

            # Compute SHA256 for the first primary file
            sha256_text = ""
            if primary_files:
                primary = _Path(primary_files[0])
                try:
                    import hashlib
                    h = hashlib.sha256()
                    with primary.open("rb") as fh:
                        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                            h.update(chunk)
                    sha256_text = h.hexdigest()
                    if proc_obj:
                        proc_obj.sha256 = sha256_text
                        # Refresh processes view so hash column updates
                        self.processes_view.update_data(self.analysis_report.processes)
                except Exception as e:
                    self.logger.warning("Failed to compute SHA256 for %s: %s", primary, e)

            if primary_files:
                preview = "\n".join(primary_files[:10])
                if len(primary_files) > 10:
                    preview += f"\n... ({len(primary_files) - 10} more)"
                extra = f"\n\nSHA256: {sha256_text}" if sha256_text else ""
                QMessageBox.information(
                    self,
                    "Dump Complete",
                    f"Saved {len(primary_files)} file(s) to:\n{target_dir}\n\n{preview}{extra}"
                )
                self.logger.info("Dumped %d primary files for PID %s into %s", len(primary_files), pid, target_dir)
            else:
                QMessageBox.warning(
                    self,
                    "No Output",
                    "No modules were dumped for this process. The process may have exited or lacks accessible modules."
                )
                self.logger.warning("No files dumped for PID %s", pid)
        except Exception as e:
            self.logger.exception("Failed to dump PID %s", pid)
            QMessageBox.critical(self, "Dump Failed", f"Failed to dump PID {pid}:\n{e}")
        finally:
            self.progress_bar.setVisible(False)
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.status_label.setText("Ready")
    
    def _on_progress(self, progress: float, description: str):
        """Handle progress updates"""
        self.progress_bar.setValue(int(progress))
        self.status_label.setText(description)
        self.logger.debug("Progress %.1f%% - %s", progress, description)
    
    def _compute_sha256(self, path: str) -> str:
        """Compute SHA256 for a file on disk if it exists."""
        if not path:
            return ""
        try:
            file_path = Path(path)
            if not file_path.is_file():
                return ""
            h = hashlib.sha256()
            with file_path.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            self.logger.debug("Failed to compute SHA256 for %s: %s", path, e)
            return ""

    def _on_analysis_finished(self, results: Dict[str, Any]):
        """Handle analysis completion"""
        self.progress_bar.setVisible(False)
        self.status_label.setText("Analysis complete")
        
        # Update analysis report
        from datetime import datetime
        if not self.analysis_report.analysis_timestamp:
            self.analysis_report.analysis_timestamp = datetime.now()
        if not self.analysis_report.dump_file and self.current_dump_file:
            self.analysis_report.dump_file = self.current_dump_file
            self.analysis_report.dump_size = os.path.getsize(self.current_dump_file) if os.path.exists(self.current_dump_file) else 0
        
        if "processes" in results:
            self.analysis_report.processes = results["processes"]
            # Ensure SHA256 is filled for all processes we can read from disk
            for proc in self.analysis_report.processes:
                try:
                    if getattr(proc, "sha256", ""):
                        continue
                except AttributeError:
                    # Older data model without sha256, skip
                    continue
                if proc.full_path:
                    sha = self._compute_sha256(proc.full_path)
                    if sha:
                        proc.sha256 = sha
        if "connections" in results:
            self.analysis_report.connections = results["connections"]
        if "strings" in results:
            self.analysis_report.string_matches = results["strings"]
        if "suspicious" in results:
            self.analysis_report.suspicious_artifacts = results["suspicious"]
        if "decoded" in results:
            # Store decoded strings in a new attribute
            if not hasattr(self.analysis_report, 'decoded_strings'):
                self.analysis_report.decoded_strings = []
            self.analysis_report.decoded_strings = results["decoded"]
        self.logger.info(
            "Analysis results -> processes: %d, connections: %d, strings: %d, decoded: %d",
            len(self.analysis_report.processes),
            len(self.analysis_report.connections),
            len(self.analysis_report.string_matches),
            len(getattr(self.analysis_report, 'decoded_strings', []))
        )
        self.overview_view.set_buttons_enabled(True)
        self.status_label.setText("Analysis complete")
        self.logger.info("Analysis completed successfully")
        
        # Update current view
        if self.current_view == self.processes_view:
            self.processes_view.update_data(self.analysis_report.processes)
        elif self.current_view == self.network_view:
            self.network_view.update_data(self.analysis_report.connections)
        elif self.current_view == self.strings_view:
            self.strings_view.update_data(self.analysis_report.string_matches)
        elif self.current_view == self.decoded_view:
            decoded = getattr(self.analysis_report, 'decoded_strings', [])
            self.decoded_view.update_data(decoded)
        elif self.current_view == self.suspicious_view:
            self.suspicious_view.update_data(self.analysis_report.suspicious_artifacts)
        
        QMessageBox.information(self, "Analysis Complete", "Analysis has completed successfully.")
    
    def _on_analysis_error(self, error: str):
        """Handle analysis error"""
        self.progress_bar.setVisible(False)
        self.status_label.setText("Analysis failed")
        self.overview_view.set_buttons_enabled(True)
        self.logger.error("Analysis failed: %s", error)
        # Show detailed error in message box
        error_dialog = QMessageBox(self)
        error_dialog.setIcon(QMessageBox.Critical)
        error_dialog.setWindowTitle("Analysis Error")
        error_dialog.setText("Analysis failed")
        error_dialog.setDetailedText(error)
        error_dialog.setStandardButtons(QMessageBox.Ok)
        error_dialog.exec()
    
    def _on_settings_clicked(self):
        """Handle settings button click"""
        from .dialogs import SettingsDialog
        dialog = SettingsDialog(self)
        dialog.exec()
    
    def _on_help_clicked(self):
        """Handle help button click"""
        QMessageBox.information(
            self,
            "Help",
            "Volatility3 Memory Analyzer\n\n"
            "1. Select or drag & drop a memory dump file\n"
            "2. Click 'Start Full Analysis' or choose specific analysis\n"
            "3. Navigate through different views to explore results\n"
            "4. Use Battle Console for CLI-style commands with autocomplete\n"
            "5. Use File Tree and Image Dump for field triage outputs\n"
            "6. Use VirusTotal to hash-check dumped files with your API key\n"
            "7. Generate reports from the Reports view\n\n"
            "For raw plugin usage, use the Advanced tab."
        )
    
    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter event"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dropEvent(self, event: QDropEvent):
        """Handle drop event"""
        files = [url.toLocalFile() for url in event.mimeData().urls()]
        if files:
            file_path = files[0]
            # Check if it's a valid memory dump file
            if any(file_path.lower().endswith(ext) for ext in ['.dmp', '.raw', '.vmem', '.img', '.dump']):
                self._on_file_selected(file_path)
                self.overview_view.set_file(file_path)
            else:
                QMessageBox.warning(self, "Invalid File", "Please drop a memory dump file (.dmp, .raw, .vmem, .img, .dump)")

