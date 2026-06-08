"""VirusTotal hash reputation view."""
import os
from pathlib import Path

from PySide6.QtCore import Qt, QUrl, QSettings
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QFileDialog,
    QSpinBox,
    QCheckBox,
)

from ..workers import VirusTotalWorker, collect_files


class VirusTotalView(QWidget):
    """Checks local files against VirusTotal by hash only."""

    def __init__(self):
        super().__init__()
        self.worker = None
        self.results = []
        self.settings = QSettings("Volatility3", "Volatility3Analyzer")
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        title = QLabel("VirusTotal Hash Check")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("API Key"))
        saved_key = self.settings.value("virustotal/api_key", os.environ.get("VT_API_KEY", ""))
        self.api_key_edit = QLineEdit(saved_key)
        self.api_key_edit.setEchoMode(QLineEdit.Password)
        self.api_key_edit.setPlaceholderText("VirusTotal API key")
        key_row.addWidget(self.api_key_edit, stretch=1)

        get_key_btn = QPushButton("Get Key")
        get_key_btn.clicked.connect(self.open_key_page)
        key_row.addWidget(get_key_btn)

        save_key_btn = QPushButton("Save Key")
        save_key_btn.clicked.connect(self.save_key)
        key_row.addWidget(save_key_btn)

        layout.addLayout(key_row)

        target_row = QHBoxLayout()
        target_row.addWidget(QLabel("Target"))
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Folder or file to hash-check")
        target_row.addWidget(self.target_edit, stretch=1)

        browse_file_btn = QPushButton("File")
        browse_file_btn.clicked.connect(self.browse_file)
        target_row.addWidget(browse_file_btn)

        browse_folder_btn = QPushButton("Folder")
        browse_folder_btn.clicked.connect(self.browse_folder)
        target_row.addWidget(browse_folder_btn)

        layout.addLayout(target_row)

        scan_row = QHBoxLayout()
        scan_row.addWidget(QLabel("Max files"))
        self.max_files_spin = QSpinBox()
        self.max_files_spin.setRange(1, 1000)
        self.max_files_spin.setValue(25)
        scan_row.addWidget(self.max_files_spin)

        self.executables_only_check = QCheckBox("Executables only")
        self.executables_only_check.setChecked(True)
        scan_row.addWidget(self.executables_only_check)

        self.scan_btn = QPushButton("Check Hashes")
        self.scan_btn.clicked.connect(self.scan)
        scan_row.addWidget(self.scan_btn)

        self.open_report_btn = QPushButton("Open VT Report")
        self.open_report_btn.clicked.connect(self.open_selected_report)
        scan_row.addWidget(self.open_report_btn)

        scan_row.addStretch()
        layout.addLayout(scan_row)

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(
            ["Verdict", "Mal", "Susp", "Harmless", "Undetected", "File", "SHA256", "Note"]
        )
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, stretch=1)

        self.status_label = QLabel("Hash lookup only. Unknown files are not uploaded.")
        layout.addWidget(self.status_label)

    def set_target_path(self, path: str):
        self.target_edit.setText(path)
        self.status_label.setText(f"Target set: {path}")

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file for VirusTotal hash check")
        if path:
            self.set_target_path(path)

    def browse_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select folder for VirusTotal hash check")
        if path:
            self.set_target_path(path)

    def open_key_page(self):
        QDesktopServices.openUrl(QUrl("https://www.virustotal.com/gui/my-apikey"))
        self.status_label.setText("Opened VirusTotal API key page in browser.")

    def save_key(self):
        api_key = self.api_key_edit.text().strip()
        if not api_key:
            self.status_label.setText("Paste your API key before saving.")
            return
        self.settings.setValue("virustotal/api_key", api_key)
        self.status_label.setText("VirusTotal API key saved locally for this Windows user.")

    def scan(self):
        api_key = self.api_key_edit.text().strip()
        target = Path(self.target_edit.text().strip())
        if not api_key:
            self.status_label.setText("Enter a VirusTotal API key first.")
            return
        if not target.exists():
            self.status_label.setText("Select an existing file or folder first.")
            return

        paths = collect_files(
            target,
            self.max_files_spin.value(),
            self.executables_only_check.isChecked(),
        )
        if not paths:
            self.status_label.setText("No matching files found.")
            return

        self.results = []
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.scan_btn.setEnabled(False)
        self.status_label.setText(f"Checking {len(paths)} file(s)...")
        self.worker = VirusTotalWorker(paths, api_key)
        self.worker.result.connect(self.add_result)
        self.worker.progress.connect(self.status_label.setText)
        self.worker.error.connect(lambda msg: self.status_label.setText(f"Error: {msg}"))
        self.worker.finished.connect(self._on_finished)
        self.worker.start()

    def add_result(self, result: dict):
        self.results.append(result)
        row = self.table.rowCount()
        self.table.insertRow(row)

        verdict = self._verdict(result)
        values = [
            verdict,
            str(result.get("malicious", 0)),
            str(result.get("suspicious", 0)),
            str(result.get("harmless", 0)),
            str(result.get("undetected", 0)),
            result.get("name", ""),
            result.get("sha256", ""),
            result.get("message", ""),
        ]
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            if verdict == "Malicious":
                item.setBackground(Qt.darkRed)
            elif verdict == "Suspicious":
                item.setBackground(Qt.darkYellow)
            elif verdict == "Unknown":
                item.setBackground(Qt.darkGray)
            self.table.setItem(row, col, item)

    def open_selected_report(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.results):
            return
        link = self.results[row].get("link", "")
        if link:
            QDesktopServices.openUrl(QUrl(link))

    def _on_finished(self):
        self.scan_btn.setEnabled(True)
        self.table.setSortingEnabled(True)
        self.status_label.setText(f"Done. Checked {len(self.results)} file(s).")

    @staticmethod
    def _verdict(result: dict) -> str:
        if result.get("malicious", 0) > 0:
            return "Malicious"
        if result.get("suspicious", 0) > 0:
            return "Suspicious"
        if result.get("status") == "not-found":
            return "Unknown"
        if result.get("status") in {"auth-error", "rate-limited", "network-error"}:
            return "Error"
        return "Clean"
