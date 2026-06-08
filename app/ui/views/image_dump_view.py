"""Image extraction view."""
from datetime import datetime
from pathlib import Path
import sys

from PySide6.QtCore import Signal, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QComboBox,
    QSpinBox,
    QCheckBox,
)

from ..workers import BattleCommandWorker


class ImageDumpView(QWidget):
    """Dumps cached image files and carves image signatures."""

    output_ready = Signal(str)

    def __init__(self):
        super().__init__()
        self.dump_file = None
        self.worker = None
        self.last_output_dir = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        title = QLabel("Image Dump")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        self.dump_label = QLabel("No memory dump loaded")
        layout.addWidget(self.dump_label)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Mode"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["both", "cache", "carve"])
        row1.addWidget(self.mode_combo)

        row1.addWidget(QLabel("Output"))
        self.output_edit = QLineEdit(f"images_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        row1.addWidget(self.output_edit, stretch=1)

        row1.addWidget(QLabel("PID"))
        self.pid_edit = QLineEdit()
        self.pid_edit.setPlaceholderText("optional")
        self.pid_edit.setMaximumWidth(110)
        row1.addWidget(self.pid_edit)

        layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Extensions"))
        self.extensions_edit = QLineEdit("jpg,jpeg,png,gif,bmp,webp,ico,tif,tiff")
        row2.addWidget(self.extensions_edit, stretch=1)

        row2.addWidget(QLabel("Min"))
        self.min_size_edit = QLineEdit("256")
        self.min_size_edit.setMaximumWidth(90)
        row2.addWidget(self.min_size_edit)

        row2.addWidget(QLabel("Max"))
        self.max_size_edit = QLineEdit("32M")
        self.max_size_edit.setMaximumWidth(90)
        row2.addWidget(self.max_size_edit)

        row2.addWidget(QLabel("Limit"))
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(0, 100000)
        self.limit_spin.setValue(0)
        row2.addWidget(self.limit_spin)

        self.validate_check = QCheckBox("Validate")
        self.validate_check.setChecked(True)
        row2.addWidget(self.validate_check)

        self.open_when_done_check = QCheckBox("Open folder")
        self.open_when_done_check.setChecked(True)
        row2.addWidget(self.open_when_done_check)

        self.run_btn = QPushButton("Dump Images")
        self.run_btn.clicked.connect(self.dump_images)
        row2.addWidget(self.run_btn)

        layout.addLayout(row2)

        row3 = QHBoxLayout()
        self.output_path_label = QLabel("Output folder: not created yet")
        row3.addWidget(self.output_path_label, stretch=1)

        self.open_folder_btn = QPushButton("Open Output Folder")
        self.open_folder_btn.setEnabled(False)
        self.open_folder_btn.clicked.connect(self.open_output_folder)
        row3.addWidget(self.open_folder_btn)

        layout.addLayout(row3)

        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
        self.output_log.setLineWrapMode(QTextEdit.NoWrap)
        font = QFont("Consolas")
        font.setPointSize(10)
        self.output_log.setFont(font)
        self.output_log.setStyleSheet("background-color: #101010; color: #d7f7d7;")
        layout.addWidget(self.output_log, stretch=1)

        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

    def set_dump_file(self, dump_file: str):
        self.dump_file = dump_file
        self.dump_label.setText(f"Dump: {dump_file}" if dump_file else "No memory dump loaded")

    def dump_images(self):
        if not self.dump_file:
            self.output_log.setPlainText("Load a memory dump first.")
            return

        self.last_output_dir = self._resolve_output_dir(self.output_edit.text().strip() or "images_gui")
        self.output_path_label.setText(f"Output folder: {self.last_output_dir}")
        self.open_folder_btn.setEnabled(False)

        args = [
            "dump-images",
            "--mode",
            self.mode_combo.currentText(),
            "--out",
            self.output_edit.text().strip() or "images_gui",
            "--extensions",
            self.extensions_edit.text().strip(),
            "--min-size",
            self.min_size_edit.text().strip() or "256",
            "--max-size",
            self.max_size_edit.text().strip() or "32M",
            "--limit",
            str(self.limit_spin.value()),
        ]

        pid = self.pid_edit.text().strip()
        if pid:
            args.extend(["--pid", pid])
        if not self.validate_check.isChecked():
            args.append("--no-validate")

        self.output_log.clear()
        self._append("> " + " ".join(args))
        self.run_btn.setEnabled(False)
        self.status_label.setText("Dumping images...")
        self.worker = BattleCommandWorker(args, self.dump_file)
        self.worker.output.connect(self._append)
        self.worker.error.connect(lambda msg: self._append(f"ERROR: {msg}"))
        self.worker.finished.connect(self._on_worker_finished)
        self.worker.start()

    def _append(self, text: str):
        self.output_log.append(text)

    def _on_worker_finished(self):
        self.run_btn.setEnabled(True)
        if self.last_output_dir and self.last_output_dir.exists():
            self.open_folder_btn.setEnabled(True)
            self.status_label.setText(f"Saved: {self.last_output_dir}")
            self.output_ready.emit(str(self.last_output_dir))
            if self.open_when_done_check.isChecked():
                self.open_output_folder()
        else:
            self.status_label.setText("Ready")

    def open_output_folder(self):
        if self.last_output_dir and self.last_output_dir.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.last_output_dir)))

    @staticmethod
    def _battle_output_root() -> Path:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent / "battle_out"
        return Path(__file__).resolve().parents[3] / "battle_out"

    def _resolve_output_dir(self, output_name: str) -> Path:
        path = Path(output_name)
        if path.is_absolute():
            return path
        return self._battle_output_root() / path
