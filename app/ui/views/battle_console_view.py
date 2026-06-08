"""Integrated Battle CLI console view."""
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QCompleter,
)

from battle_cli import COMMANDS, PLUGIN_ALIASES, split_command
from ..workers import BattleCommandWorker


class BattleConsoleView(QWidget):
    """Runs Battle CLI commands from inside the GUI."""

    def __init__(self):
        super().__init__()
        self.dump_file = None
        self.worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        title = QLabel("Battle Console")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        self.dump_label = QLabel("No memory dump loaded")
        layout.addWidget(self.dump_label)

        quick_layout = QHBoxLayout()
        for label, command in [
            ("Info", "info --limit 40"),
            ("Processes", "ps --limit 80"),
            ("Tree", "tree --source filescan --limit 120"),
            ("Images", "dump-images --mode both --out images_gui --max-size 32M"),
            ("Triage", "triage --skip-heavy"),
        ]:
            button = QPushButton(label)
            button.clicked.connect(lambda checked=False, cmd=command: self.run_command(cmd))
            quick_layout.addWidget(button)
        quick_layout.addStretch()
        layout.addLayout(quick_layout)

        command_layout = QHBoxLayout()
        self.command_edit = QLineEdit()
        self.command_edit.setPlaceholderText("Run Battle CLI command...")
        self.command_edit.returnPressed.connect(self._on_run_clicked)
        completions = sorted(
            set(
                COMMANDS
                + list(PLUGIN_ALIASES)
                + list(PLUGIN_ALIASES.values())
                + [
                    "windows.info.Info",
                    "windows.pslist.PsList",
                    "windows.pstree.PsTree",
                    "windows.filescan.FileScan",
                    "windows.dumpfiles.DumpFiles",
                    "windows.malware.malfind.Malfind",
                ]
            )
        )
        completer = QCompleter(completions, self)
        completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.command_edit.setCompleter(completer)
        command_layout.addWidget(self.command_edit)

        self.run_btn = QPushButton("Run")
        self.run_btn.clicked.connect(self._on_run_clicked)
        command_layout.addWidget(self.run_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.output_edit_clear)
        command_layout.addWidget(clear_btn)

        layout.addLayout(command_layout)

        self.output_edit = QTextEdit()
        self.output_edit.setReadOnly(True)
        self.output_edit.setLineWrapMode(QTextEdit.NoWrap)
        font = QFont("Consolas")
        font.setPointSize(10)
        self.output_edit.setFont(font)
        self.output_edit.setStyleSheet("background-color: #101010; color: #d7f7d7;")
        layout.addWidget(self.output_edit, stretch=1)

        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

    def set_dump_file(self, dump_file: str):
        self.dump_file = dump_file
        self.dump_label.setText(f"Dump: {dump_file}" if dump_file else "No memory dump loaded")

    def _on_run_clicked(self):
        self.run_command(self.command_edit.text().strip())

    def output_edit_clear(self):
        self.output_edit.clear()

    def run_command(self, command: str):
        if not command:
            return
        args = split_command(command)
        if not args:
            return
        if not self.dump_file and args[0] not in {"help", "status", "plugins"}:
            self._append("Load a memory dump first.\n")
            return

        self.command_edit.setText(command)
        self._append(f"\n> {command}\n")
        self.run_btn.setEnabled(False)
        self.status_label.setText("Running...")
        self.worker = BattleCommandWorker(args, self.dump_file)
        self.worker.output.connect(self._append)
        self.worker.error.connect(lambda msg: self._append(f"ERROR: {msg}"))
        self.worker.finished.connect(self._on_worker_finished)
        self.worker.start()

    def _append(self, text: str):
        self.output_edit.append(text)

    def _on_worker_finished(self):
        self.run_btn.setEnabled(True)
        self.status_label.setText("Ready")
