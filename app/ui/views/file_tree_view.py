"""Memory artifact file tree view."""
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
    QFileDialog,
)

from ..workers import BattleCommandWorker


class FileTreeView(QWidget):
    """Builds a directory tree from Volatility file artifacts."""

    def __init__(self):
        super().__init__()
        self.dump_file = None
        self.worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        title = QLabel("File Tree")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        self.dump_label = QLabel("No memory dump loaded")
        layout.addWidget(self.dump_label)

        controls = QHBoxLayout()

        controls.addWidget(QLabel("Source"))
        self.source_combo = QComboBox()
        self.source_combo.addItems(["filescan", "mft"])
        controls.addWidget(self.source_combo)

        controls.addWidget(QLabel("Filter"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Users, AppData, Windows...")
        controls.addWidget(self.filter_edit, stretch=1)

        controls.addWidget(QLabel("Lines"))
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(20, 5000)
        self.limit_spin.setValue(500)
        controls.addWidget(self.limit_spin)

        controls.addWidget(QLabel("Depth"))
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(0, 20)
        self.depth_spin.setValue(0)
        controls.addWidget(self.depth_spin)

        self.render_btn = QPushButton("Render")
        self.render_btn.clicked.connect(self.render_tree)
        controls.addWidget(self.render_btn)

        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.save_tree)
        controls.addWidget(self.save_btn)

        layout.addLayout(controls)

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

    def render_tree(self):
        if not self.dump_file:
            self.output_edit.setPlainText("Load a memory dump first.")
            return

        args = [
            "tree",
            "--source",
            self.source_combo.currentText(),
            "--limit",
            str(self.limit_spin.value()),
            "--depth",
            str(self.depth_spin.value()),
        ]
        filter_text = self.filter_edit.text().strip()
        if filter_text:
            args.extend(["--filter", filter_text])

        self.output_edit.clear()
        self._append("> " + " ".join(args))
        self.render_btn.setEnabled(False)
        self.status_label.setText("Rendering tree...")
        self.worker = BattleCommandWorker(args, self.dump_file)
        self.worker.output.connect(self._append)
        self.worker.error.connect(lambda msg: self._append(f"ERROR: {msg}"))
        self.worker.finished.connect(self._on_worker_finished)
        self.worker.start()

    def save_tree(self):
        text = self.output_edit.toPlainText()
        if not text.strip():
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save File Tree",
            "file_tree.txt",
            "Text Files (*.txt);;All Files (*.*)",
        )
        if path:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            self.status_label.setText(f"Saved: {path}")

    def _append(self, text: str):
        self.output_edit.append(text)

    def _on_worker_finished(self):
        self.render_btn.setEnabled(True)
        self.status_label.setText("Ready")
