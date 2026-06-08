"""Worker for running Battle CLI commands from the GUI."""
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import QThread, Signal


class BattleCommandWorker(QThread):
    """Runs one Battle CLI command in a background subprocess."""

    output = Signal(str)
    error = Signal(str)
    finished = Signal()

    def __init__(self, command_args: List[str], dump_file: Optional[str] = None):
        super().__init__()
        self.command_args = command_args
        self.dump_file = dump_file

    def run(self):
        try:
            if getattr(sys, "frozen", False):
                cmd = [sys.executable, "--cli", "--quiet"]
                cwd = str(Path(sys.executable).resolve().parent)
            else:
                project_root = Path(__file__).resolve().parents[3]
                cmd = [
                    sys.executable,
                    str(project_root / "app" / "main.py"),
                    "--cli",
                    "--quiet",
                ]
                cwd = str(project_root)

            if self.dump_file:
                cmd.extend(["-f", self.dump_file])
            cmd.extend(self.command_args)

            self.output.emit("COMMAND: " + " ".join(self._quote(part) for part in cmd))

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=cwd,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )

            assert process.stdout is not None
            for line in iter(process.stdout.readline, ""):
                text = line.rstrip("\r\n")
                if text:
                    self.output.emit(text)

            process.wait()
            if process.returncode != 0:
                self.error.emit(f"Command exited with code {process.returncode}")
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            self.finished.emit()

    @staticmethod
    def _quote(text: str) -> str:
        if any(ch.isspace() for ch in text):
            return f'"{text}"'
        return text
