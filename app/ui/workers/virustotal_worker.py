"""VirusTotal hash lookup worker."""
import hashlib
import json
import time
from pathlib import Path
from typing import Iterable, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from PySide6.QtCore import QThread, Signal


class VirusTotalWorker(QThread):
    """Looks up file SHA256 hashes in VirusTotal."""

    result = Signal(dict)
    progress = Signal(str)
    error = Signal(str)
    finished = Signal()

    def __init__(self, paths: List[str], api_key: str, delay_seconds: float = 1.0):
        super().__init__()
        self.paths = paths
        self.api_key = api_key
        self.delay_seconds = delay_seconds

    def run(self):
        try:
            if not self.api_key:
                raise ValueError("VirusTotal API key is required")

            for index, path_text in enumerate(self.paths, start=1):
                path = Path(path_text)
                self.progress.emit(f"Checking {index}/{len(self.paths)}: {path.name}")
                sha256 = self._sha256(path)
                result = self._lookup_hash(path, sha256)
                self.result.emit(result)
                if index < len(self.paths):
                    time.sleep(self.delay_seconds)
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            self.finished.emit()

    def _lookup_hash(self, path: Path, sha256: str) -> dict:
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        request = Request(url, headers={"x-apikey": self.api_key})

        base = {
            "path": str(path),
            "name": path.name,
            "size": path.stat().st_size,
            "sha256": sha256,
            "status": "unknown",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "link": f"https://www.virustotal.com/gui/file/{sha256}",
            "message": "",
        }

        try:
            with urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
        except HTTPError as exc:
            if exc.code == 404:
                base["status"] = "not-found"
                base["message"] = "Hash not found in VirusTotal"
                return base
            if exc.code in {401, 403}:
                base["status"] = "auth-error"
                base["message"] = "Invalid or unauthorized API key"
                return base
            if exc.code == 429:
                base["status"] = "rate-limited"
                base["message"] = "VirusTotal rate limit reached"
                return base
            base["status"] = f"http-{exc.code}"
            base["message"] = str(exc)
            return base
        except URLError as exc:
            base["status"] = "network-error"
            base["message"] = str(exc.reason)
            return base

        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)

        base.update(
            {
                "status": "detected" if malicious or suspicious else "clean-or-unknown",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": int(stats.get("harmless", 0) or 0),
                "undetected": int(stats.get("undetected", 0) or 0),
                "message": attributes.get("meaningful_name", ""),
            }
        )
        return base

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


def collect_files(root: Path, max_files: int, executable_only: bool) -> List[str]:
    """Collect candidate files from a file or folder."""
    if root.is_file():
        return [str(root)]

    executable_suffixes = {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".dmp"}
    files: List[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if executable_only and path.suffix.lower() not in executable_suffixes:
            continue
        files.append(str(path))
        if len(files) >= max_files:
            break
    return files
