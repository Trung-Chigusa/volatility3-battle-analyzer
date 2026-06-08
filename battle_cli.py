#!/usr/bin/env python3
"""Portable field CLI for the local Volatility3 bundle.

The goal of this wrapper is practical memory-forensics workflow:
interactive tab completion, repeatable triage commands, image extraction, and
filesystem tree views without modifying Volatility3's original CLI.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import mmap
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


FROZEN = bool(getattr(sys, "frozen", False))
EXE_DIR = Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent
BUNDLE_ROOT = Path(getattr(sys, "_MEIPASS", EXE_DIR)).resolve() if FROZEN else EXE_DIR
TOOL_ROOT = EXE_DIR
VOL_BUNDLE = BUNDLE_ROOT / "volatility3-2.26.2"
DEFAULT_OUTPUT_ROOT = EXE_DIR / "battle_out"
DEFAULT_CACHE_PATH = EXE_DIR / ".vol3_cache"

if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))
if VOL_BUNDLE.is_dir() and str(VOL_BUNDLE) not in sys.path:
    sys.path.insert(0, str(VOL_BUNDLE))


COMMANDS = [
    "help",
    "status",
    "setdump",
    "plugins",
    "info",
    "ps",
    "pstree",
    "psscan",
    "cmdline",
    "net",
    "files",
    "tree",
    "run",
    "vol",
    "triage",
    "dump-images",
    "carve-images",
    "dump-proc",
    "clear",
    "exit",
    "quit",
]

PLUGIN_ALIASES = {
    "info": "windows.info.Info",
    "ps": "windows.pslist.PsList",
    "pslist": "windows.pslist.PsList",
    "pstree": "windows.pstree.PsTree",
    "psscan": "windows.psscan.PsScan",
    "cmdline": "windows.cmdline.CmdLine",
    "net": "windows.netstat.NetStat",
    "netstat": "windows.netstat.NetStat",
    "netscan": "windows.netscan.NetScan",
    "files": "windows.filescan.FileScan",
    "filescan": "windows.filescan.FileScan",
    "mft": "windows.mftscan.MFTScan",
    "mftscan": "windows.mftscan.MFTScan",
    "malfind": "windows.malware.malfind.Malfind",
    "psxview": "windows.malware.psxview.PsXView",
    "dlllist": "windows.dlllist.DllList",
    "dumpfiles": "windows.dumpfiles.DumpFiles",
    "handles": "windows.handles.Handles",
    "svcscan": "windows.svcscan.SvcScan",
}

IMAGE_EXTENSIONS = {
    "jpg",
    "jpeg",
    "png",
    "gif",
    "bmp",
    "webp",
    "ico",
    "tif",
    "tiff",
}

CARVE_FORMAT_EXTENSIONS = {
    "jpg": {"jpg", "jpeg"},
    "png": {"png"},
    "gif": {"gif"},
    "bmp": {"bmp"},
    "webp": {"webp"},
    "ico": {"ico"},
}


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def default_symbol_dirs() -> List[Path]:
    candidates = [
        EXE_DIR / "symbols",
        EXE_DIR / "volatility3" / "symbols",
        EXE_DIR / "volatility3" / "framework" / "symbols",
        BUNDLE_ROOT / "symbols",
        BUNDLE_ROOT / "volatility3" / "symbols",
        BUNDLE_ROOT / "volatility3" / "framework" / "symbols",
        VOL_BUNDLE / "volatility3" / "symbols",
        VOL_BUNDLE / "volatility3" / "framework" / "symbols",
    ]
    result: List[Path] = []
    seen = set()
    for path in candidates:
        if path.is_dir():
            resolved = path.resolve()
            if resolved not in seen:
                result.append(resolved)
                seen.add(resolved)
    return result


def configure_portable_volatility(
    cache_path: Path,
    symbol_dirs: Sequence[Path],
    offline: bool,
) -> None:
    """Point Volatility runtime state at folders inside this portable bundle."""
    cache_path.mkdir(parents=True, exist_ok=True)
    try:
        from volatility3.framework import constants
        import volatility3.symbols

        constants.CACHE_PATH = str(cache_path)
        constants.OFFLINE = offline

        existing = [str(p) for p in getattr(volatility3.symbols, "__path__", [])]
        portable_symbols = [str(p.resolve()) for p in symbol_dirs if p.is_dir()]
        merged = []
        for item in portable_symbols + existing:
            if item not in merged:
                merged.append(item)
        volatility3.symbols.__path__ = merged
    except Exception:
        # The caller will surface concrete Volatility import errors later.
        pass


def parse_size(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([kmgt]?b?)?\s*", value, re.I)
    if not match:
        raise ValueError(f"Invalid size: {value}")
    number = int(match.group(1))
    suffix = (match.group(2) or "").lower()
    factor = {
        "": 1,
        "b": 1,
        "k": 1024,
        "kb": 1024,
        "m": 1024**2,
        "mb": 1024**2,
        "g": 1024**3,
        "gb": 1024**3,
        "t": 1024**4,
        "tb": 1024**4,
    }[suffix]
    return number * factor


def parse_value(raw: str) -> Any:
    text = raw.strip()
    if not text:
        return ""
    lowered = text.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if "," in text:
        return [parse_value(item) for item in text.split(",")]
    try:
        if lowered.startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        return text


def split_command(line: str) -> List[str]:
    try:
        parts = shlex.split(line, posix=False)
    except ValueError:
        parts = line.split()
    return [strip_outer_quotes(part) for part in parts]


def strip_outer_quotes(text: str) -> str:
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1]
    return text


def normalize_cell(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    if text in {"N/A", "UnreadableValue", "UnparsableValue", "NotApplicableValue"}:
        return ""
    return text.replace("\r", " ").replace("\n", " ")


def print_table(rows: List[Dict[str, Any]], limit: int = 80, max_width: int = 56) -> None:
    if not rows:
        print("No rows returned.")
        return

    headers = list(rows[0].keys())
    for row in rows[1:]:
        for key in row.keys():
            if key not in headers:
                headers.append(key)

    visible_rows = rows[:limit]
    widths = {}
    for header in headers:
        width = len(header)
        for row in visible_rows:
            width = max(width, len(normalize_cell(row.get(header, ""))))
        widths[header] = min(width, max_width)

    def fit(text: str, width: int) -> str:
        if len(text) > width:
            if width <= 3:
                return text[:width]
            return text[: width - 3] + "..."
        return text.ljust(width)

    header_line = " | ".join(fit(header, widths[header]) for header in headers)
    print(header_line)
    print("-" * len(header_line))
    for row in visible_rows:
        print(
            " | ".join(
                fit(normalize_cell(row.get(header, "")), widths[header])
                for header in headers
            )
        )
    if len(rows) > limit:
        print(f"... {len(rows) - limit} more rows not shown. Use --limit to show more.")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, default=str)


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    headers: List[str] = []
    for row in rows:
        for key in row.keys():
            if key not in headers:
                headers.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: normalize_cell(row.get(key, "")) for key in headers})


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_image_format(header: bytes) -> Optional[str]:
    if header.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if header.startswith(b"BM"):
        return "bmp"
    if len(header) >= 12 and header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return "webp"
    if header.startswith(b"\x00\x00\x01\x00"):
        return "ico"
    if header.startswith((b"II*\x00", b"MM\x00*")):
        return "tiff"
    return None


def validate_image_bytes(data: bytes, enabled: bool) -> Tuple[bool, str]:
    if not enabled:
        return True, "validation-disabled"
    try:
        from PIL import Image
    except Exception:
        return True, "pillow-not-installed"
    try:
        with Image.open(io.BytesIO(data)) as image:
            image.verify()
        return True, "ok"
    except Exception as exc:
        return False, str(exc)


def inspect_image_file(path: Path, validate: bool) -> Dict[str, Any]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        header = handle.read(64)
        detected = detect_image_format(header)
        sample = header + handle.read(min(size, 1024 * 1024))
    valid, note = validate_image_bytes(sample, validate) if detected else (False, "unknown-header")
    return {
        "path": str(path),
        "size": size,
        "format": detected or "",
        "sha256": sha256_file(path) if size else "",
        "valid": valid,
        "note": note,
    }


@dataclass
class BattleContext:
    dump_file: Optional[Path]
    output_root: Path
    cache_path: Path
    symbol_dirs: List[Path]
    offline: bool = True
    quiet: bool = False

    def __post_init__(self) -> None:
        self.output_root = self.output_root.resolve()
        self.cache_path = self.cache_path.resolve()
        self.symbol_dirs = [path.resolve() for path in self.symbol_dirs]
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.cache_path.mkdir(parents=True, exist_ok=True)
        self._runner = None
        self._plugin_cache: Optional[Dict[str, Any]] = None
        if self.dump_file:
            self.set_dump(self.dump_file)
        configure_portable_volatility(self.cache_path, self.symbol_dirs, self.offline)

    def set_dump(self, dump_file: Path | str) -> None:
        path = Path(dump_file).expanduser()
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Memory dump not found: {path}")
        self.dump_file = path
        self._runner = None

    def require_dump(self) -> Path:
        if not self.dump_file:
            raise RuntimeError("No dump selected. Use: setdump <path> or start with -f <path>.")
        return self.dump_file

    def progress(self, progress: float, description: str) -> None:
        if self.quiet:
            return
        sys.stderr.write(f"\r[{progress:6.2f}%] {description[:96]:96}")
        if progress >= 100:
            sys.stderr.write("\n")
        sys.stderr.flush()

    def plugin_map(self) -> Dict[str, Any]:
        if self._plugin_cache is None:
            configure_portable_volatility(self.cache_path, self.symbol_dirs, self.offline)
            import volatility3.plugins
            from volatility3 import framework

            framework.require_interface_version(2, 0, 0)
            framework.import_files(volatility3.plugins, True)
            self._plugin_cache = framework.list_plugins()
        return self._plugin_cache

    def runner(self):
        if self._runner is None:
            configure_portable_volatility(self.cache_path, self.symbol_dirs, self.offline)
            from app.core.vol_runner import VolatilityRunner

            self._runner = VolatilityRunner(str(self.require_dump()), self.progress)
            self._runner.initialize()
            self._plugin_cache = self._runner.get_available_plugins()
        return self._runner

    def run_plugin(
        self,
        plugin_name: str,
        plugin_args: Optional[Dict[str, Any]] = None,
        file_handler_cls: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        resolved = resolve_plugin(self, plugin_name)
        return self.runner().run_plugin_to_list(
            resolved,
            plugin_args=plugin_args or {},
            file_handler_cls=file_handler_cls,
        )

    def output_path(self, name: str) -> Path:
        path = Path(name)
        if not path.is_absolute():
            path = self.output_root / path
        return path.resolve()


def resolve_plugin(ctx: BattleContext, name: str) -> str:
    candidate = PLUGIN_ALIASES.get(name.lower(), name)
    plugins = ctx.plugin_map()
    if candidate in plugins:
        return candidate

    lowered = candidate.lower()
    exact_case = [plugin for plugin in plugins if plugin.lower() == lowered]
    if len(exact_case) == 1:
        return exact_case[0]

    suffix = "." + lowered
    suffix_matches = [plugin for plugin in plugins if plugin.lower().endswith(suffix)]
    if len(suffix_matches) == 1:
        return suffix_matches[0]

    contains = [plugin for plugin in plugins if lowered in plugin.lower()]
    if len(contains) == 1:
        return contains[0]
    if contains:
        preview = ", ".join(sorted(contains)[:12])
        raise ValueError(f"Ambiguous plugin '{name}'. Matches: {preview}")
    raise ValueError(f"Plugin not found: {name}")


def build_image_regex(extensions: Iterable[str]) -> str:
    normalized = sorted({ext.lower().lstrip(".") for ext in extensions})
    normalized = ["jpe?g" if ext in {"jpg", "jpeg"} else ext for ext in normalized]
    normalized = ["tiff?" if ext in {"tif", "tiff"} else ext for ext in normalized]
    parts = sorted(set(normalized))
    return r"\.(?:" + "|".join(parts) + r")(?:$|[\\/\?#:\s])"


def enabled_carve_formats(extensions: Iterable[str]) -> List[str]:
    requested = {ext.lower().lstrip(".") for ext in extensions}
    formats = []
    for fmt, aliases in CARVE_FORMAT_EXTENSIONS.items():
        if requested & aliases:
            formats.append(fmt)
    return formats


def extract_uint32_le(data: bytes) -> int:
    return int.from_bytes(data[:4], "little", signed=False)


def carve_end(mm: mmap.mmap, start: int, fmt: str, max_size: int) -> Optional[int]:
    file_size = len(mm)
    max_end = min(file_size, start + max_size)

    if fmt == "jpg":
        end = mm.find(b"\xff\xd9", start + 3, max_end)
        return end + 2 if end >= 0 else None

    if fmt == "png":
        end = mm.find(b"IEND\xaeB\x60\x82", start + 8, max_end)
        return end + 8 if end >= 0 else None

    if fmt == "gif":
        end = mm.find(b"\x3b", start + 13, max_end)
        return end + 1 if end >= 0 else None

    if fmt == "bmp":
        if start + 14 > file_size:
            return None
        total = extract_uint32_le(mm[start + 2 : start + 6])
        pixel_offset = extract_uint32_le(mm[start + 10 : start + 14])
        if 54 <= pixel_offset <= total <= max_size and start + total <= file_size:
            return start + total
        return None

    if fmt == "webp":
        if start + 12 > file_size or mm[start + 8 : start + 12] != b"WEBP":
            return None
        riff_size = extract_uint32_le(mm[start + 4 : start + 8])
        total = riff_size + 8
        if 12 <= total <= max_size and start + total <= file_size:
            return start + total
        return None

    if fmt == "ico":
        if start + 6 > file_size:
            return None
        count = int.from_bytes(mm[start + 4 : start + 6], "little", signed=False)
        if not 1 <= count <= 64:
            return None
        directory_end = start + 6 + (count * 16)
        if directory_end > file_size:
            return None
        end = directory_end
        for index in range(count):
            entry = start + 6 + (index * 16)
            size = extract_uint32_le(mm[entry + 8 : entry + 12])
            offset = extract_uint32_le(mm[entry + 12 : entry + 16])
            if size == 0 or offset < 6 or offset > max_size:
                return None
            end = max(end, start + offset + size)
        if start < end <= max_end:
            return end
        return None

    return None


def carve_images(
    dump_path: Path,
    output_dir: Path,
    extensions: Iterable[str],
    min_size: int,
    max_size: int,
    limit: int,
    validate: bool,
    progress: Optional[Callable[[float, str], None]] = None,
) -> List[Dict[str, Any]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    patterns = {
        "jpg": [b"\xff\xd8\xff"],
        "png": [b"\x89PNG\r\n\x1a\n"],
        "gif": [b"GIF87a", b"GIF89a"],
        "bmp": [b"BM"],
        "webp": [b"RIFF"],
        "ico": [b"\x00\x00\x01\x00"],
    }
    formats = enabled_carve_formats(extensions)
    records: List[Dict[str, Any]] = []
    seen_offsets = set()
    dump_size = dump_path.stat().st_size
    start_time = time.time()

    with dump_path.open("rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for fmt_index, fmt in enumerate(formats):
                if progress:
                    progress((fmt_index / max(len(formats), 1)) * 100, f"Carving {fmt}")
                for signature in patterns[fmt]:
                    pos = 0
                    while True:
                        start = mm.find(signature, pos)
                        if start < 0:
                            break
                        if start in seen_offsets:
                            pos = start + 1
                            continue
                        if fmt == "webp" and (
                            start + 12 > dump_size or mm[start + 8 : start + 12] != b"WEBP"
                        ):
                            pos = start + 1
                            continue
                        end = carve_end(mm, start, fmt, max_size)
                        if not end or end - start < min_size:
                            pos = start + 1
                            continue

                        data = mm[start:end]
                        valid, note = validate_image_bytes(data, validate)
                        if not valid:
                            pos = start + 1
                            continue

                        digest = hashlib.sha256(data).hexdigest()
                        ext = "jpg" if fmt == "jpg" else fmt
                        name = f"{fmt}_{start:012x}_{digest[:12]}.{ext}"
                        target = output_dir / name
                        with target.open("wb") as out:
                            out.write(data)

                        record = {
                            "source": "carve",
                            "path": str(target),
                            "format": fmt,
                            "offset": f"0x{start:x}",
                            "size": end - start,
                            "sha256": digest,
                            "valid": valid,
                            "note": note,
                        }
                        records.append(record)
                        seen_offsets.add(start)
                        if limit and len(records) >= limit:
                            if progress:
                                progress(100, "Carving limit reached")
                            return records
                        pos = end

    if progress:
        elapsed = time.time() - start_time
        progress(100, f"Carved {len(records)} images in {elapsed:.1f}s")
    return records


class TreeNode:
    def __init__(self) -> None:
        self.children: Dict[str, "TreeNode"] = {}
        self.count = 0

    def add(self, parts: Sequence[str]) -> None:
        node = self
        node.count += 1
        for part in parts:
            if not part:
                continue
            node = node.children.setdefault(part, TreeNode())
            node.count += 1


def split_memory_path(path: str) -> List[str]:
    text = normalize_cell(path).strip().strip('"')
    if not text:
        return []
    text = re.sub(r"^\\\\\?\\", "", text)
    text = text.replace("\\??\\", "")
    text = text.replace("/", "\\")
    parts = [part for part in re.split(r"\\+", text) if part]
    return parts


def render_tree(root: TreeNode, limit: int, max_depth: int) -> List[str]:
    lines: List[str] = []

    def walk(node: TreeNode, prefix: str, depth: int) -> None:
        if len(lines) >= limit:
            return
        if max_depth and depth >= max_depth:
            return
        items = sorted(node.children.items(), key=lambda item: item[0].lower())
        for index, (name, child) in enumerate(items):
            if len(lines) >= limit:
                return
            last = index == len(items) - 1
            connector = "`-- " if last else "+-- "
            count = f" ({child.count})" if child.children else ""
            lines.append(f"{prefix}{connector}{name}{count}")
            walk(child, prefix + ("    " if last else "|   "), depth + 1)

    walk(root, "", 0)
    if len(lines) >= limit:
        lines.append(f"... output limited at {limit} lines")
    return lines


class LineEditor:
    def __init__(self, completer: Callable[[str], Tuple[str, List[str]]]) -> None:
        self.completer = completer
        self.history: List[str] = []
        self._readline_ready = False
        if os.name != "nt":
            try:
                import readline

                def complete(text: str, state: int):
                    buffer = readline.get_line_buffer()
                    _new, choices = self.completer(buffer)
                    return choices[state] if state < len(choices) else None

                readline.set_completer(complete)
                readline.parse_and_bind("tab: complete")
                self._readline_ready = True
            except Exception:
                self._readline_ready = False

    def readline(self, prompt: str) -> str:
        if os.name != "nt" or not sys.stdin.isatty():
            return input(prompt)
        import msvcrt

        buffer = ""
        history_index = len(self.history)

        def redraw() -> None:
            sys.stdout.write("\r" + prompt + buffer + " " * 20)
            sys.stdout.write("\r" + prompt + buffer)
            sys.stdout.flush()

        sys.stdout.write(prompt)
        sys.stdout.flush()
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                sys.stdout.write("\n")
                if buffer.strip():
                    self.history.append(buffer)
                return buffer
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch == "\x1a":
                raise EOFError
            if ch == "\b":
                if buffer:
                    buffer = buffer[:-1]
                    redraw()
                continue
            if ch == "\t":
                new_buffer, choices = self.completer(buffer)
                if new_buffer != buffer:
                    buffer = new_buffer
                    redraw()
                elif choices:
                    sys.stdout.write("\n")
                    print_columns(choices)
                    redraw()
                continue
            if ch in ("\x00", "\xe0"):
                code = msvcrt.getwch()
                if code == "H" and self.history:
                    history_index = max(0, history_index - 1)
                    buffer = self.history[history_index]
                    redraw()
                elif code == "P" and self.history:
                    history_index = min(len(self.history), history_index + 1)
                    buffer = self.history[history_index] if history_index < len(self.history) else ""
                    redraw()
                continue
            buffer += ch
            sys.stdout.write(ch)
            sys.stdout.flush()


def print_columns(items: Sequence[str], width: int = 32) -> None:
    if not items:
        return
    columns = max(1, min(4, 100 // width))
    for index, item in enumerate(items):
        sys.stdout.write(item[: width - 2].ljust(width))
        if (index + 1) % columns == 0:
            sys.stdout.write("\n")
    if len(items) % columns:
        sys.stdout.write("\n")


class BattleShell:
    def __init__(self, ctx: BattleContext) -> None:
        self.ctx = ctx
        self.editor = LineEditor(self.complete_line)

    def run(self) -> None:
        print("Volatility Battle CLI")
        print("Type 'help' for commands. Tab completes commands/plugins in the interactive shell.")
        if self.ctx.dump_file:
            print(f"Dump: {self.ctx.dump_file}")
        else:
            print("No dump selected yet. Use: setdump <path>")
        while True:
            try:
                line = self.editor.readline("vol3> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            try:
                keep_running = self.execute(split_command(line))
                if not keep_running:
                    break
            except SystemExit:
                continue
            except Exception as exc:
                print(f"Error: {exc}")

    def execute(self, argv: Sequence[str]) -> bool:
        if not argv:
            return True
        command = argv[0].lower()
        args = list(argv[1:])

        if command in {"exit", "quit"}:
            return False
        if command == "help":
            self.cmd_help(args)
        elif command == "status":
            self.cmd_status(args)
        elif command == "setdump":
            self.cmd_setdump(args)
        elif command == "plugins":
            self.cmd_plugins(args)
        elif command in {"info", "ps", "pstree", "psscan", "cmdline", "net", "files"}:
            self.cmd_alias(command, args)
        elif command == "run":
            self.cmd_run(args)
        elif command == "vol":
            self.cmd_vol(args)
        elif command == "tree":
            self.cmd_tree(args)
        elif command == "triage":
            self.cmd_triage(args)
        elif command == "dump-images":
            self.cmd_dump_images(args)
        elif command == "carve-images":
            self.cmd_carve_images(args)
        elif command == "dump-proc":
            self.cmd_dump_proc(args)
        elif command == "clear":
            os.system("cls" if os.name == "nt" else "clear")
        else:
            print(f"Unknown command: {command}. Try 'help'.")
        return True

    def complete_line(self, line: str) -> Tuple[str, List[str]]:
        parts = line.split()
        if not parts or (len(parts) == 1 and not line.endswith(" ")):
            token = parts[0] if parts else ""
            choices = [cmd for cmd in COMMANDS if cmd.startswith(token.lower())]
            if len(choices) == 1:
                return choices[0] + " ", choices
            return line, choices

        command = parts[0].lower()
        token = "" if line.endswith(" ") else parts[-1]
        before_token = line[: len(line) - len(token)] if token else line

        choices: List[str] = []
        if command in {"run", "vol"}:
            try:
                names = sorted(self.ctx.plugin_map())
            except Exception:
                names = []
            names.extend(sorted(PLUGIN_ALIASES))
            choices = [name for name in names if name.lower().startswith(token.lower())]
        elif command == "help":
            choices = [cmd for cmd in COMMANDS if cmd.startswith(token.lower())]
        elif command in {"setdump"}:
            choices = path_choices(token)
        elif command in {"dump-images", "carve-images"}:
            options = [
                "--out",
                "--extensions",
                "--mode",
                "--pid",
                "--min-size",
                "--max-size",
                "--limit",
                "--no-validate",
                "cache",
                "carve",
                "both",
            ]
            choices = [opt for opt in options if opt.startswith(token)]
        elif command == "tree":
            options = ["--source", "--filter", "--limit", "--depth", "--out", "filescan", "mft"]
            choices = [opt for opt in options if opt.startswith(token)]

        if len(choices) == 1:
            return before_token + choices[0] + " ", choices
        return line, choices[:80]

    def cmd_help(self, args: Sequence[str]) -> None:
        print(
            """
Core:
  setdump <path>                 Select memory image
  plugins [text]                 List Volatility plugins
  run <plugin> [key=value]       Run a plugin through the reusable runner
  vol <raw vol.py args>          Run original Volatility CLI with portable cache

Fast aliases:
  info | ps | pstree | psscan | cmdline | net | files

Field workflow:
  triage [--out DIR]             Save common triage plugin outputs as JSON
  tree [--source filescan|mft]   Render file/path artifacts as a directory tree
  dump-images [options]          Dump cached image files and/or carve raw images
  carve-images [options]         Shortcut for dump-images --mode carve
  dump-proc <pid> [--out DIR]    Dump DLL/EXE images for a process

Examples:
  setdump C:\\cases\\mem.raw
  info
  run windows.pslist.PsList --limit 40
  run dlllist pid=1234 dump=true
  tree --source filescan --filter Users --out trees\\files.txt
  dump-images --mode both --out images --max-size 32M
  vol -r pretty windows.info.Info
""".strip()
        )

    def cmd_status(self, args: Sequence[str]) -> None:
        print(f"Tool root : {TOOL_ROOT}")
        print(f"Dump      : {self.ctx.dump_file or '(not selected)'}")
        print(f"Output    : {self.ctx.output_root}")
        print(f"Cache     : {self.ctx.cache_path}")
        print(f"Offline   : {self.ctx.offline}")
        print("Symbols   :")
        for path in self.ctx.symbol_dirs:
            print(f"  {path}")

    def cmd_setdump(self, args: Sequence[str]) -> None:
        if not args:
            print("Usage: setdump <memory_dump_path>")
            return
        self.ctx.set_dump(Path(" ".join(args)))
        print(f"Dump selected: {self.ctx.dump_file}")

    def cmd_plugins(self, args: Sequence[str]) -> None:
        query = " ".join(args).lower()
        names = sorted(self.ctx.plugin_map())
        if query:
            names = [name for name in names if query in name.lower()]
        for name in names:
            print(name)
        print(f"{len(names)} plugin(s)")

    def cmd_alias(self, command: str, args: Sequence[str]) -> None:
        self.cmd_run([PLUGIN_ALIASES[command], *args])

    def cmd_run(self, args: Sequence[str]) -> None:
        parser = argparse.ArgumentParser(prog="run", add_help=True)
        parser.add_argument("plugin")
        parser.add_argument("plugin_args", nargs="*")
        parser.add_argument("--limit", type=int, default=80)
        parser.add_argument("--json", dest="json_path")
        parser.add_argument("--csv", dest="csv_path")
        ns = parser.parse_args(args)

        plugin_args: Dict[str, Any] = {}
        for item in ns.plugin_args:
            if "=" not in item:
                raise ValueError(f"Plugin argument must be key=value: {item}")
            key, value = item.split("=", 1)
            plugin_args[key] = parse_value(value)

        rows = self.ctx.run_plugin(ns.plugin, plugin_args)
        print_table(rows, limit=ns.limit)
        if ns.json_path:
            path = self.ctx.output_path(ns.json_path)
            write_json(path, rows)
            print(f"JSON saved: {path}")
        if ns.csv_path:
            path = self.ctx.output_path(ns.csv_path)
            write_csv(path, rows)
            print(f"CSV saved: {path}")

    def cmd_vol(self, args: Sequence[str]) -> None:
        dump = self.ctx.dump_file
        vol_args: List[str] = []
        if dump and not any(arg in {"-f", "--file", "--single-location"} for arg in args):
            vol_args.extend(["-f", str(dump)])
        vol_args.extend(["--cache-path", str(self.ctx.cache_path)])
        if self.ctx.symbol_dirs and not any(arg in {"-s", "--symbol-dirs"} for arg in args):
            vol_args.extend(["-s", ";".join(str(path) for path in self.ctx.symbol_dirs)])
        if self.ctx.offline and "--offline" not in args and "-u" not in args and "--remote-isf-url" not in args:
            vol_args.append("--offline")
        if not any(arg in {"-o", "--output-dir"} for arg in args):
            vol_args.extend(["-o", str(self.ctx.output_root)])
        vol_args.extend(args)

        if FROZEN:
            print("vol.py " + " ".join(f'"{part}"' if " " in part else part for part in vol_args))
            old_argv = sys.argv[:]
            try:
                sys.argv = ["vol.py", *vol_args]
                import volatility3.cli

                try:
                    volatility3.cli.main()
                except SystemExit as exc:
                    if exc.code not in (0, None):
                        print(f"Volatility exited with code {exc.code}")
            finally:
                sys.argv = old_argv
            return

        cmd = [sys.executable, str(TOOL_ROOT / "vol.py"), *vol_args]
        print(" ".join(f'"{part}"' if " " in part else part for part in cmd))
        subprocess.run(cmd, cwd=str(TOOL_ROOT), check=False)

    def cmd_tree(self, args: Sequence[str]) -> None:
        parser = argparse.ArgumentParser(prog="tree", add_help=True)
        parser.add_argument("--source", choices=["filescan", "mft"], default="filescan")
        parser.add_argument("--filter", default="")
        parser.add_argument("--limit", type=int, default=500)
        parser.add_argument("--depth", type=int, default=0)
        parser.add_argument("--out")
        ns = parser.parse_args(args)

        plugin = "windows.filescan.FileScan" if ns.source == "filescan" else "windows.mftscan.MFTScan"
        rows = self.ctx.run_plugin(plugin)
        root = TreeNode()
        used = 0
        query = ns.filter.lower()
        for row in rows:
            path = row.get("Name") if ns.source == "filescan" else row.get("Filename")
            if not path:
                continue
            text = normalize_cell(path)
            if query and query not in text.lower():
                continue
            parts = split_memory_path(text)
            if parts:
                root.add(parts)
                used += 1

        lines = [f"{ns.source} paths: {used}", "."]
        lines.extend(render_tree(root, ns.limit, ns.depth))
        output = "\n".join(lines)
        print(output)
        if ns.out:
            path = self.ctx.output_path(ns.out)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(output + "\n", encoding="utf-8")
            print(f"Tree saved: {path}")

    def cmd_triage(self, args: Sequence[str]) -> None:
        parser = argparse.ArgumentParser(prog="triage", add_help=True)
        parser.add_argument("--out", default=f"triage_{timestamp()}")
        parser.add_argument("--skip-heavy", action="store_true")
        ns = parser.parse_args(args)
        out_dir = self.ctx.output_path(ns.out)
        out_dir.mkdir(parents=True, exist_ok=True)

        plugins = [
            "info",
            "pslist",
            "pstree",
            "psscan",
            "cmdline",
            "netstat",
            "netscan",
            "malfind",
            "psxview",
            "svcscan",
        ]
        if ns.skip_heavy:
            plugins = ["info", "pslist", "pstree", "cmdline", "netstat"]

        summary = []
        for name in plugins:
            try:
                resolved = resolve_plugin(self.ctx, name)
                print(f"Running {resolved}...")
                rows = self.ctx.run_plugin(resolved)
                safe = resolved.replace(".", "_")
                write_json(out_dir / f"{safe}.json", rows)
                summary.append({"plugin": resolved, "rows": len(rows), "status": "ok"})
            except Exception as exc:
                summary.append({"plugin": name, "rows": 0, "status": f"error: {exc}"})
                print(f"  failed: {exc}")
        write_json(out_dir / "summary.json", summary)
        print(f"Triage saved: {out_dir}")
        print_table(summary, limit=50)

    def cmd_dump_images(self, args: Sequence[str]) -> None:
        parser = argparse.ArgumentParser(prog="dump-images", add_help=True)
        parser.add_argument("--out", default=f"images_{timestamp()}")
        parser.add_argument("--extensions", default="jpg,jpeg,png,gif,bmp,webp,ico,tif,tiff")
        parser.add_argument("--mode", choices=["cache", "carve", "both"], default="both")
        parser.add_argument("--pid", type=int)
        parser.add_argument("--min-size", default="256")
        parser.add_argument("--max-size", default="32M")
        parser.add_argument("--limit", type=int, default=0)
        parser.add_argument("--no-validate", action="store_true")
        ns = parser.parse_args(args)

        dump = self.ctx.require_dump()
        extensions = [
            ext.strip().lower().lstrip(".")
            for ext in ns.extensions.split(",")
            if ext.strip()
        ]
        bad = sorted(set(extensions) - IMAGE_EXTENSIONS)
        if bad:
            raise ValueError(f"Unsupported extension(s): {', '.join(bad)}")

        out_dir = self.ctx.output_path(ns.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        validate = not ns.no_validate
        records: List[Dict[str, Any]] = []

        if ns.mode in {"cache", "both"}:
            from app.core.vol_runner import VolatilityRunner

            cache_dir = out_dir / "cache"
            file_handler_cls = VolatilityRunner.create_disk_file_handler(str(cache_dir))
            plugin_args: Dict[str, Any] = {
                "filter": build_image_regex(extensions),
                "ignore-case": True,
            }
            if ns.pid is not None:
                plugin_args["pid"] = ns.pid
            print(f"Dumping cached image file objects to {cache_dir}...")
            rows = self.ctx.run_plugin("windows.dumpfiles.DumpFiles", plugin_args, file_handler_cls)
            row_by_result = {
                normalize_cell(row.get("Result", "")): row
                for row in rows
                if normalize_cell(row.get("Result", ""))
            }
            for path_text in getattr(file_handler_cls, "created_files", []):
                path = Path(path_text)
                info = inspect_image_file(path, validate)
                source_row = row_by_result.get(path.name) or row_by_result.get(str(path))
                info.update(
                    {
                        "source": "windows.dumpfiles.DumpFiles",
                        "file_object": normalize_cell(source_row.get("FileObject", "")) if source_row else "",
                        "cache": normalize_cell(source_row.get("Cache", "")) if source_row else "",
                        "original_name": normalize_cell(source_row.get("FileName", "")) if source_row else "",
                    }
                )
                records.append(info)
            print(f"Cache dump created {len(getattr(file_handler_cls, 'created_files', []))} file(s).")

        if ns.mode in {"carve", "both"}:
            carve_dir = out_dir / "carved"
            min_size = parse_size(ns.min_size)
            max_size = parse_size(ns.max_size)
            print(f"Carving raw image signatures to {carve_dir}...")
            carved = carve_images(
                dump,
                carve_dir,
                extensions,
                min_size=min_size,
                max_size=max_size,
                limit=ns.limit,
                validate=validate,
                progress=self.ctx.progress,
            )
            records.extend(carved)
            print(f"Carved {len(carved)} image(s).")

        manifest_json = out_dir / "manifest.json"
        manifest_csv = out_dir / "manifest.csv"
        write_json(manifest_json, records)
        write_csv(manifest_csv, records)
        print(f"Image extraction complete: {len(records)} record(s)")
        print(f"Manifest: {manifest_json}")

    def cmd_carve_images(self, args: Sequence[str]) -> None:
        self.cmd_dump_images(["--mode", "carve", *args])

    def cmd_dump_proc(self, args: Sequence[str]) -> None:
        parser = argparse.ArgumentParser(prog="dump-proc", add_help=True)
        parser.add_argument("pid", type=int)
        parser.add_argument("--out", default="")
        ns = parser.parse_args(args)

        from app.core.vol_runner import VolatilityRunner

        out_dir = (
            self.ctx.output_path(ns.out)
            if ns.out
            else self.ctx.output_path(f"process_{ns.pid}_{timestamp()}")
        )
        file_handler_cls = VolatilityRunner.create_disk_file_handler(str(out_dir))
        rows = self.ctx.run_plugin(
            "windows.dlllist.DllList",
            {"pid": [ns.pid], "dump": True},
            file_handler_cls,
        )
        files = [Path(path) for path in getattr(file_handler_cls, "created_files", [])]
        manifest = []
        for path in files:
            manifest.append(
                {
                    "path": str(path),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
        write_json(out_dir / "manifest.json", {"rows": rows, "files": manifest})
        print(f"Dumped {len(files)} file(s) to {out_dir}")
        if files:
            for path in files[:20]:
                print(path)


def path_choices(token: str) -> List[str]:
    try:
        raw = token.strip('"')
        path = Path(raw) if raw else Path.cwd()
        if raw and not raw.endswith(("\\", "/")):
            base = path.parent if str(path.parent) != "." else Path.cwd()
            prefix = path.name.lower()
        else:
            base = path
            prefix = ""
        if not base.is_absolute():
            base = (Path.cwd() / base).resolve()
        if not base.is_dir():
            return []
        choices = []
        for child in base.iterdir():
            if child.name.lower().startswith(prefix):
                text = str(child)
                if child.is_dir():
                    text += os.sep
                choices.append(text)
        return choices[:80]
    except Exception:
        return []


def parse_main(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="battle_cli.py",
        description="Portable Volatility3 field CLI",
    )
    parser.add_argument("-f", "--file", dest="dump_file", help="Memory dump path")
    parser.add_argument(
        "-o",
        "--output-root",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="Root folder for generated outputs",
    )
    parser.add_argument(
        "--cache-path",
        default=str(DEFAULT_CACHE_PATH),
        help="Portable Volatility cache folder",
    )
    parser.add_argument(
        "--symbol-dirs",
        default="",
        help="Extra symbol directories separated by semicolon",
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help="Allow Volatility to query remote symbol sources",
    )
    parser.add_argument("--quiet", action="store_true", help="Hide progress lines")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ns = parse_main(argv or sys.argv[1:])
    symbol_dirs = default_symbol_dirs()
    if ns.symbol_dirs:
        symbol_dirs = [Path(item) for item in ns.symbol_dirs.split(";") if item] + symbol_dirs

    try:
        ctx = BattleContext(
            dump_file=Path(ns.dump_file) if ns.dump_file else None,
            output_root=Path(ns.output_root),
            cache_path=Path(ns.cache_path),
            symbol_dirs=symbol_dirs,
            offline=not ns.online,
            quiet=ns.quiet,
        )
        shell = BattleShell(ctx)
        if ns.command:
            shell.execute(ns.command)
        else:
            shell.run()
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
