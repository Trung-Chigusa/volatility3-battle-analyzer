import sys
import os
import json
import logging
import traceback
import shlex
import hashlib
from pathlib import Path
from typing import List

# Setup paths
volatility3_path = Path(__file__).parent.parent / "volatility3-2.26.2"
if str(volatility3_path) not in sys.path:
    sys.path.insert(0, str(volatility3_path))

from app.core.vol_runner import VolatilityRunner
from app.core.models import (
    Process,
    NetworkConnection,
    StringMatch,
    SuspiciousArtifact,
)
from app.core.analysis import SuspicionAnalyzer
from app.core.decoder import Decoder
from datetime import datetime

# Configure logging to stderr so we can capture it
logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("worker")

def run_worker(dump_file: str, analysis_type: str):
    """Run analysis in a separate process"""
    logger.info(f"Worker process started. File: {dump_file}, Type: {analysis_type}")
    
    try:
        def emit_progress(progress: float, message: str):
            try:
                print(f"PROGRESS:{progress}:{message}", file=sys.stderr, flush=True)
            except Exception:
                pass
        
        # Initialize components
        vol_runner = VolatilityRunner(dump_file, emit_progress)
        analyzer = SuspicionAnalyzer()
        decoder = Decoder()
        
        vol_runner.initialize()
        
        results = {
            "processes": [],
            "connections": [],
            "strings": [],
            "decoded": [],
            "suspicious": [],
        }
        
        def safe_int(value, default=0):
            try:
                return int(str(value))
            except Exception:
                return default
        
        def parse_time(value: str):
            if not value:
                return None
            try:
                return datetime.fromisoformat(str(value).replace('Z', '+00:00'))
            except Exception:
                return None
        
        DEFAULT_SYSTEMROOT = "C:\\Windows"
        
        def normalize_path(candidate: str) -> str:
            if not candidate:
                return ""
            candidate = candidate.strip().strip('"').strip("'")
            if candidate.startswith("\\??\\"):
                candidate = candidate[4:]
            candidate = candidate.replace("\\SystemRoot\\", f"{DEFAULT_SYSTEMROOT}\\")
            candidate = candidate.replace("%SystemRoot%", DEFAULT_SYSTEMROOT).replace("%systemroot%", DEFAULT_SYSTEMROOT)
            return candidate
        
        def path_from_cmdline(cmdline: str) -> str:
            if not cmdline:
                return ""
            try:
                parts = shlex.split(cmdline)
            except ValueError:
                parts = [cmdline.split(" ")[0]]
            if not parts:
                return ""
            first = normalize_path(parts[0])
            return first
        
        def compute_sha256(path: str) -> str:
            """Compute SHA-256 hash for a given file path if it exists on disk."""
            if not path:
                return ""
            try:
                resolved = Path(path)
                if not resolved.is_file():
                    return ""
                h = hashlib.sha256()
                with resolved.open("rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        h.update(chunk)
                return h.hexdigest()
            except Exception as e:
                logger.debug(f"Failed to compute SHA256 for {path}: {e}")
                return ""
        
        if analysis_type in ["full", "processes"]:
            logger.info("Running pslist...")
            cmdline_map = {}
            env_strings = []
            string_matches: List[StringMatch] = []
            try:
                emit_progress(20, "Starting pslist (process enumeration)...")
                ps_results = vol_runner.run_plugin_to_list("windows.pslist.PsList")
                processes = []
                logger.info(f"Parsing {len(ps_results)} process rows...")
                
                for i, row in enumerate(ps_results):
                    try:
                        if i == 0:
                            logger.info(f"First process row keys: {list(row.keys())}")
                            logger.info(f"First process row sample: {dict(list(row.items())[:5])}")
                        
                        proc = Process(
                            pid=safe_int(row.get("PID")),
                            ppid=safe_int(row.get("PPID")),
                            name=str(row.get("ImageFileName", row.get("Image", ""))),
                            full_path=str(row.get("ImageFileName", row.get("Image", ""))),
                            command_line=str(row.get("CommandLine", "")),
                            user=str(row.get("Owner", "")),
                            start_time=parse_time(row.get("CreateTime", "")),
                            source="pslist"
                        )
                        if proc.command_line:
                            exe_path = path_from_cmdline(proc.command_line)
                            if exe_path:
                                proc.full_path = exe_path
                        elif "\\" in proc.full_path or ":" in proc.full_path:
                            proc.full_path = normalize_path(proc.full_path)
                        # Try to compute hash from disk if path exists
                        proc.sha256 = compute_sha256(proc.full_path)
                        processes.append(proc)
                    except Exception as e:
                        logger.warning(f"Failed to parse process row {i}: {e}")
                        if i == 0:
                            logger.warning(f"Row data: {row}")
                        continue
                
                # Collect command line data
                try:
                    logger.info("Running cmdline plugin for arguments...")
                    cmd_results = vol_runner.run_plugin_to_list("windows.cmdline.CmdLine")
                    logger.info("CmdLine returned %d rows", len(cmd_results))
                    for row in cmd_results:
                        pid = safe_int(row.get("PID"))
                        cmd = row.get("CommandLine") or row.get("Args") or row.get("Command", "")
                        if pid and cmd:
                            cmdline_map[pid] = str(cmd)
                except Exception as e:
                    logger.warning(f"CmdLine plugin failed: {e}")
                
                # Collect environment variables
                try:
                    logger.info("Running envars plugin...")
                    env_results = vol_runner.run_plugin_to_list("windows.envars.Envars")
                    logger.info("Envars returned %d rows", len(env_results))
                    for row in env_results:
                        pid = safe_int(row.get("PID"))
                        if not pid:
                            continue
                        proc_name = str(row.get("Process", row.get("ImageFileName", "")))
                        variable = str(row.get("Variable", row.get("Name", "")))
                        value = row.get("Value")
                        if value is None:
                            continue
                        env_strings.append((pid, proc_name, f"{variable}={value}"))
                except Exception as e:
                    logger.warning(f"Envars plugin failed: {e}")
                
                pid_map = {proc.pid: proc for proc in processes if proc.pid}
                for pid, cmd in cmdline_map.items():
                    proc = pid_map.get(pid)
                    if proc:
                        proc.command_line = cmd
                        exe_path = path_from_cmdline(cmd)
                        if exe_path:
                            proc.full_path = exe_path
                            if not proc.sha256:
                                proc.sha256 = compute_sha256(proc.full_path)
                
                # Run psscan for hidden processes
                try:
                    logger.info("Running psscan for hidden processes...")
                    psscan_results = vol_runner.run_plugin_to_list("windows.psscan.PsScan")
                    logger.info("psscan returned %d rows", len(psscan_results))
                    for row in psscan_results:
                        pid = safe_int(row.get("PID"))
                        if not pid or pid in pid_map:
                            continue
                        proc = Process(
                            pid=pid,
                            ppid=safe_int(row.get("PPID")),
                            name=str(row.get("ImageFileName", row.get("Image", ""))),
                            full_path=str(row.get("ImageFileName", row.get("Image", ""))),
                            command_line=cmdline_map.get(pid, ""),
                            user="",
                            start_time=parse_time(row.get("CreateTime", "")),
                            is_hidden=True,
                            source="psscan"
                        )
                        exe_path = path_from_cmdline(proc.command_line)
                        if exe_path:
                            proc.full_path = exe_path
                        if not proc.sha256:
                            proc.sha256 = compute_sha256(proc.full_path)
                        processes.append(proc)
                        pid_map[pid] = proc
                except Exception as e:
                    logger.warning(f"Psscan plugin failed: {e}")
                
                # Analyze processes
                processes = [analyzer.analyze_process(p) for p in processes]
                results["processes"] = [p.__dict__ for p in processes]
                logger.info(f"Found {len(processes)} processes (pslist + psscan)")
                emit_progress(55, f"Processes parsed: {len(processes)}")
                
                # Build string matches from command lines
                for proc in processes:
                    if proc.command_line:
                        sm = StringMatch(
                            pid=proc.pid,
                            process_name=proc.name,
                            match=proc.command_line,
                            region="CommandLine",
                            suspicious=False
                        )
                        sm = analyzer.analyze_string(sm)
                        string_matches.append(sm)
                
                # Add environment variable strings
                for pid, proc_name, env_string in env_strings:
                    sm = StringMatch(
                        pid=pid,
                        process_name=proc_name,
                        match=env_string,
                        region="Environment",
                        suspicious=False
                    )
                    sm = analyzer.analyze_string(sm)
                    string_matches.append(sm)
                
                results["strings"] = [sm.__dict__ for sm in string_matches]
                
                # Decode potential encoded strings
                decoded_results = []
                seen_decoded = set()
                for sm in string_matches:
                    decoded_items = decoder.detect_and_decode(sm.match)
                    for decoded in decoded_items:
                        key = (decoded.get("decoded"), decoded.get("encoding"), sm.pid)
                        if key in seen_decoded:
                            continue
                        seen_decoded.add(key)
                        decoded_results.append({
                            **decoded,
                            "source_pid": sm.pid,
                            "source_process": sm.process_name,
                            "source_region": sm.region
                        })
                results["decoded"] = decoded_results
                
                # Suspicious artifacts
                suspicious_artifacts: List[SuspiciousArtifact] = analyzer.find_suspicious_executables(processes)
                suspicious_artifacts.extend(
                    analyzer.extract_urls_from_strings([sm.match for sm in string_matches])
                )
                results["suspicious"] = [artifact.__dict__ for artifact in suspicious_artifacts]
                
            except Exception as e:
                logger.error(f"Process analysis failed: {e}")
                results["processes"] = []

        if analysis_type in ["full", "network"]:
            logger.info("Running netscan...")
            try:
                emit_progress(65, "Starting netscan (network connections)...")
                net_results = vol_runner.run_plugin_to_list("windows.netscan.NetScan")
                connections = []
                logger.info(f"Parsing {len(net_results)} network connection rows...")
                for i, row in enumerate(net_results):
                    try:
                        # Debug: log first row to see actual field names
                        if i == 0:
                            logger.info(f"First connection row keys: {list(row.keys())}")
                            logger.info(f"First connection row sample: {dict(list(row.items())[:5])}")
                        
                        # Try multiple field name variations
                        local_addr = row.get("LocalAddr") or row.get("LocalAddress") or ""
                        remote_addr = row.get("ForeignAddr") or row.get("RemoteAddr") or row.get("RemoteAddress") or ""
                        local_port_val = row.get("LocalPort", 0)
                        remote_port_val = row.get("ForeignPort") or row.get("RemotePort") or 0
                        pid_val = row.get("PID", 0)
                        
                        conn = NetworkConnection(
                            local_ip=str(local_addr),
                            local_port=int(local_port_val) if local_port_val is not None and str(local_port_val).isdigit() else 0,
                            remote_ip=str(remote_addr),
                            remote_port=int(remote_port_val) if remote_port_val is not None and str(remote_port_val).isdigit() else 0,
                            protocol=str(row.get("Proto", row.get("Protocol", ""))),
                            state=str(row.get("State", "")),
                            pid=int(pid_val) if pid_val is not None and str(pid_val).isdigit() else 0,
                            process_name=str(row.get("Owner", row.get("Process", "")))
                        )
                        connections.append(conn)
                    except Exception as e:
                        logger.warning(f"Failed to parse connection row {i}: {e}")
                        if i == 0:
                            logger.warning(f"Row data: {row}")
                        continue
                
                # Enhance
                connections = [analyzer.analyze_connection(c) for c in connections]
                
                results["connections"] = [c.__dict__ for c in connections]
                logger.info(f"Found {len(connections)} connections")
                emit_progress(85, f"Connections parsed: {len(connections)}")
                
            except Exception as e:
                logger.error(f"Network analysis failed: {e}")
                results["connections"] = []
        
        emit_progress(95, "Serializing results...")
        # Output result as JSON to stdout
        print("JSON_RESULT_START")
        print(json.dumps(results, default=str))
        print("JSON_RESULT_END")
        emit_progress(100, "Analysis complete")
        
    except Exception as e:
        logger.error(f"Worker crashed: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: worker_process.py <dump_file> <analysis_type>", file=sys.stderr)
        sys.exit(1)
    
    run_worker(sys.argv[1], sys.argv[2])

