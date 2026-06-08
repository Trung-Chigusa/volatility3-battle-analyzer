"""Background worker for running analysis"""
import logging
import threading
from typing import Dict, Any, List
from PySide6.QtCore import QThread, Signal
import os

from ...core.vol_runner import VolatilityRunner
from ...core.models import Process, NetworkConnection, StringMatch, SuspiciousArtifact
from ...core.analysis import SuspicionAnalyzer
from ...core.decoder import Decoder


class AnalysisWorker(QThread):
    """Worker thread for running volatility3 analysis"""
    
    progress = Signal(float, str)
    finished = Signal(dict)
    error = Signal(str)
    cli_log = Signal(str)
    
    def __init__(self, vol_runner: VolatilityRunner, analysis_type: str):
        super().__init__()
        self.vol_runner = vol_runner
        self.analysis_type = analysis_type
        self.analyzer = SuspicionAnalyzer()
        self.decoder = Decoder()
        self.logger = logging.getLogger(__name__)
    
    def run(self):
        """Run the analysis in a subprocess"""
        self.logger.info("=" * 60)
        self.logger.info("WORKER THREAD STARTED - Analysis Type: %s", self.analysis_type)
        self.logger.info("=" * 60)
        
        import sys
        import subprocess
        import json
        
        try:
            self.progress.emit(1, f"Starting {self.analysis_type} analysis...")
            
            # Get path to executable
            if getattr(sys, 'frozen', False):
                exe_path = sys.executable
            else:
                exe_path = sys.executable
            
            # Construct command
            cmd = [exe_path, "--worker", self.vol_runner.dump_file, self.analysis_type]
            if not getattr(sys, 'frozen', False):
                cmd = [sys.executable, "app/main.py", "--worker", self.vol_runner.dump_file, self.analysis_type]
                
            self.logger.info(f"Running command: {cmd}")
            self.cli_log.emit(f"COMMAND: {' '.join(cmd)}")
            
            # Run subprocess
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            json_output: List[str] = []
            stdout_done = threading.Event()
            stderr_done = threading.Event()
            
            def stdout_reader():
                capture_json = False
                for line in iter(process.stdout.readline, ''):
                    stripped = line.rstrip("\r\n")
                    if stripped == "JSON_RESULT_START":
                        capture_json = True
                        continue
                    if stripped == "JSON_RESULT_END":
                        capture_json = False
                        continue
                    if capture_json:
                        json_output.append(line)
                    else:
                        if stripped:
                            self.cli_log.emit(stripped)
                            self.logger.info(f"[WORKER STDOUT] {stripped}")
                stdout_done.set()
            
            def stderr_reader():
                for line in iter(process.stderr.readline, ''):
                    stripped = line.rstrip("\r\n")
                    if not stripped:
                        continue
                    if stripped.startswith("PROGRESS:"):
                        try:
                            parts = stripped.split(":", 2)
                            pct = float(parts[1])
                            msg = parts[2]
                            self.progress.emit(pct, msg)
                        except Exception:
                            self.logger.warning(f"Failed to parse progress line: {stripped}")
                    else:
                        self.cli_log.emit(stripped)
                        self.logger.info(f"[WORKER] {stripped}")
                stderr_done.set()
            
            stdout_thread = threading.Thread(target=stdout_reader, daemon=True)
            stderr_thread = threading.Thread(target=stderr_reader, daemon=True)
            stdout_thread.start()
            stderr_thread.start()
            
            process.wait()
            stdout_thread.join()
            stderr_thread.join()
            
            if process.returncode != 0:
                raise Exception(f"Worker process exited with code {process.returncode}")
            
            if not json_output:
                raise Exception("No results received from worker process")
                
            results_str = "".join(json_output)
            results = json.loads(results_str)
            self.logger.info(
                "Worker returned %d processes, %d connections",
                len(results.get("processes", [])),
                len(results.get("connections", []))
            )
            
            # Convert dicts back to objects
            if "processes" in results:
                procs = []
                for p_dict in results["processes"]:
                    try:
                        p = Process(**p_dict)
                        procs.append(p)
                    except TypeError as exc:
                        self.logger.warning("Failed to deserialize process: %s", exc)
                results["processes"] = procs
                
            if "connections" in results:
                conns = []
                for c_dict in results["connections"]:
                    try:
                        c = NetworkConnection(**c_dict)
                        conns.append(c)
                    except TypeError as exc:
                        self.logger.warning("Failed to deserialize connection: %s", exc)
                results["connections"] = conns
            
            if "strings" in results:
                matches = []
                for s_dict in results["strings"]:
                    try:
                        matches.append(StringMatch(**s_dict))
                    except TypeError as exc:
                        self.logger.warning("Failed to deserialize string match: %s", exc)
                results["strings"] = matches
            
            if "suspicious" in results:
                artifacts = []
                for a_dict in results["suspicious"]:
                    try:
                        artifacts.append(SuspiciousArtifact(**a_dict))
                    except TypeError as exc:
                        self.logger.warning("Failed to deserialize suspicious artifact: %s", exc)
                results["suspicious"] = artifacts
            
            self.progress.emit(100, "Analysis complete")
            self.finished.emit(results)
            
        except Exception as e:
            import traceback
            error_msg = f"{str(e)}\n\n{traceback.format_exc()}"
            self.logger.exception("Analysis worker failed")
            self.error.emit(error_msg)
    
    def _get_processes(self) -> List[Process]:
        """Get process list from volatility3"""
        self.logger.info("_get_processes() called")
        processes = []
        
        try:
            # Try pslist first
            self.logger.info("Calling vol_runner.run_plugin_to_list('windows.pslist.PsList')...")
            results = self.vol_runner.run_plugin_to_list("windows.pslist.PsList")
            self.logger.info("Plugin returned %d results", len(results) if results else 0)
            
            for row in results:
                try:
                    proc = Process(
                        pid=int(row.get("PID", 0)),
                        ppid=int(row.get("PPID", 0)),
                        name=row.get("Image", ""),
                        full_path=row.get("ImageFileName", ""),
                        command_line=row.get("CommandLine", ""),
                        user=row.get("Owner", ""),
                    )
                    processes.append(proc)
                except (ValueError, KeyError) as e:
                    continue
        except Exception as e:
            # Try psscan as fallback
            try:
                results = self.vol_runner.run_plugin_to_list("windows.psscan.PsScan")
                for row in results:
                    try:
                        proc = Process(
                            pid=int(row.get("PID", 0)),
                            ppid=int(row.get("PPID", 0)),
                            name=row.get("Image", ""),
                            full_path=row.get("ImageFileName", ""),
                        )
                        processes.append(proc)
                    except (ValueError, KeyError):
                        continue
            except Exception:
                pass
        
        return processes
    
    def _get_network_connections(self) -> List[NetworkConnection]:
        """Get network connections from volatility3"""
        self.logger.info("_get_network_connections() called")
        connections = []
        
        try:
            # Try netscan
            self.logger.info("Calling vol_runner.run_plugin_to_list('windows.netscan.NetScan')...")
            self.progress.emit(55, "Scanning network connections (this may take 2-3 minutes)...")
            results = self.vol_runner.run_plugin_to_list("windows.netscan.NetScan")
            self.logger.info("NetScan plugin returned %d results", len(results) if results else 0)
            
            for row in results:
                try:
                    conn = NetworkConnection(
                        local_ip=str(row.get("LocalAddress", "")),
                        local_port=int(row.get("LocalPort", 0)) if str(row.get("LocalPort", "")).isdigit() else 0,
                        remote_ip=str(row.get("RemoteAddress", "")),
                        remote_port=int(row.get("RemotePort", 0)) if str(row.get("RemotePort", "")).isdigit() else 0,
                        protocol=str(row.get("Protocol", "")),
                        state=str(row.get("State", "")),
                        pid=int(row.get("PID", 0)),
                        process_name=str(row.get("Owner", "")),
                    )
                    connections.append(conn)
                except (ValueError, KeyError, TypeError):
                    continue
        except Exception:
            # Try netstat as fallback
            try:
                results = self.vol_runner.run_plugin_to_list("windows.netstat.NetStat")
                for row in results:
                    try:
                        conn = NetworkConnection(
                            local_ip=str(row.get("LocalAddress", "")),
                            local_port=int(row.get("LocalPort", 0)) if str(row.get("LocalPort", "")).isdigit() else 0,
                            remote_ip=str(row.get("RemoteAddress", "")),
                            remote_port=int(row.get("RemotePort", 0)) if str(row.get("RemotePort", "")).isdigit() else 0,
                            protocol=str(row.get("Protocol", "")),
                            state=str(row.get("State", "")),
                            pid=int(row.get("PID", 0)),
                        )
                        connections.append(conn)
                    except (ValueError, KeyError, TypeError):
                        continue
            except Exception:
                pass
        
        return connections
    
    def _get_suspicious_artifacts(self, processes: List[Process]) -> List:
        """Get suspicious artifacts"""
        artifacts = []
        
        # Get suspicious executables from processes
        artifacts.extend(self.analyzer.find_suspicious_executables(processes))
        
        # Try to extract URLs from process memory (simplified - would need strings plugin)
        # This is a placeholder - full implementation would use strings plugin
        
        return artifacts
    
    def _decode_strings(self, processes: List[Process]) -> List[Dict]:
        """Detect and decode encoded strings from processes"""
        decoded_results = []
        
        try:
            # Try to get strings from process memory using strings plugin
            # This is a simplified approach - in production you'd want to scan each process
            self.progress.emit(86, "Extracting strings from memory...")
            
            # Try windows.strings plugin to get strings
            try:
                strings_results = self.vol_runner.run_plugin_to_list("windows.strings.Strings")
                
                # Process strings and decode
                for row in strings_results[:1000]:  # Limit to first 1000 for performance
                    string_value = str(row.get("String", ""))
                    if len(string_value) > 10:  # Only process longer strings
                        decoded = self.decoder.detect_and_decode(string_value)
                        for item in decoded:
                            item['location'] = f"Process {row.get('PID', 'unknown')} - Memory"
                            item['source_pid'] = int(row.get('PID', 0)) if str(row.get('PID', '')).isdigit() else None
                            decoded_results.append(item)
            except Exception:
                # Fallback: decode from process command lines and paths
                for proc in processes:
                    # Decode from command line
                    if proc.command_line:
                        decoded = self.decoder.detect_and_decode(proc.command_line)
                        for item in decoded:
                            item['location'] = f"Process {proc.pid} - Command Line"
                            item['source_pid'] = proc.pid
                            item['source_process'] = proc.name
                            decoded_results.append(item)
                    
                    # Decode from full path
                    if proc.full_path:
                        decoded = self.decoder.detect_and_decode(proc.full_path)
                        for item in decoded:
                            item['location'] = f"Process {proc.pid} - Executable Path"
                            item['source_pid'] = proc.pid
                            item['source_process'] = proc.name
                            decoded_results.append(item)
            
            # Remove duplicates
            seen = set()
            unique_results = []
            for item in decoded_results:
                key = (item.get('decoded', '')[:50], item.get('encoding', ''))
                if key not in seen:
                    seen.add(key)
                    unique_results.append(item)
            
            return unique_results
            
        except Exception as e:
            # If decoding fails, return empty list
            return []

