"""Suspicion scoring and heuristics for detecting suspicious artifacts"""
import re
import os
from typing import List, Dict, Any
from urllib.parse import urlparse
from .models import Process, NetworkConnection, SuspiciousArtifact, StringMatch


class SuspicionAnalyzer:
    """Analyzes processes, connections, and artifacts for suspicious behavior"""
    
    # Suspicious process name patterns (typosquatting, mimicry)
    SUSPICIOUS_PROCESS_NAMES = [
        r'svch0st\.exe',
        r'svchost\.exe',  # Common target for mimicry
        r'exp1orer\.exe',
        r'explorer\.exe',  # Common target
        r'lsass\.exe',  # Common target
        r'csrss\.exe',  # Common target
        r'winlogon\.exe',  # Common target
        r'services\.exe',  # Common target
        r'smss\.exe',  # Common target
    ]
    
    # Suspicious directories
    SUSPICIOUS_DIRS = [
        r'%TEMP%',
        r'%TMP%',
        r'AppData\\Local\\Temp',
        r'AppData\\Roaming',
        r'AppData\\Local',
        r'Users\\.*\\AppData\\Local\\Temp',
        r'Users\\.*\\AppData\\Roaming',
        r'Windows\\Temp',
        r'\\Temp\\',
    ]
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        '.xyz', '.top', '.click', '.download', '.gq', '.tk', '.ml', '.cf',
        '.ga', '.pw', '.review', '.accountant', '.science', '.work', '.party'
    ]
    
    # Common malware keywords
    MALWARE_KEYWORDS = [
        'mimikatz', 'cmd.exe', 'powershell', 'wscript', 'cscript',
        'rundll32', 'regsvr32', 'mshta', 'certutil', 'bitsadmin',
        'schtasks', 'at.exe', 'net.exe', 'net1.exe'
    ]
    
    # Uncommon high ports (above 49152)
    UNCOMMON_HIGH_PORT_THRESHOLD = 49152
    
    # RFC 1918 private IP ranges
    RFC1918_PATTERNS = [
        (r'^10\.', '10.0.0.0/8'),
        (r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', '172.16.0.0/12'),
        (r'^192\.168\.', '192.168.0.0/16'),
    ]
    
    def __init__(self):
        self.suspicious_name_patterns = [re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_PROCESS_NAMES]
        self.suspicious_dir_patterns = [re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_DIRS]
    
    def analyze_process(self, process: Process) -> Process:
        """Analyze a process and assign suspicion score"""
        score = 0
        reasons = []
        
        # Check process name for mimicry
        name_lower = process.name.lower()
        for pattern in self.suspicious_name_patterns:
            if pattern.search(name_lower):
                score += 30
                reasons.append(f"Suspicious process name pattern: {process.name}")
                break
        
        # Check location
        path_lower = process.full_path.lower() if process.full_path else ""
        for pattern in self.suspicious_dir_patterns:
            if pattern.search(path_lower):
                score += 25
                reasons.append(f"Located in suspicious directory: {process.full_path}")
                break
        
        # Check for processes in root of drive
        if path_lower and (path_lower.startswith('c:\\') and path_lower.count('\\') == 1):
            score += 20
            reasons.append("Process in root directory (unusual)")
        
        # Check for no path (orphan process)
        if not process.full_path or process.full_path.strip() == "":
            score += 15
            reasons.append("No executable path found")
        
        # Check command line for suspicious patterns
        cmd_lower = process.command_line.lower() if process.command_line else ""
        for keyword in self.MALWARE_KEYWORDS:
            if keyword.lower() in cmd_lower:
                score += 10
                reasons.append(f"Command line contains suspicious keyword: {keyword}")
        
        # Check for very short names (often suspicious)
        if len(process.name) < 4 and process.name.lower() not in ['cmd', 'net', 'at']:
            score += 5
            reasons.append("Unusually short process name")
        
        process.suspicious_score = min(score, 100)  # Cap at 100
        process.suspicious_reasons = reasons
        return process
    
    def analyze_connection(self, conn: NetworkConnection) -> NetworkConnection:
        """Analyze a network connection and assign suspicion score"""
        score = 0
        reasons = []
        
        # Check for uncommon high ports
        if conn.local_port > self.UNCOMMON_HIGH_PORT_THRESHOLD:
            score += 15
            reasons.append(f"Uncommon high local port: {conn.local_port}")
        
        if conn.remote_port > self.UNCOMMON_HIGH_PORT_THRESHOLD:
            score += 15
            reasons.append(f"Uncommon high remote port: {conn.remote_port}")
        
        # Check if remote IP is external (not RFC 1918)
        is_private = False
        for pattern, _ in self.RFC1918_PATTERNS:
            if re.match(pattern, conn.remote_ip):
                is_private = True
                break
        
        if not is_private and conn.remote_ip not in ['127.0.0.1', '::1', '0.0.0.0']:
            score += 20
            reasons.append(f"External IP connection: {conn.remote_ip}")
        
        # Check for common suspicious ports
        suspicious_ports = [4444, 5555, 6666, 6667, 8080, 31337, 12345, 54321]
        if conn.remote_port in suspicious_ports or conn.local_port in suspicious_ports:
            score += 25
            reasons.append(f"Connection to suspicious port: {conn.remote_port}")
        
        # Check for listening on non-standard ports
        if conn.state and 'LISTEN' in conn.state.upper():
            if conn.local_port not in [80, 443, 22, 21, 25, 53, 135, 139, 445, 3389]:
                score += 10
                reasons.append(f"Listening on non-standard port: {conn.local_port}")
        
        conn.suspicious_score = min(score, 100)
        conn.suspicious_reasons = reasons
        return conn
    
    def analyze_string(self, string_match: StringMatch) -> StringMatch:
        """Analyze a string match for suspicious content"""
        match_lower = string_match.match.lower()
        
        # Check for URLs
        url_pattern = re.compile(r'https?://[^\s]+|www\.[^\s]+|[a-z0-9.-]+\.(com|net|org|io|xyz|top|click|download)')
        if url_pattern.search(string_match.match):
            string_match.suspicious = True
        
        # Check for IP addresses
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        if ip_pattern.search(string_match.match):
            string_match.suspicious = True
        
        # Check for malware keywords
        for keyword in self.MALWARE_KEYWORDS:
            if keyword.lower() in match_lower:
                string_match.suspicious = True
                break
        
        return string_match
    
    def extract_urls_from_strings(self, strings: List[str]) -> List[SuspiciousArtifact]:
        """Extract and classify URLs from strings"""
        artifacts = []
        url_pattern = re.compile(
            r'(https?://[^\s<>"\'{}|\\^`\[\]]+|www\.[^\s<>"\'{}|\\^`\[\]]+|[a-z0-9.-]+\.(?:com|net|org|io|xyz|top|click|download|gq|tk|ml|cf|ga|pw)[^\s<>"\'{}|\\^`\[\]]*)',
            re.IGNORECASE
        )
        
        seen_urls = set()
        
        for string in strings:
            matches = url_pattern.findall(string)
            for match in matches:
                url = match[0] if isinstance(match, tuple) else match
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                
                # Parse URL
                try:
                    if not url.startswith(('http://', 'https://')):
                        url = 'http://' + url
                    parsed = urlparse(url)
                    
                    severity = "low"
                    reason = "URL found in memory"
                    
                    # Check TLD
                    if any(parsed.netloc.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
                        severity = "high"
                        reason = f"Suspicious TLD: {parsed.netloc}"
                    
                    # Check if IP-based
                    if re.match(r'^\d+\.\d+\.\d+\.\d+', parsed.netloc):
                        severity = "medium"
                        reason = "IP-based URL"
                    
                    artifacts.append(SuspiciousArtifact(
                        artifact_type="url",
                        source="string_scan",
                        value=url,
                        reason=reason,
                        severity=severity
                    ))
                except Exception:
                    continue
        
        return artifacts
    
    def find_suspicious_executables(self, processes: List[Process]) -> List[SuspiciousArtifact]:
        """Find suspicious executables from process list"""
        artifacts = []
        seen_paths = set()
        
        for process in processes:
            if not process.full_path or process.full_path in seen_paths:
                continue
            seen_paths.add(process.full_path)
            
            if process.suspicious_score >= 30:
                artifacts.append(SuspiciousArtifact(
                    artifact_type="executable",
                    source=f"process_{process.pid}",
                    value=process.full_path,
                    reason=f"Suspicious process (score: {process.suspicious_score})",
                    severity="high" if process.suspicious_score >= 50 else "medium",
                    metadata={
                        "pid": process.pid,
                        "name": process.name,
                        "score": process.suspicious_score,
                        "reasons": process.suspicious_reasons
                    }
                ))
        
        return artifacts

