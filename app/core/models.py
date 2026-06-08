"""Data models for memory analysis results"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class Process:
    """Represents a process from memory dump"""
    pid: int
    ppid: int
    name: str
    full_path: str = ""
    sha256: str = ""
    command_line: str = ""
    user: str = ""
    start_time: Optional[datetime] = None
    integrity_level: str = ""
    suspicious_score: int = 0
    suspicious_reasons: List[str] = field(default_factory=list)
    children: List['Process'] = field(default_factory=list)
    is_hidden: bool = False
    source: str = "pslist"
    
    def __hash__(self):
        return hash((self.pid, self.name))
    
    def __eq__(self, other):
        if not isinstance(other, Process):
            return False
        return self.pid == other.pid and self.name == other.name


@dataclass
class NetworkConnection:
    """Represents a network connection"""
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: str
    state: str
    pid: int
    process_name: str = ""
    suspicious_score: int = 0
    suspicious_reasons: List[str] = field(default_factory=list)


@dataclass
class StringMatch:
    """Represents a string match found in memory"""
    pid: int
    process_name: str
    match: str
    offset: Optional[int] = None
    region: str = ""
    suspicious: bool = False


@dataclass
class SuspiciousArtifact:
    """Represents a suspicious artifact found during analysis"""
    artifact_type: str  # 'executable', 'link', 'url', etc.
    source: str  # Which plugin/process found it
    value: str  # The actual artifact (path, URL, etc.)
    reason: str  # Why it's suspicious
    severity: str = "medium"  # 'low', 'medium', 'high'
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisReport:
    """Complete analysis report"""
    dump_file: str
    dump_size: int
    analysis_timestamp: datetime
    os_profile: str = ""
    processes: List[Process] = field(default_factory=list)
    connections: List[NetworkConnection] = field(default_factory=list)
    suspicious_artifacts: List[SuspiciousArtifact] = field(default_factory=list)
    string_matches: List[StringMatch] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    decoded_strings: List[Dict[str, Any]] = field(default_factory=list)

