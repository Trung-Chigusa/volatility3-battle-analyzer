"""Reports view for generating and viewing reports"""
from pathlib import Path
from datetime import datetime
from typing import List
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QTextEdit, QComboBox, QCheckBox, QGroupBox
)
from PySide6.QtCore import Qt
from ...core.models import AnalysisReport, Process, NetworkConnection, SuspiciousArtifact, StringMatch


class ReportsView(QWidget):
    """View for generating reports"""
    
    def __init__(self):
        super().__init__()
        self.analysis_report: AnalysisReport = None
        self._setup_ui()
    
    def set_analysis_report(self, report: AnalysisReport):
        """Set the analysis report to generate from"""
        self.analysis_report = report
    
    def _setup_ui(self):
        """Setup reports view UI"""
        layout = QVBoxLayout(self)
        
        # Options
        options_group = QGroupBox("Report Options")
        options_layout = QVBoxLayout()
        
        self.include_processes = QCheckBox("Include Processes")
        self.include_processes.setChecked(True)
        options_layout.addWidget(self.include_processes)
        
        self.include_network = QCheckBox("Include Network Connections")
        self.include_network.setChecked(True)
        options_layout.addWidget(self.include_network)
        
        self.include_strings = QCheckBox("Include String Matches")
        self.include_strings.setChecked(True)
        options_layout.addWidget(self.include_strings)
        
        self.include_suspicious = QCheckBox("Include Suspicious Artifacts")
        self.include_suspicious.setChecked(True)
        options_layout.addWidget(self.include_suspicious)
        
        self.suspicious_only = QCheckBox("Suspicious Items Only")
        options_layout.addWidget(self.suspicious_only)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Format selection
        format_layout = QHBoxLayout()
        format_label = QLabel("Format:")
        format_layout.addWidget(format_label)
        
        self.format_combo = QComboBox()
        self.format_combo.addItems(["HTML", "Markdown", "JSON"])
        format_layout.addWidget(self.format_combo)
        format_layout.addStretch()
        
        layout.addLayout(format_layout)
        
        # Generate button
        button_layout = QHBoxLayout()
        self.generate_btn = QPushButton("Generate Report")
        self.generate_btn.clicked.connect(self._on_generate_report)
        button_layout.addWidget(self.generate_btn)
        
        self.save_btn = QPushButton("Save Report")
        self.save_btn.clicked.connect(self._on_save_report)
        self.save_btn.setEnabled(False)
        button_layout.addWidget(self.save_btn)
        
        layout.addLayout(button_layout)
        
        # Preview
        preview_group = QGroupBox("Preview")
        preview_layout = QVBoxLayout()
        
        self.preview_edit = QTextEdit()
        self.preview_edit.setReadOnly(True)
        preview_layout.addWidget(self.preview_edit)
        
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)
        
        # Status
        self.status_label = QLabel("Configure options and click 'Generate Report'")
        layout.addWidget(self.status_label)
        
        self.current_report = None
    
    def _on_generate_report(self):
        """Generate report based on options"""
        if not self.analysis_report:
            self.status_label.setText("No analysis data available. Please run analysis first.")
            return
        
        format_type = self.format_combo.currentText().lower()
        
        try:
            if format_type == "html":
                self.current_report = self._generate_html()
            elif format_type == "markdown":
                self.current_report = self._generate_markdown()
            elif format_type == "json":
                self.current_report = self._generate_json()
            
            self.preview_edit.setPlainText(self.current_report)
            self.save_btn.setEnabled(True)
            self.status_label.setText("Report generated successfully")
        except Exception as e:
            self.status_label.setText(f"Error generating report: {str(e)}")
    
    def _on_save_report(self):
        """Save report to file"""
        if not self.current_report:
            return
        
        format_type = self.format_combo.currentText().lower()
        extensions = {"html": ".html", "markdown": ".md", "json": ".json"}
        ext = extensions.get(format_type, ".txt")
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Report",
            f"volatility_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}",
            f"{format_type.upper()} Files (*{ext});;All Files (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.current_report)
                self.status_label.setText(f"Report saved to: {file_path}")
            except Exception as e:
                self.status_label.setText(f"Error saving report: {str(e)}")
    
    def _generate_html(self) -> str:
        """Generate HTML report"""
        html = ["<html><head><title>Volatility3 Analysis Report</title>"]
        html.append("<style>")
        html.append("body { font-family: Arial, sans-serif; margin: 20px; }")
        html.append("table { border-collapse: collapse; width: 100%; margin: 10px 0; }")
        html.append("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
        html.append("th { background-color: #4CAF50; color: white; }")
        html.append(".suspicious { background-color: #ffcccc; }")
        html.append(".high { background-color: #ff6666; }")
        html.append("</style></head><body>")
        
        html.append(f"<h1>Volatility3 Memory Analysis Report</h1>")
        html.append(f"<p><strong>Dump File:</strong> {self.analysis_report.dump_file}</p>")
        html.append(f"<p><strong>File Size:</strong> {self.analysis_report.dump_size / (1024*1024):.2f} MB</p>")
        html.append(f"<p><strong>Analysis Date:</strong> {self.analysis_report.analysis_timestamp}</p>")
        
        if self.include_suspicious.isChecked() and self.analysis_report.suspicious_artifacts:
            html.append("<h2>Suspicious Artifacts</h2>")
            html.append("<table>")
            html.append("<tr><th>Type</th><th>Source</th><th>Value</th><th>Reason</th><th>Severity</th></tr>")
            for artifact in self.analysis_report.suspicious_artifacts:
                if not self.suspicious_only.isChecked() or artifact.severity in ["high", "medium"]:
                    html.append(f"<tr class='{artifact.severity}'>")
                    html.append(f"<td>{artifact.artifact_type}</td>")
                    html.append(f"<td>{artifact.source}</td>")
                    html.append(f"<td>{artifact.value[:100]}</td>")
                    html.append(f"<td>{artifact.reason}</td>")
                    html.append(f"<td>{artifact.severity}</td>")
                    html.append("</tr>")
            html.append("</table>")
        
        if self.include_processes.isChecked() and self.analysis_report.processes:
            html.append("<h2>Processes</h2>")
            html.append("<table>")
            html.append("<tr><th>PID</th><th>PPID</th><th>Name</th><th>Path</th><th>Score</th></tr>")
            for proc in self.analysis_report.processes:
                if not self.suspicious_only.isChecked() or proc.suspicious_score >= 30:
                    cls = "suspicious" if proc.suspicious_score >= 30 else ""
                    html.append(f"<tr class='{cls}'>")
                    html.append(f"<td>{proc.pid}</td>")
                    html.append(f"<td>{proc.ppid}</td>")
                    html.append(f"<td>{proc.name}</td>")
                    html.append(f"<td>{proc.full_path[:100]}</td>")
                    html.append(f"<td>{proc.suspicious_score}</td>")
                    html.append("</tr>")
            html.append("</table>")
        
        if self.include_network.isChecked() and self.analysis_report.connections:
            html.append("<h2>Network Connections</h2>")
            html.append("<table>")
            html.append("<tr><th>Local IP</th><th>Local Port</th><th>Remote IP</th><th>Remote Port</th><th>Protocol</th><th>Score</th></tr>")
            for conn in self.analysis_report.connections:
                if not self.suspicious_only.isChecked() or conn.suspicious_score >= 30:
                    cls = "suspicious" if conn.suspicious_score >= 30 else ""
                    html.append(f"<tr class='{cls}'>")
                    html.append(f"<td>{conn.local_ip}</td>")
                    html.append(f"<td>{conn.local_port}</td>")
                    html.append(f"<td>{conn.remote_ip}</td>")
                    html.append(f"<td>{conn.remote_port}</td>")
                    html.append(f"<td>{conn.protocol}</td>")
                    html.append(f"<td>{conn.suspicious_score}</td>")
                    html.append("</tr>")
            html.append("</table>")
        
        html.append("</body></html>")
        return "\n".join(html)
    
    def _generate_markdown(self) -> str:
        """Generate Markdown report"""
        md = []
        md.append("# Volatility3 Memory Analysis Report\n")
        md.append(f"**Dump File:** {self.analysis_report.dump_file}\n")
        md.append(f"**File Size:** {self.analysis_report.dump_size / (1024*1024):.2f} MB\n")
        md.append(f"**Analysis Date:** {self.analysis_report.analysis_timestamp}\n")
        
        if self.include_suspicious.isChecked() and self.analysis_report.suspicious_artifacts:
            md.append("\n## Suspicious Artifacts\n")
            md.append("| Type | Source | Value | Reason | Severity |")
            md.append("|------|--------|-------|--------|----------|")
            for artifact in self.analysis_report.suspicious_artifacts:
                if not self.suspicious_only.isChecked() or artifact.severity in ["high", "medium"]:
                    md.append(f"| {artifact.artifact_type} | {artifact.source} | {artifact.value[:50]} | {artifact.reason} | {artifact.severity} |")
        
        if self.include_processes.isChecked() and self.analysis_report.processes:
            md.append("\n## Processes\n")
            md.append("| PID | PPID | Name | Path | Score |")
            md.append("|-----|------|------|------|-------|")
            for proc in self.analysis_report.processes:
                if not self.suspicious_only.isChecked() or proc.suspicious_score >= 30:
                    md.append(f"| {proc.pid} | {proc.ppid} | {proc.name} | {proc.full_path[:50]} | {proc.suspicious_score} |")
        
        if self.include_network.isChecked() and self.analysis_report.connections:
            md.append("\n## Network Connections\n")
            md.append("| Local IP | Local Port | Remote IP | Remote Port | Protocol | Score |")
            md.append("|----------|------------|-----------|-------------|----------|-------|")
            for conn in self.analysis_report.connections:
                if not self.suspicious_only.isChecked() or conn.suspicious_score >= 30:
                    md.append(f"| {conn.local_ip} | {conn.local_port} | {conn.remote_ip} | {conn.remote_port} | {conn.protocol} | {conn.suspicious_score} |")
        
        return "\n".join(md)
    
    def _generate_json(self) -> str:
        """Generate JSON report"""
        import json
        from datetime import datetime
        
        report_data = {
            "dump_file": self.analysis_report.dump_file,
            "dump_size": self.analysis_report.dump_size,
            "analysis_timestamp": self.analysis_report.analysis_timestamp.isoformat() if self.analysis_report.analysis_timestamp else None,
        }
        
        if self.include_suspicious.isChecked() and self.analysis_report.suspicious_artifacts:
            artifacts = []
            for artifact in self.analysis_report.suspicious_artifacts:
                if not self.suspicious_only.isChecked() or artifact.severity in ["high", "medium"]:
                    artifacts.append({
                        "type": artifact.artifact_type,
                        "source": artifact.source,
                        "value": artifact.value,
                        "reason": artifact.reason,
                        "severity": artifact.severity
                    })
            report_data["suspicious_artifacts"] = artifacts
        
        if self.include_processes.isChecked() and self.analysis_report.processes:
            processes = []
            for proc in self.analysis_report.processes:
                if not self.suspicious_only.isChecked() or proc.suspicious_score >= 30:
                    processes.append({
                        "pid": proc.pid,
                        "ppid": proc.ppid,
                        "name": proc.name,
                        "full_path": proc.full_path,
                        "command_line": proc.command_line,
                        "suspicious_score": proc.suspicious_score,
                        "suspicious_reasons": proc.suspicious_reasons
                    })
            report_data["processes"] = processes
        
        if self.include_network.isChecked() and self.analysis_report.connections:
            connections = []
            for conn in self.analysis_report.connections:
                if not self.suspicious_only.isChecked() or conn.suspicious_score >= 30:
                    connections.append({
                        "local_ip": conn.local_ip,
                        "local_port": conn.local_port,
                        "remote_ip": conn.remote_ip,
                        "remote_port": conn.remote_port,
                        "protocol": conn.protocol,
                        "state": conn.state,
                        "pid": conn.pid,
                        "process_name": conn.process_name,
                        "suspicious_score": conn.suspicious_score
                    })
            report_data["connections"] = connections
        
        return json.dumps(report_data, indent=2)

