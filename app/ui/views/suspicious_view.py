"""Suspicious artifacts view"""
from typing import List
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QLabel, QHeaderView, QComboBox
)
from PySide6.QtCore import Qt
from ...core.models import SuspiciousArtifact


class SuspiciousView(QWidget):
    """View for displaying suspicious artifacts"""
    
    def __init__(self):
        super().__init__()
        self.artifacts: List[SuspiciousArtifact] = []
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup suspicious view UI"""
        layout = QVBoxLayout(self)
        
        # Filter bar
        filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter:")
        filter_layout.addWidget(filter_label)
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Search artifacts...")
        self.filter_edit.textChanged.connect(self._on_filter_changed)
        filter_layout.addWidget(self.filter_edit)
        
        severity_label = QLabel("Severity:")
        filter_layout.addWidget(severity_label)
        
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["All", "High", "Medium", "Low"])
        self.severity_combo.currentTextChanged.connect(self._on_filter_changed)
        filter_layout.addWidget(self.severity_combo)
        
        layout.addLayout(filter_layout)
        
        # Artifacts table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Type", "Source", "Value", "Reason", "Severity"
        ])
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        
        layout.addWidget(self.table)
        
        # Status label
        self.status_label = QLabel("No suspicious artifacts found")
        layout.addWidget(self.status_label)
    
    def update_data(self, artifacts: List[SuspiciousArtifact]):
        """Update the view with artifact data"""
        self.artifacts = artifacts
        self._populate_table()
        self._apply_filter()
    
    def _populate_table(self):
        """Populate table with artifacts"""
        self.table.setRowCount(len(self.artifacts))
        
        for row, artifact in enumerate(self.artifacts):
            self.table.setItem(row, 0, QTableWidgetItem(artifact.artifact_type))
            self.table.setItem(row, 1, QTableWidgetItem(artifact.source))
            
            value_item = QTableWidgetItem(artifact.value[:200])  # Limit length
            self.table.setItem(row, 2, value_item)
            
            self.table.setItem(row, 3, QTableWidgetItem(artifact.reason))
            
            severity_item = QTableWidgetItem(artifact.severity.upper())
            if artifact.severity == "high":
                severity_item.setForeground(Qt.red)
            elif artifact.severity == "medium":
                severity_item.setForeground(Qt.yellow)
            self.table.setItem(row, 4, severity_item)
        
        self.status_label.setText(f"Found {len(self.artifacts)} suspicious artifacts")
    
    def _on_filter_changed(self):
        """Handle filter change"""
        self._apply_filter()
    
    def _apply_filter(self):
        """Apply filter to table"""
        filter_text = self.filter_edit.text().lower()
        severity_filter = self.severity_combo.currentText().lower()
        
        for row in range(self.table.rowCount()):
            visible = True
            
            if filter_text:
                visible = False
                for col in range(self.table.columnCount()):
                    item = self.table.item(row, col)
                    if item and filter_text in item.text().lower():
                        visible = True
                        break
            
            if visible and severity_filter != "all":
                severity_item = self.table.item(row, 4)
                if severity_item:
                    if severity_item.text().lower() != severity_filter:
                        visible = False
            
            self.table.setRowHidden(row, not visible)

