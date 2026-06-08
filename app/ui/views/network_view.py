"""Network connections view"""
from typing import List
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QLabel, QHeaderView
)
from PySide6.QtCore import Qt
from ...core.models import NetworkConnection


class NetworkView(QWidget):
    """View for displaying network connections"""
    
    def __init__(self):
        super().__init__()
        self.connections: List[NetworkConnection] = []
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup network view UI"""
        layout = QVBoxLayout(self)
        
        # Filter bar
        filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter:")
        filter_layout.addWidget(filter_label)
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Search by IP, port, or process...")
        self.filter_edit.textChanged.connect(self._on_filter_changed)
        filter_layout.addWidget(self.filter_edit)
        
        self.suspicious_only_btn = QPushButton("Show Suspicious Only")
        self.suspicious_only_btn.setCheckable(True)
        self.suspicious_only_btn.toggled.connect(self._on_filter_changed)
        filter_layout.addWidget(self.suspicious_only_btn)
        
        layout.addLayout(filter_layout)
        
        # Connections table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Local IP", "Local Port", "Remote IP", "Remote Port",
            "Protocol", "State", "PID", "Process", "Score"
        ])
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        
        layout.addWidget(self.table)
        
        # Status label
        self.status_label = QLabel("No connections loaded")
        layout.addWidget(self.status_label)
    
    def update_data(self, connections: List[NetworkConnection]):
        """Update the view with connection data"""
        self.connections = connections
        self._populate_table()
        self._apply_filter()
    
    def _populate_table(self):
        """Populate table with connections"""
        self.table.setRowCount(len(self.connections))
        
        for row, conn in enumerate(self.connections):
            self.table.setItem(row, 0, QTableWidgetItem(conn.local_ip))
            self.table.setItem(row, 1, QTableWidgetItem(str(conn.local_port)))
            self.table.setItem(row, 2, QTableWidgetItem(conn.remote_ip))
            self.table.setItem(row, 3, QTableWidgetItem(str(conn.remote_port)))
            self.table.setItem(row, 4, QTableWidgetItem(conn.protocol))
            self.table.setItem(row, 5, QTableWidgetItem(conn.state))
            self.table.setItem(row, 6, QTableWidgetItem(str(conn.pid)))
            self.table.setItem(row, 7, QTableWidgetItem(conn.process_name))
            
            score_item = QTableWidgetItem(str(conn.suspicious_score))
            if conn.suspicious_score >= 50:
                score_item.setForeground(Qt.red)
                for col in range(9):
                    if self.table.item(row, col):
                        self.table.item(row, col).setBackground(Qt.darkRed)
            elif conn.suspicious_score >= 30:
                score_item.setForeground(Qt.yellow)
                for col in range(9):
                    if self.table.item(row, col):
                        self.table.item(row, col).setBackground(Qt.darkYellow)
            self.table.setItem(row, 8, score_item)
        
        self.status_label.setText(f"Loaded {len(self.connections)} connections")
    
    def _on_filter_changed(self):
        """Handle filter change"""
        self._apply_filter()
    
    def _apply_filter(self):
        """Apply filter to table"""
        filter_text = self.filter_edit.text().lower()
        suspicious_only = self.suspicious_only_btn.isChecked()
        
        for row in range(self.table.rowCount()):
            visible = True
            
            if filter_text:
                visible = False
                for col in range(self.table.columnCount()):
                    item = self.table.item(row, col)
                    if item and filter_text in item.text().lower():
                        visible = True
                        break
            
            if visible and suspicious_only:
                score_item = self.table.item(row, 8)
                if score_item:
                    try:
                        score = int(score_item.text())
                        if score < 30:
                            visible = False
                    except ValueError:
                        pass
            
            self.table.setRowHidden(row, not visible)

