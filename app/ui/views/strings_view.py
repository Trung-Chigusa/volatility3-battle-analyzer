"""Strings search view"""
from typing import List
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QLabel, QHeaderView, QCheckBox
)
from PySide6.QtCore import Qt
from ...core.models import StringMatch


class StringsView(QWidget):
    """View for string search results"""
    
    def __init__(self):
        super().__init__()
        self.string_matches: List[StringMatch] = []
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup strings view UI"""
        layout = QVBoxLayout(self)
        
        # Search bar
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        search_layout.addWidget(search_label)
        
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Enter search term or regex...")
        self.search_edit.returnPressed.connect(self._on_search)
        search_layout.addWidget(self.search_edit)
        
        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self._on_search)
        search_layout.addWidget(self.search_btn)
        
        self.regex_checkbox = QCheckBox("Use Regex")
        search_layout.addWidget(self.regex_checkbox)
        
        self.suspicious_only_checkbox = QCheckBox("Suspicious Only")
        self.suspicious_only_checkbox.toggled.connect(self._on_filter_changed)
        search_layout.addWidget(self.suspicious_only_checkbox)
        
        layout.addLayout(search_layout)
        
        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "PID", "Process", "Match", "Offset", "Region"
        ])
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        
        layout.addWidget(self.table)
        
        # Status label
        self.status_label = QLabel("No strings loaded. Use Advanced tab to run string search plugins.")
        layout.addWidget(self.status_label)
    
    def update_data(self, string_matches: List[StringMatch]):
        """Update the view with string matches"""
        self.string_matches = string_matches
        self._populate_table()
        self._apply_filter()
    
    def _populate_table(self):
        """Populate table with string matches"""
        self.table.setRowCount(len(self.string_matches))
        
        for row, match in enumerate(self.string_matches):
            self.table.setItem(row, 0, QTableWidgetItem(str(match.pid)))
            self.table.setItem(row, 1, QTableWidgetItem(match.process_name))
            
            match_item = QTableWidgetItem(match.match[:500])  # Limit length
            if match.suspicious:
                match_item.setForeground(Qt.red)
            self.table.setItem(row, 2, match_item)
            
            offset_text = hex(match.offset) if match.offset else ""
            self.table.setItem(row, 3, QTableWidgetItem(offset_text))
            self.table.setItem(row, 4, QTableWidgetItem(match.region))
        
        self.status_label.setText(f"Loaded {len(self.string_matches)} string matches")
    
    def _on_search(self):
        """Handle search button click"""
        # This would trigger a new search - for now just filter existing results
        self._apply_filter()
    
    def _on_filter_changed(self):
        """Handle filter change"""
        self._apply_filter()
    
    def _apply_filter(self):
        """Apply filter to table"""
        filter_text = self.search_edit.text().lower()
        suspicious_only = self.suspicious_only_checkbox.isChecked()
        use_regex = self.regex_checkbox.isChecked()
        
        import re
        pattern = None
        if filter_text and use_regex:
            try:
                pattern = re.compile(filter_text, re.IGNORECASE)
            except re.error:
                pattern = None
        
        for row in range(self.table.rowCount()):
            visible = True
            
            if filter_text:
                match_item = self.table.item(row, 2)
                if match_item:
                    text = match_item.text()
                    if use_regex and pattern:
                        visible = bool(pattern.search(text))
                    else:
                        visible = filter_text in text.lower()
            
            if visible and suspicious_only:
                match_item = self.table.item(row, 2)
                if match_item and match_item.foreground().color() != Qt.red:
                    visible = False
            
            self.table.setRowHidden(row, not visible)

