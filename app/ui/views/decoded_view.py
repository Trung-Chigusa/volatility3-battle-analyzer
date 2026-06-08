"""Decoded strings view"""
from typing import List, Dict
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QLabel, QHeaderView, QComboBox, QTextEdit
)
from PySide6.QtCore import Qt


class DecodedView(QWidget):
    """View for displaying decoded strings"""
    
    def __init__(self):
        super().__init__()
        self.decoded_strings: List[Dict] = []
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup decoded view UI"""
        layout = QVBoxLayout(self)
        
        # Filter bar
        filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter:")
        filter_layout.addWidget(filter_label)
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Search decoded content...")
        self.filter_edit.textChanged.connect(self._on_filter_changed)
        filter_layout.addWidget(self.filter_edit)
        
        encoding_label = QLabel("Encoding:")
        filter_layout.addWidget(encoding_label)
        
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(["All", "base64", "base32", "hex", "url"])
        self.encoding_combo.currentTextChanged.connect(self._on_filter_changed)
        filter_layout.addWidget(self.encoding_combo)
        
        self.high_confidence_btn = QPushButton("High Confidence Only")
        self.high_confidence_btn.setCheckable(True)
        self.high_confidence_btn.toggled.connect(self._on_filter_changed)
        filter_layout.addWidget(self.high_confidence_btn)
        
        layout.addLayout(filter_layout)
        
        # Decoded strings table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Encoding", "Original (truncated)", "Decoded", "Confidence", 
            "PID", "Process", "Offset", "Location"
        ])
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_context_menu)
        
        layout.addWidget(self.table)
        
        # Detail view for selected item
        detail_group = QWidget()
        detail_layout = QVBoxLayout(detail_group)
        detail_label = QLabel("Details:")
        detail_layout.addWidget(detail_label)
        
        self.detail_edit = QTextEdit()
        self.detail_edit.setReadOnly(True)
        self.detail_edit.setMaximumHeight(150)
        self.detail_edit.setFontFamily("Courier")
        detail_layout.addWidget(self.detail_edit)
        
        layout.addWidget(detail_group)
        
        # Status label
        self.status_label = QLabel("No decoded strings found")
        layout.addWidget(self.status_label)
        
        # Connect selection change
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
    
    def update_data(self, decoded_strings: List[Dict]):
        """Update the view with decoded string data"""
        self.decoded_strings = decoded_strings
        self._populate_table()
        self._apply_filter()
    
    def _populate_table(self):
        """Populate table with decoded strings"""
        self.table.setRowCount(len(self.decoded_strings))
        
        for row, item in enumerate(self.decoded_strings):
            # Encoding
            encoding_item = QTableWidgetItem(item.get('encoding', 'unknown'))
            self.table.setItem(row, 0, encoding_item)
            
            # Original (truncated)
            original = item.get('original', '')[:50]
            if len(item.get('original', '')) > 50:
                original += '...'
            self.table.setItem(row, 1, QTableWidgetItem(original))
            
            # Decoded
            decoded = item.get('decoded', '')
            decoded_item = QTableWidgetItem(decoded[:200])  # Limit display length
            if item.get('confidence', 0) >= 0.7:
                decoded_item.setForeground(Qt.green)
            elif item.get('confidence', 0) >= 0.5:
                decoded_item.setForeground(Qt.yellow)
            self.table.setItem(row, 2, decoded_item)
            
            # Confidence
            confidence = item.get('confidence', 0)
            confidence_item = QTableWidgetItem(f"{confidence:.2f}")
            if confidence >= 0.7:
                confidence_item.setForeground(Qt.green)
            elif confidence >= 0.5:
                confidence_item.setForeground(Qt.yellow)
            else:
                confidence_item.setForeground(Qt.red)
            self.table.setItem(row, 3, confidence_item)
            
            # PID
            self.table.setItem(row, 4, QTableWidgetItem(str(item.get('source_pid', ''))))
            
            # Process
            self.table.setItem(row, 5, QTableWidgetItem(item.get('source_process', '')))
            
            # Offset
            offset = item.get('source_offset', '')
            if offset:
                offset_str = hex(offset) if isinstance(offset, int) else str(offset)
            else:
                offset_str = ''
            self.table.setItem(row, 6, QTableWidgetItem(offset_str))
            
            # Location
            location = item.get('location', '') or item.get('source_region', '')
            self.table.setItem(row, 7, QTableWidgetItem(location))
        
        self.status_label.setText(f"Found {len(self.decoded_strings)} decoded strings")
    
    def _on_filter_changed(self):
        """Handle filter change"""
        self._apply_filter()
    
    def _apply_filter(self):
        """Apply filter to table"""
        filter_text = self.filter_edit.text().lower()
        encoding_filter = self.encoding_combo.currentText().lower()
        high_confidence_only = self.high_confidence_btn.isChecked()
        
        for row in range(self.table.rowCount()):
            visible = True
            
            if filter_text:
                visible = False
                # Check in decoded content
                decoded_item = self.table.item(row, 2)
                if decoded_item and filter_text in decoded_item.text().lower():
                    visible = True
                # Check in original
                original_item = self.table.item(row, 1)
                if original_item and filter_text in original_item.text().lower():
                    visible = True
            
            if visible and encoding_filter != "all":
                encoding_item = self.table.item(row, 0)
                if encoding_item and encoding_item.text().lower() != encoding_filter:
                    visible = False
            
            if visible and high_confidence_only:
                confidence_item = self.table.item(row, 3)
                if confidence_item:
                    try:
                        confidence = float(confidence_item.text())
                        if confidence < 0.7:
                            visible = False
                    except ValueError:
                        pass
            
            self.table.setRowHidden(row, not visible)
    
    def _on_selection_changed(self):
        """Handle table selection change"""
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            self.detail_edit.clear()
            return
        
        row = selected_rows[0].row()
        if row < len(self.decoded_strings):
            item = self.decoded_strings[row]
            
            detail_text = f"Encoding: {item.get('encoding', 'unknown')}\n"
            detail_text += f"Confidence: {item.get('confidence', 0):.2f}\n"
            detail_text += f"Source PID: {item.get('source_pid', 'N/A')}\n"
            detail_text += f"Source Process: {item.get('source_process', 'N/A')}\n"
            detail_text += f"Offset: {hex(item.get('source_offset', 0)) if item.get('source_offset') else 'N/A'}\n"
            detail_text += f"Location: {item.get('location', item.get('source_region', 'N/A'))}\n\n"
            detail_text += f"Original (full):\n{item.get('original', '')}\n\n"
            detail_text += f"Decoded (full):\n{item.get('decoded', '')}"
            
            self.detail_edit.setPlainText(detail_text)
    
    def _on_context_menu(self, position):
        """Handle right-click context menu"""
        item = self.table.itemAt(position)
        if item:
            # Could add copy, export, etc. here
            pass

