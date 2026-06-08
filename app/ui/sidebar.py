"""Sidebar navigation widget"""
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel
from PySide6.QtCore import Signal, Qt


class Sidebar(QWidget):
    """Sidebar navigation with view buttons"""
    
    view_changed = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.setFixedWidth(220)
        self.current_button = None
        self._setup_ui()
        self._apply_styles()
    
    def _setup_ui(self):
        """Setup sidebar UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 10, 5, 10)
        layout.setSpacing(5)
        
        # Navigation buttons
        views = [
            ("overview", "Overview"),
            ("battle", "Battle Console"),
            ("filetree", "File Tree"),
            ("images", "Image Dump"),
            ("virustotal", "VirusTotal"),
            ("processes", "Processes"),
            ("network", "Network"),
            ("strings", "Strings Search"),
            ("decoded", "Decoded Strings"),
            ("suspicious", "Suspicious Artifacts"),
            ("advanced", "Advanced"),
            ("reports", "Reports"),
        ]
        
        for view_id, view_name in views:
            btn = QPushButton(view_name)
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, vid=view_id: self._on_view_clicked(vid, checked))
            layout.addWidget(btn)
            
            if view_id == "overview":
                btn.setChecked(True)
                self.current_button = btn
        
        layout.addStretch()
    
    def _on_view_clicked(self, view_id: str, checked: bool):
        """Handle view button click"""
        if checked:
            # Uncheck previous button
            if self.current_button:
                self.current_button.setChecked(False)
            
            # Find and check new button
            for i in range(self.layout().count()):
                item = self.layout().itemAt(i)
                if item and item.widget():
                    widget = item.widget()
                    if isinstance(widget, QPushButton) and widget.isChecked():
                        self.current_button = widget
                        break
            
            self.view_changed.emit(view_id)
    
    def _apply_styles(self):
        """Apply styles to sidebar"""
        self.setStyleSheet("""
            QWidget {
                background-color: #252525;
            }
            QPushButton {
                background-color: #2b2b2b;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                padding: 10px;
                text-align: left;
                color: #ffffff;
            }
            QPushButton:hover {
                background-color: #333333;
            }
            QPushButton:checked {
                background-color: #0078d4;
                border-color: #005a9e;
            }
        """)

