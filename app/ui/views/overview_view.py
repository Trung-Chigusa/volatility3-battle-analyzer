"""Overview/Dashboard view"""
from pathlib import Path
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QFrame
)
from PySide6.QtCore import Signal, Qt
from PySide6.QtGui import QFont


class OverviewView(QWidget):
    """Overview/Dashboard view with file selection"""
    
    file_selected = Signal(str)
    analyze_clicked = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.current_file = None
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup overview UI"""
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        
        # File drop area
        self.drop_area = QFrame()
        self.drop_area.setFrameShape(QFrame.Box)
        self.drop_area.setMinimumHeight(300)
        drop_layout = QVBoxLayout(self.drop_area)
        drop_layout.setAlignment(Qt.AlignCenter)
        
        self.drop_label = QLabel("Drop memory dump here or click to select file")
        self.drop_label.setAlignment(Qt.AlignCenter)
        font = QFont()
        font.setPointSize(14)
        self.drop_label.setFont(font)
        drop_layout.addWidget(self.drop_label)
        
        select_btn = QPushButton("Select File")
        select_btn.clicked.connect(self._on_select_file)
        select_btn.setMinimumWidth(150)
        drop_layout.addWidget(select_btn, alignment=Qt.AlignCenter)
        
        layout.addWidget(self.drop_area)
        
        # File info (hidden initially)
        self.file_info = QWidget()
        file_info_layout = QVBoxLayout(self.file_info)
        file_info_layout.setSpacing(10)
        
        self.file_name_label = QLabel()
        self.file_name_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        file_info_layout.addWidget(self.file_name_label)
        
        self.file_size_label = QLabel()
        file_info_layout.addWidget(self.file_size_label)
        
        # Analysis buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)
        
        self.full_analysis_btn = QPushButton("Start Full Analysis")
        self.full_analysis_btn.clicked.connect(lambda: self.analyze_clicked.emit("full"))
        buttons_layout.addWidget(self.full_analysis_btn)
        
        self.processes_btn = QPushButton("Processes Only")
        self.processes_btn.clicked.connect(lambda: self.analyze_clicked.emit("processes"))
        buttons_layout.addWidget(self.processes_btn)
        
        self.network_btn = QPushButton("Network Only")
        self.network_btn.clicked.connect(lambda: self.analyze_clicked.emit("network"))
        buttons_layout.addWidget(self.network_btn)
        
        file_info_layout.addLayout(buttons_layout)
        
        self.file_info.setVisible(False)
        layout.addWidget(self.file_info)
        
        layout.addStretch()
        
        self._apply_styles()

    def set_buttons_enabled(self, enabled: bool):
        """Enable/disable analysis buttons"""
        self.full_analysis_btn.setEnabled(enabled)
        self.processes_btn.setEnabled(enabled)
        self.network_btn.setEnabled(enabled)
    
    def _apply_styles(self):
        """Apply styles"""
        self.drop_area.setStyleSheet("""
            QFrame {
                border: 2px dashed #555555;
                border-radius: 10px;
                background-color: #1e1e1e;
            }
        """)
    
    def _on_select_file(self):
        """Handle file selection"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Memory Dump File",
            "",
            "Memory Dumps (*.dmp *.raw *.vmem *.img *.dump);;All Files (*.*)"
        )
        if file_path:
            self.set_file(file_path)
    
    def set_file(self, file_path: str):
        """Set the current file and update UI"""
        self.current_file = file_path
        file_name = Path(file_path).name
        file_size = Path(file_path).stat().st_size / (1024 * 1024)  # MB
        
        self.file_name_label.setText(f"File: {file_name}")
        self.file_size_label.setText(f"Size: {file_size:.2f} MB")
        
        self.drop_area.setVisible(False)
        self.file_info.setVisible(True)
        
        self.file_selected.emit(file_path)

