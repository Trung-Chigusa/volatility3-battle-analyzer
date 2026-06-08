"""Settings dialog"""
import json
import os
from pathlib import Path
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QLineEdit, QSpinBox, QFormLayout, QGroupBox
)
from PySide6.QtCore import Qt


class SettingsDialog(QDialog):
    """Settings dialog for application configuration"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(400)
        self.config_file = Path.home() / ".volatility3_gui_config.json"
        self.settings = self._load_settings()
        self._setup_ui()
        self._apply_styles()
    
    def _setup_ui(self):
        """Setup settings UI"""
        layout = QVBoxLayout(self)
        
        # Performance settings
        perf_group = QGroupBox("Performance")
        perf_layout = QFormLayout()
        
        self.max_workers_spin = QSpinBox()
        self.max_workers_spin.setMinimum(1)
        self.max_workers_spin.setMaximum(32)
        self.max_workers_spin.setValue(self.settings.get("max_workers", 4))
        perf_layout.addRow("Max Parallel Workers:", self.max_workers_spin)
        
        perf_group.setLayout(perf_layout)
        layout.addWidget(perf_group)
        
        # Heuristics settings
        heur_group = QGroupBox("Heuristics")
        heur_layout = QFormLayout()
        
        self.uncommon_port_spin = QSpinBox()
        self.uncommon_port_spin.setMinimum(1024)
        self.uncommon_port_spin.setMaximum(65535)
        self.uncommon_port_spin.setValue(self.settings.get("uncommon_port_threshold", 49152))
        heur_layout.addRow("Uncommon Port Threshold:", self.uncommon_port_spin)
        
        heur_group.setLayout(heur_layout)
        layout.addWidget(heur_group)
        
        # Paths
        paths_group = QGroupBox("Paths")
        paths_layout = QFormLayout()
        
        self.volatility_path_edit = QLineEdit()
        self.volatility_path_edit.setText(self.settings.get("volatility_path", ""))
        paths_layout.addRow("Volatility3 Path:", self.volatility_path_edit)
        
        paths_group.setLayout(paths_layout)
        layout.addWidget(paths_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self._on_ok)
        button_layout.addWidget(ok_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
    
    def _apply_styles(self):
        """Apply styles"""
        self.setStyleSheet("""
            QDialog {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QGroupBox {
                border: 1px solid #555555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
            }
        """)
    
    def _load_settings(self) -> dict:
        """Load settings from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
    
    def _save_settings(self):
        """Save settings to file"""
        self.settings = {
            "max_workers": self.max_workers_spin.value(),
            "uncommon_port_threshold": self.uncommon_port_spin.value(),
            "volatility_path": self.volatility_path_edit.text(),
        }
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
        except Exception as e:
            print(f"Error saving settings: {e}")
    
    def _on_ok(self):
        """Handle OK button"""
        self._save_settings()
        self.accept()
    
    def get_settings(self) -> dict:
        """Get current settings"""
        return self.settings

