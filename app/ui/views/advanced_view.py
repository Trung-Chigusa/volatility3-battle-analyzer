"""Advanced plugin runner view"""
from typing import Dict, List
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QComboBox, QPushButton,
    QTextEdit, QLabel, QLineEdit, QGroupBox, QFormLayout
)
from PySide6.QtCore import Qt


class AdvancedView(QWidget):
    """Advanced view for running plugins manually"""
    
    def __init__(self):
        super().__init__()
        self.vol_runner = None
        self._setup_ui()
    
    def set_vol_runner(self, vol_runner):
        """Set the volatility runner instance"""
        self.vol_runner = vol_runner
        if vol_runner:
            self._load_plugins()
    
    def _setup_ui(self):
        """Setup advanced view UI"""
        layout = QVBoxLayout(self)
        
        # Plugin selection
        plugin_group = QGroupBox("Plugin Selection")
        plugin_layout = QFormLayout()
        
        self.plugin_combo = QComboBox()
        self.plugin_combo.setEditable(True)
        self.plugin_combo.setMinimumWidth(300)
        plugin_layout.addRow("Plugin:", self.plugin_combo)
        
        plugin_group.setLayout(plugin_layout)
        layout.addWidget(plugin_group)
        
        # Arguments (simple key-value pairs for now)
        args_group = QGroupBox("Plugin Arguments (JSON format)")
        args_layout = QVBoxLayout()
        
        self.args_edit = QTextEdit()
        self.args_edit.setPlaceholderText('{"key": "value", ...}')
        self.args_edit.setMaximumHeight(100)
        args_layout.addWidget(self.args_edit)
        
        args_group.setLayout(args_layout)
        layout.addWidget(args_group)
        
        # Run button
        button_layout = QHBoxLayout()
        self.run_btn = QPushButton("Run Plugin")
        self.run_btn.clicked.connect(self._on_run_plugin)
        button_layout.addWidget(self.run_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        # Output
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        
        self.output_edit = QTextEdit()
        self.output_edit.setReadOnly(True)
        self.output_edit.setFontFamily("Courier")
        output_layout.addWidget(self.output_edit)
        
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Status
        self.status_label = QLabel("Select a plugin and click 'Run Plugin'")
        layout.addWidget(self.status_label)
    
    def _load_plugins(self):
        """Load available plugins into combo box"""
        if not self.vol_runner:
            return
        
        try:
            plugins = self.vol_runner.get_available_plugins()
            self.plugin_combo.clear()
            self.plugin_combo.addItems(sorted(plugins.keys()))
            self.status_label.setText(f"Loaded {len(plugins)} plugins")
        except Exception as e:
            self.status_label.setText(f"Error loading plugins: {str(e)}")
    
    def _on_run_plugin(self):
        """Handle run plugin button click"""
        if not self.vol_runner:
            self.status_label.setText("No volatility runner available. Please load a memory dump first.")
            return
        
        plugin_name = self.plugin_combo.currentText()
        if not plugin_name:
            self.status_label.setText("Please select a plugin")
            return
        
        # Parse arguments
        args_text = self.args_edit.toPlainText().strip()
        plugin_args = {}
        if args_text:
            try:
                import json
                plugin_args = json.loads(args_text)
            except json.JSONDecodeError as e:
                self.status_label.setText(f"Invalid JSON in arguments: {e}")
                return
        
        # Run plugin
        self.status_label.setText(f"Running plugin: {plugin_name}...")
        self.output_edit.clear()
        self.run_btn.setEnabled(False)
        
        try:
            results = self.vol_runner.run_plugin_to_list(plugin_name, plugin_args)
            
            # Format output
            if results:
                output_lines = []
                if results:
                    # Header
                    headers = list(results[0].keys())
                    output_lines.append(" | ".join(headers))
                    output_lines.append("-" * 80)
                    
                    # Rows
                    for row in results[:100]:  # Limit to 100 rows
                        values = [str(row.get(h, ""))[:50] for h in headers]
                        output_lines.append(" | ".join(values))
                    
                    if len(results) > 100:
                        output_lines.append(f"\n... and {len(results) - 100} more rows")
                
                self.output_edit.setPlainText("\n".join(output_lines))
                self.status_label.setText(f"Plugin completed: {len(results)} results")
            else:
                self.output_edit.setPlainText("No results returned")
                self.status_label.setText("Plugin completed with no results")
                
        except Exception as e:
            self.output_edit.setPlainText(f"Error: {str(e)}")
            self.status_label.setText(f"Plugin failed: {str(e)}")
        finally:
            self.run_btn.setEnabled(True)

