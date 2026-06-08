"""Processes view with tree and table"""
from typing import List, Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTreeWidget, QTreeWidgetItem, QLabel, QHeaderView, QMenu
)
from PySide6.QtCore import Qt, Signal, QPoint, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from ...core.models import Process


class ProcessesView(QWidget):
    """View for displaying process tree and details"""
    
    dump_requested = Signal(int)
    
    def __init__(self):
        super().__init__()
        self.processes: List[Process] = []
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup processes view UI"""
        layout = QVBoxLayout(self)
        
        # Search/filter bar
        filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter:")
        filter_layout.addWidget(filter_label)
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Search by name, PID, or path...")
        self.filter_edit.textChanged.connect(self._on_filter_changed)
        filter_layout.addWidget(self.filter_edit)
        
        self.suspicious_only_btn = QPushButton("Show Suspicious Only")
        self.suspicious_only_btn.setCheckable(True)
        self.suspicious_only_btn.toggled.connect(self._on_filter_changed)
        filter_layout.addWidget(self.suspicious_only_btn)
        
        layout.addLayout(filter_layout)
        
        # Process tree
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([
            "PID", "PPID", "Name", "Path", "SHA256", "Command Line", "User", "Score"
        ])
        self.tree.setAlternatingRowColors(True)
        self.tree.setRootIsDecorated(True)
        self.tree.header().setStretchLastSection(False)
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._on_context_menu)
        
        layout.addWidget(self.tree)
        
        # Status label
        self.status_label = QLabel("No processes loaded")
        layout.addWidget(self.status_label)
    
    def _on_context_menu(self, position: QPoint):
        """Show context menu for process actions"""
        item = self.tree.itemAt(position)
        if not item:
            return
        try:
            pid = int(item.text(0))
        except ValueError:
            return
        
        sha_text = item.text(4)
        
        menu = QMenu(self)
        dump_action = menu.addAction("Dump Executable...")
        copy_hash_action = menu.addAction("Copy SHA256")
        vt_action = menu.addAction("Open in VirusTotal")
        vt_action.setEnabled(bool(sha_text))
        
        selected = menu.exec(self.tree.viewport().mapToGlobal(position))
        if selected == dump_action:
            self.dump_requested.emit(pid)
        elif selected == copy_hash_action and sha_text:
            clipboard = QGuiApplication.clipboard()
            clipboard.setText(sha_text)
        elif selected == vt_action and sha_text:
            url = QUrl(f"https://www.virustotal.com/gui/file/{sha_text}")
            QDesktopServices.openUrl(url)
    
    def update_data(self, processes: List[Process]):
        """Update the view with process data"""
        self.processes = processes
        self._build_tree()
        self._apply_filter()
    
    def _build_tree(self):
        """Build process tree from process list"""
        self.tree.clear()
        
        if not self.processes:
            self.status_label.setText("No processes found")
            return
        
        # Create process map
        process_map = {proc.pid: proc for proc in self.processes}
        
        # Build parent-child relationships
        root_processes = []
        for proc in self.processes:
            proc.children = []
            if proc.ppid == 0 or proc.ppid not in process_map:
                root_processes.append(proc)
            else:
                parent = process_map.get(proc.ppid)
                if parent:
                    parent.children.append(proc)
        
        # Add to tree
        for proc in root_processes:
            self._add_process_to_tree(None, proc)
        
        self.status_label.setText(f"Loaded {len(self.processes)} processes")
        self.tree.expandAll()
    
    def _add_process_to_tree(self, parent_item: Optional[QTreeWidgetItem], process: Process):
        """Recursively add process and children to tree"""
        item = QTreeWidgetItem(parent_item or self.tree)
        item.setText(0, str(process.pid))
        item.setText(1, str(process.ppid))
        item.setText(2, process.name)
        item.setText(3, process.full_path[:100] if process.full_path else "")
        item.setText(4, process.sha256 or "")
        item.setText(5, process.command_line[:100] if process.command_line else "")
        item.setText(6, process.user)
        item.setText(7, str(process.suspicious_score))
        
        # Color code by suspicion score
        if process.suspicious_score >= 50:
            item.setForeground(7, Qt.red)
            for col in range(item.columnCount()):
                item.setBackground(col, Qt.darkRed)
        elif process.suspicious_score >= 30:
            item.setForeground(7, Qt.yellow)
            for col in range(item.columnCount()):
                item.setBackground(col, Qt.darkYellow)
        
        # Add children
        for child in process.children:
            self._add_process_to_tree(item, child)
        
        # Expand root items
        if parent_item is None:
            item.setExpanded(True)
    
    def _on_filter_changed(self):
        """Handle filter change"""
        self._apply_filter()
    
    def _apply_filter(self):
        """Apply filter to tree"""
        filter_text = self.filter_edit.text().lower()
        suspicious_only = self.suspicious_only_btn.isChecked()
        
        def should_show(item: QTreeWidgetItem) -> bool:
            # Check filter text
            if filter_text:
                for col in range(item.columnCount()):
                    if filter_text in item.text(col).lower():
                        return True
                return False
            
            # Check suspicious filter
            if suspicious_only:
                score_text = item.text(7)
                try:
                    score = int(score_text)
                    if score < 30:
                        return False
                except ValueError:
                    pass
            
            return True
        
        # Hide/show items based on filter
        def filter_tree_item(item: QTreeWidgetItem):
            visible = should_show(item)
            item.setHidden(not visible)
            
            # Check children
            for i in range(item.childCount()):
                child = item.child(i)
                filter_tree_item(child)
                if not child.isHidden():
                    visible = True
            
            # Show parent if any child is visible
            if visible and item.parent():
                item.setHidden(False)
        
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            filter_tree_item(item)

