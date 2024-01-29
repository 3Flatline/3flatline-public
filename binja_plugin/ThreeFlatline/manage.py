from binaryninja import BinaryView
from binaryninja.settings import Settings
import re
import tempfile
import binaryninjaui
from binaryninja import DisassemblySettings, lineardisassembly, DisassemblyOption
from binaryninja.plugin import PluginCommand, BackgroundTaskThread
from typing import Optional
import time

if "qt_major_version" in dir(binaryninjaui) and binaryninjaui.qt_major_version == 6:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QPlainTextEdit, QWidget, QPushButton, QKeySequenceEdit, QCheckBox, QVBoxLayout, QScrollArea, QFormLayout, QListWidget, QListWidgetItem
else:
    from PySide2.QtCore import Qt
    from PySide2.QtWidgets import QPlainTextEdit, QWidget, QPushButton, QKeySequenceEdit, QCheckBox, QVBoxLayout, QScrollArea, QFormLayout, QListWidget, QListWidgetItem

from .api import DixieAPI

class ManageTasks(QWidget):
    """Custom editor widget."""
    # Dixie API
    dix: DixieAPI
    # The currently focused BinaryView.
    bv: Optional[BinaryView] = None
    

    def __init__(self, parent: QWidget, dix: DixieAPI, bv: Optional[BinaryView]):
        QWidget.__init__(self, parent)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
        # The currently focused BinaryView.
        self.bv = bv
        self.dix = dix
        # # Editor should use a monospace font
        # self.setFont(binaryninjaui.getDefaultMonospaceFont())
        # Create spots for settings
        refresh_button = QPushButton("Refresh Task List")
        refresh_button.clicked.connect(self.refresh_results)
        self.layout.addWidget(refresh_button)
        self.list_widget = QListWidget()
        self.layout.addWidget(self.list_widget)
        delete_button = QPushButton("Delete Tasks")
        delete_button.clicked.connect(self.delete_tasks)
        self.layout.addWidget(delete_button)
        self.username = Settings().get_string("dixie.username") 
        self.password = Settings().get_string("dixie.password")

    def refresh_results(self):
        """Update the viewer when the content of the linked editor changes."""
        self.username = Settings().get_string("dixie.username")
        self.password = Settings().get_string("dixie.password")

        if not self.username or not self.password:
            print("Please set your Dixie username and password in the settings menu.")
            return
        self.dix.authenticate(self.username, self.password)
        task_list = []
        raw_results = self.dix.retrieve_status()
        for key, value in raw_results.items():
            task_list.append(value)
        self.clear_widgets()
        print("Cleared widgets")

        for entry in task_list:
            task_id = entry.get("task_id")
            filepath = entry.get("filepath")
            created_at = entry.get("created_at")
            status = entry.get("status")
            box_name = f"{task_id}\n\t-{filepath}\n\t-{created_at}\n\t-{status}"
            print(box_name)
            list_widget_item = QListWidgetItem(
                box_name,
                self.list_widget
            )
            list_widget_item.setFlags(list_widget_item.flags() | Qt.ItemIsUserCheckable)
            list_widget_item.setCheckState(Qt.Unchecked)

    def clear_widgets(self):
        self.list_widget.clear()

    def delete_tasks(self):
        if not self.username or not self.password:
            print("Please set your Dixie username and password in the settings menu.")
            return
        self.dix.authenticate(self.username, self.password)
        task_ids_for_deletion = []
        length = self.list_widget.count()
        for i in range(0, length):
            item = self.list_widget.item(i)
            if item.checkState() == Qt.Checked:
                print(f"Deleting {item.text()}")
                task_id = item.text().split("\n")[0]
                task_ids_for_deletion.append(task_id)
        
        self.dix.delete_tasks(task_ids_for_deletion)
        self.refresh_results()
        self.dix.sign_out()
