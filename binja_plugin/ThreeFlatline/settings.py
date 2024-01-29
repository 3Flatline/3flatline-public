from binaryninja import BinaryView
from binaryninja.settings import Settings
import re
import tempfile
import binaryninjaui
from binaryninja import DisassemblySettings, lineardisassembly, DisassemblyOption
from binaryninja.plugin import PluginCommand, BackgroundTaskThread
from typing import Optional


if "qt_major_version" in dir(binaryninjaui) and binaryninjaui.qt_major_version == 6:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QPlainTextEdit, QWidget, QPushButton, QKeySequenceEdit, QCheckBox, QVBoxLayout, QScrollArea, QFormLayout, QListWidget, QListWidgetItem
else:
    from PySide2.QtCore import Qt
    from PySide2.QtWidgets import QPlainTextEdit, QWidget, QPushButton, QKeySequenceEdit, QCheckBox, QVBoxLayout, QScrollArea, QFormLayout, QListWidget, QListWidgetItem

from .api import DixieAPI

class AnalysisSettings(QWidget):
    """Custom editor widget."""

    dix: DixieAPI
    bv: Optional[BinaryView] = None
    
    def __init__(self, parent: QWidget, dix: DixieAPI, bv: Optional[BinaryView]):
        QWidget.__init__(self, parent)
        layout = QVBoxLayout()
        self.setLayout(layout)
        self.bv = bv
        self.dix = dix
        refresh_button = QPushButton("Refresh Function List")
        refresh_button.clicked.connect(self.refresh_widgets)
        layout.addWidget(refresh_button)
        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)
        run_button = QPushButton("Run Analysis")
        run_button.clicked.connect(self.create_tasks)
        layout.addWidget(run_button)

        self.username = Settings().get_string("dixie.username") 
        self.password = Settings().get_string("dixie.password")
        self.selected_functions = []
        self.available_functions = []

        for fn in self.bv.functions:
            list_widget_item = QListWidgetItem(
                fn.name,
                self.list_widget
            )
            list_widget_item.setFlags(list_widget_item.flags() | Qt.ItemIsUserCheckable)
            list_widget_item.setCheckState(Qt.Unchecked)

    def clear_widgets(self):
        self.list_widget.clear()
    
    def refresh_widgets(self):
        self.clear_widgets()
        for fn in self.bv.functions:
            list_widget_item = QListWidgetItem(
                fn.name,
                self.list_widget
            )
            list_widget_item.setFlags(list_widget_item.flags() | Qt.ItemIsUserCheckable)
            list_widget_item.setCheckState(Qt.Unchecked)

    def c_source(self, bv, func):
        replacements = [("__noreturn", "/* __noreturn__ */"),
            (r"__convention\(([^)]*)\)", r"/* __convention(\1) */")
        ]
        offsets = False
        lines = ''
        Settings().set_string('rendering.hlil.scopingStyle', 'bracesNewLine')
        settings = DisassemblySettings()
        settings.set_option(DisassemblyOption.ShowAddress, False)	
        obj = lineardisassembly.LinearViewObject.language_representation(bv, settings)
        cursor_end = lineardisassembly.LinearViewCursor(obj)
        cursor_end.seek_to_address(func.highest_address)
        bruh = bv.get_next_linear_disassembly_lines(cursor_end)
        cursor_end.seek_to_address(func.highest_address)
        bruh2 = bv.get_previous_linear_disassembly_lines(cursor_end)
        for line in bruh2:
            output = str(line)
            for (pat, repl) in replacements:
                output = re.sub(pat, repl, output)
            lines += output
            if offsets and len(output) > 2:
                lines += f" /* 0x{line.contents.address:04x} */ "
            lines += "\n"
        for line in bruh:
            output = str(line)
            for (pat, repl) in replacements:
                output = re.sub(pat, repl, output)
            lines += output
            if offsets and len(output) > 2:
                lines += f" /* 0x{line.contents.address:04x} */ "
            lines += "\n"
        return lines

    def c_to_file(self, bv, filename):
        with open(filename, 'w') as f:
            #TODO: output binjadefs.h to output
            bv.begin_undo_actions()
            for tag in bv.tag_types:
                bv.tag_types[tag].visible = False
            bv.commit_undo_actions()
            for fn in bv.functions:
                f.write(self.c_source(bv, fn))
                f.write('')
            bv.undo()

    def create_tasks(self):
        """Create tasks for analysis."""
        # TODO: Popups?
        if not self.username or not self.password:
            print("No username or password set.  Please set them in settings.")
        if not self.selected_functions:
            print("No functions selected.  Please select functions to analyze.")
        self.dix.authenticate(self.username, self.password)
        self.bv.begin_undo_actions()
        for tag in self.bv.tag_types:
            self.bv.tag_types[tag].visible = False
        self.bv.commit_undo_actions()
        length = self.list_widget.count()
        checked_functions = []
        for i in range(0, length):
            item = self.list_widget.item(i)
            if item.checkState() == Qt.Checked:
                checked_functions.append(item.text())

        for fn in self.bv.functions:
            if fn.name in checked_functions:
                with tempfile.NamedTemporaryFile() as fp:
                    print(fn.name)
                    fp.name = fn.name + '.c'
                    fp.write(bytes(self.c_source(self.bv, fn), 'utf8'))
                    fp.write(b'')
                    task_id = self.dix.create_task(fp)
                    print(f"Created task {task_id}")
        self.bv.undo()
        self.dix.sign_out()

