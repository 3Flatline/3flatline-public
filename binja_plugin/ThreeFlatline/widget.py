from typing import Optional

from binaryninja import BinaryView
from binaryninjaui import DockContextHandler
import binaryninjaui

if "qt_major_version" in dir(binaryninjaui) and binaryninjaui.qt_major_version == 6:
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import (
        QWidget,
        QTabWidget,
        QVBoxLayout,
        QLabel,
        QScrollArea,
    )
else:
    from PySide2.QtCore import QTimer
    from PySide2.QtWidgets import (
        QWidget,
        QTabWidget,
        QVBoxLayout,
        QScrollArea,
    )

from .api import DixieAPI
from .viewer import DixieMarkdownViewer
from .settings import AnalysisSettings
from .manage import ManageTasks
from .local_viewer import DixieLocalMarkdownViewer


class DixieScannerDockWidget(QWidget, DockContextHandler):

    # Tab container
    tab_container: QTabWidget

    # Viewer/content widget
    viewer: DixieMarkdownViewer

    # Settings widget
    dix_settings: AnalysisSettings

    # Task management widget
    task_manager: ManageTasks

    # Locally Stored Results Viewer
    local_viewer: DixieLocalMarkdownViewer

    # The currently focused BinaryView.
    bv: Optional[BinaryView] = None

    dix: Optional[DixieAPI] = None

    def __init__(self, parent: QWidget, name: str, bv: Optional[BinaryView]):
        """
        Initialize a new DixieScannerDockWidget.

        :param parent: the QWidget to parent this NotepadDockWidget to
        :param name: the name to register the dock widget under
        :param bv: the currently focused BinaryView (may be None)
        """
        self.bv = bv

        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.dix = DixieAPI()

        # Create the viewer

        self.dix_settings = AnalysisSettings(self, self.dix, self.bv)
        self.viewer = DixieMarkdownViewer(self, self.dix)
        # self.dix_settings.setWidget(AnalysisSettings(self, self.dix, self.bv))
        self.task_manager = ManageTasks(self, self.dix, self.bv)
        self.local_viewer = DixieLocalMarkdownViewer(self, self.dix, self.bv)
        # self.viewer.setWidget(DixieMarkdownViewer(self, self.dix))
        # Add both widgets to a tab container
        self.tab_container = QTabWidget()
        self.tab_container.addTab(self.dix_settings, "Analysis Settings")
        self.tab_container.addTab(self.local_viewer, "Local Function Results")
        self.tab_container.addTab(self.viewer, "View Results")
        self.tab_container.addTab(self.task_manager, "Manage Tasks")

        # Create a simple layout for the editor and set it as the root layout.
        layout = QVBoxLayout()
        layout.addWidget(self.tab_container)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)
