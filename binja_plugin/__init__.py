#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pdb import run
import sys
import os
import re
import binaryninjaui
from binaryninja import core_ui_enabled
import tempfile
import subprocess
import time
from binaryninjaui import (getMonospaceFont, UIAction, UIActionHandler, Menu, DockHandler, UIContext, DockContextHandler)
if "qt_major_version" in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
    from PySide6.QtWidgets import (QLineEdit, QPushButton, QApplication, QTextEdit, QWidget,
         QVBoxLayout, QHBoxLayout, QDialog, QFileSystemModel, QTreeView, QLabel, QSplitter,
         QInputDialog, QMessageBox, QHeaderView, QMenu, QKeySequenceEdit, QWidget,
         QPlainTextEdit)
    from PySide6.QtCore import (QDir, QObject, Qt, QFileInfo, QItemSelectionModel, QSettings, QUrl)
    from PySide6.QtGui import (QAction, QFont, QFontMetrics, QDesktopServices, QKeySequence, QIcon)
from binaryninja.plugin import PluginCommand, BackgroundTaskThread
from binaryninja.log import (log_error, log_info, log_debug)
from binaryninja.settings import Settings
from binaryninja.interaction import *
from binaryninja import DisassemblySettings, lineardisassembly, DisassemblyOption
from .ThreeFlatline import DixieAPI
from .ThreeFlatline import docking
from .ThreeFlatline.widget import DixieScannerDockWidget
# from .QCodeEditor import QCodeEditor, Pylighter

Settings().register_group("dixie", "Dixie Vuln Scanner")
Settings().register_setting("dixie.password", """
    {
        "title" : "Password",
        "type" : "string",
        "default" : "",
        "description" : "The password used to login to the 3Flatline Dixie API",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """)
Settings().register_setting("dixie.username", """
    {
        "title" : "Username",
        "type" : "string",
        "default" : "",
        "description" : "The username used to login to the 3Flatline Dixie API",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """)

# PluginCommand.register("Dixie", "Query Binary Using Dixie Vuln Scanner", launchDixie)
if core_ui_enabled():
    docking.register_widget(
        DixieScannerDockWidget, "Dixie Vuln Scanner", Qt.RightDockWidgetArea, Qt.Vertical, False
    )