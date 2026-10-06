#!/usr/bin/env python3
"""Sentinel CAC Manager - Graphical Setup Wizard Launcher.
Run directly or double-click to launch the native Linux setup wizard.
"""

import os
import sys

# Ensure project root is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from ui.installer_window import run_installer_gui


if __name__ == "__main__":
    sys.exit(run_installer_gui() or 0)
