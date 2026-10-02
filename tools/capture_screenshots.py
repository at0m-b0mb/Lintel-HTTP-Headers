#!/usr/bin/env python3
"""Render the window off-screen and save PNGs — proof, and the README sheet."""

from __future__ import annotations

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from PyQt6.QtWidgets import QApplication  # noqa: E402

from lintel.ui import theme  # noqa: E402
from lintel.ui.main_window import MainWindow  # noqa: E402

SIZE = (1200, 860)
SHOTS = [
    ("moderate.http", theme.LIGHT),
    ("moderate.http", theme.DARK),
    ("hardened.http", theme.LIGHT),
    ("hardened.http", theme.DARK),
    ("default-server.http", theme.LIGHT),
]


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    out = os.path.join(ROOT, "images")
    os.makedirs(out, exist_ok=True)
    samples = os.path.join(ROOT, "samples")
    for name, mode in SHOTS:
        win = MainWindow(mode=mode)
        win.resize(*SIZE)
        with open(os.path.join(samples, name), encoding="utf-8") as fh:
            win.source.setPlainText(fh.read())
        win._on_analyze()
        win.show()
        app.processEvents()
        app.processEvents()
        path = os.path.join(out, f"shot-{name[:-5]}-{mode}.png")
        win.grab().save(path)
        print(f"wrote {os.path.relpath(path, ROOT)}")
        win.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
