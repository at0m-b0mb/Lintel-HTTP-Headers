"""
The window.

Left: a pasted HTTP response — the output of ``curl -I`` or a block from a
browser's network panel. Right: the reading — a grade, the coverage grid that
shows the shape of the protection at a glance, the cookies and their flags, and
every finding in plain words. The window keeps the current response and
re-renders the right side on a theme change so the painted grid always matches
the palette.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ..core.grade import analyze
from ..core.model import Report, Severity
from . import theme
from .coverage import CoverageGrid
from .widgets import Card, Chip, hrule, key_value, label, mini_label

_SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "samples")

_SEV_TOKEN = {
    Severity.GOOD: "sev_good", Severity.INFO: "sev_info",
    Severity.NOTICE: "sev_notice", Severity.WARNING: "sev_warning",
    Severity.ALERT: "sev_alert",
}


class MainWindow(QWidget):
    def __init__(self, mode: str = theme.AUTO):
        super().__init__()
        self._mode_choice = mode
        self._mode = theme.resolve(mode)
        self._report: Report | None = None
        self.setWindowTitle("Lintel")
        self.resize(1160, 770)
        self._build()
        self._apply_theme()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_header())
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._build_source_pane())
        split.addWidget(self._build_report_pane())
        split.setSizes([450, 710])
        host = QWidget()
        host.setObjectName("PageHost")
        hl = QVBoxLayout(host)
        hl.setContentsMargins(16, 12, 16, 16)
        hl.addWidget(split)
        root.addWidget(host, 1)

    def _build_header(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("Rail")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(20, 12, 20, 12)
        mark = QLabel("LINTEL")
        mark.setObjectName("Wordmark")
        sub = QLabel("mind the headers")
        sub.setObjectName("WordmarkSub")
        wm = QVBoxLayout()
        wm.setSpacing(0)
        wm.addWidget(mark)
        wm.addWidget(sub)
        lay.addLayout(wm)
        lay.addStretch(1)
        lay.addWidget(mini_label("THEME"))
        self.theme_box = QComboBox()
        self.theme_box.addItems(["Auto", "Light", "Dark"])
        self.theme_box.setCurrentText(self._mode_choice.capitalize())
        self.theme_box.setFixedWidth(110)
        self.theme_box.currentTextChanged.connect(self._on_theme_changed)
        lay.addWidget(self.theme_box)
        return bar

    def _build_source_pane(self) -> QWidget:
        pane = QWidget()
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(theme.SPACE["base"])
        lay.addWidget(label("Paste a response", "PageTitle"))
        lay.addWidget(label(
            "The response headers of a page: run “curl -I https://…”, "
            "or copy the Response Headers from your browser's network panel, and "
            "paste them below.", "PageIntro"))
        self.source = QPlainTextEdit()
        self.source.setObjectName("Mono")
        self.source.setPlaceholderText(
            "HTTP/2 200\nstrict-transport-security: max-age=...\n"
            "content-security-policy: ...\nset-cookie: ...")
        lay.addWidget(self.source, 1)
        row = QHBoxLayout()
        b = QPushButton("Inspect")
        b.setObjectName("Primary")
        b.clicked.connect(self._on_analyze)
        row.addWidget(b)
        ob = QPushButton("Open file…")
        ob.clicked.connect(self._on_open)
        row.addWidget(ob)
        self.sample_btn = QPushButton("Load sample")
        self._build_sample_menu()
        row.addWidget(self.sample_btn)
        cb = QPushButton("Clear")
        cb.setObjectName("Quiet")
        cb.clicked.connect(self._on_clear)
        row.addWidget(cb)
        row.addStretch(1)
        lay.addLayout(row)
        return pane

    def _build_sample_menu(self) -> None:
        menu = QMenu(self)
        try:
            names = sorted(f for f in os.listdir(_SAMPLES_DIR) if f.endswith(".http"))
        except OSError:
            names = []
        if not names:
            a = QAction("(no samples found)", self)
            a.setEnabled(False)
            menu.addAction(a)
        for name in names:
            pretty = name[:-5].replace("-", " ").title()
            a = QAction(pretty, self)
            a.triggered.connect(lambda _=False, n=name: self._load_sample(n))
            menu.addAction(a)
        self.sample_btn.setMenu(menu)

    def _build_report_pane(self) -> QWidget:
        self.report_scroll = QScrollArea()
        self.report_scroll.setWidgetResizable(True)
        self._set_placeholder()
        return self.report_scroll

    # --- behaviour ----------------------------------------------------------
    def _on_theme_changed(self, text: str) -> None:
        self._mode_choice = text.lower()
        self._mode = theme.resolve(self._mode_choice)
        self._apply_theme()
        if self._report is not None:
            self._render(self._report)
        else:
            self._set_placeholder()

    def _apply_theme(self) -> None:
        self.setStyleSheet(theme.stylesheet(self._mode))

    def _on_analyze(self) -> None:
        src = self.source.toPlainText()
        if not src.strip():
            self._set_placeholder("Paste a response, or load a sample, to begin.")
            return
        self._report = analyze(src)
        self._render(self._report)

    def _on_open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open a response", "", "Responses (*.http *.txt);;All files (*)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                self.source.setPlainText(fh.read())
        except OSError as exc:
            self._set_placeholder(f"Could not open the file: {exc}")
            return
        self._on_analyze()

    def _load_sample(self, name: str) -> None:
        try:
            with open(os.path.join(_SAMPLES_DIR, name), encoding="utf-8") as fh:
                self.source.setPlainText(fh.read())
        except OSError as exc:
            self._set_placeholder(f"Could not load the sample: {exc}")
            return
        self._on_analyze()

    def _on_clear(self) -> None:
        self.source.clear()
        self._report = None
        self._set_placeholder()

    # --- rendering ----------------------------------------------------------
    def _set_placeholder(self, text: str = "") -> None:
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.addStretch(1)
        lay.addWidget(label("Nothing read yet", "Figure"))
        lay.addWidget(label(
            text or "Lintel reads the security headers of an HTTP response and "
            "shows which protections are in place, which are undercut, and which "
            "are missing. It grades the headers you give it — it is not a "
            "penetration test, and it never calls a site secure.", "PageIntro"))
        lay.addStretch(2)
        self.report_scroll.setWidget(host)

    def _render(self, r: Report) -> None:
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(8, 4, 8, 16)
        lay.setSpacing(theme.SPACE["base"])
        lay.addWidget(self._grade_card(r))
        if r.protections:
            lay.addWidget(self._coverage_card(r))
        if r.cookies:
            lay.addWidget(self._cookies_card(r))
        lay.addWidget(self._findings_card(r))
        if r.notes:
            n = Card("Notes", flat=True)
            for note in r.notes:
                n.add(label(note, muted=True))
            lay.addWidget(n)
        lay.addStretch(1)
        self.report_scroll.setWidget(host)

    def _grade_card(self, r: Report) -> QWidget:
        g = r.grade
        card = Card()
        top = QHBoxLayout()
        letter = QLabel(g.letter)
        letter.setStyleSheet(
            f"{theme.font_css('grade')} color: "
            f"{theme.color(theme.grade_token(g.letter), self._mode)};")
        top.addWidget(letter)
        col = QVBoxLayout()
        col.setSpacing(2)
        status = f"  ·  {r.status_line}" if r.status_line else ""
        col.addWidget(mini_label(f"HEADER GRADE  ·  SCORE {g.score}/100{status.upper()}"))
        col.addWidget(label(g.headline, "PageTitle"))
        col.addStretch(1)
        top.addLayout(col, 1)
        card.add_layout(top)
        card.add(hrule())
        card.add(label(g.ceiling_note, "Faint"))
        return card

    def _coverage_card(self, r: Report) -> QWidget:
        card = Card("Protection coverage")
        grid = CoverageGrid()
        grid.set_data(r.protections, self._mode)
        card.add(grid)
        return card

    def _cookies_card(self, r: Report) -> QWidget:
        card = Card(f"Cookies ({len(r.cookies)})")
        for i, ck in enumerate(r.cookies):
            if i:
                card.add(hrule())
            row = QHBoxLayout()
            row.setSpacing(theme.SPACE["snug"])
            name = label(ck.name, "body_bold")
            name.setFixedWidth(150)
            row.addWidget(name, 0, Qt.AlignmentFlag.AlignVCenter)
            row.addWidget(Chip("Secure", "sev_good" if ck.secure else "sev_alert", self._mode))
            row.addWidget(Chip("HttpOnly", "sev_good" if ck.http_only else "sev_alert", self._mode))
            ss_ok = ck.same_site and not (ck.same_site == "None" and not ck.secure)
            ss_text = f"SameSite={ck.same_site}" if ck.same_site else "no SameSite"
            row.addWidget(Chip(ss_text, "sev_good" if ss_ok else "sev_warning", self._mode))
            row.addStretch(1)
            w = QWidget()
            w.setLayout(row)
            card.add(w)
        return card

    def _findings_card(self, r: Report) -> QWidget:
        card = Card(f"Findings ({len(r.findings)})")
        if not r.findings:
            card.add(label("No findings.", muted=True))
            return card
        for i, f in enumerate(r.findings):
            if i:
                card.add(hrule())
            row = QHBoxLayout()
            row.setSpacing(theme.SPACE["base"])
            chip = Chip(f.severity.value, _SEV_TOKEN[f.severity], self._mode)
            chip.setFixedWidth(84)
            row.addWidget(chip, 0, Qt.AlignmentFlag.AlignTop)
            col = QVBoxLayout()
            col.setSpacing(2)
            head = QHBoxLayout()
            head.addWidget(label(f.title, "body"))
            head.addStretch(1)
            if f.points:
                head.addWidget(label(f"−{f.points}", "Faint"))
            col.addLayout(head)
            col.addWidget(label(f.detail, muted=True))
            row.addLayout(col, 1)
            card.add_layout(row)
        return card
