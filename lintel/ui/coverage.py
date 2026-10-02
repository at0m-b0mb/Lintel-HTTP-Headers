"""
The coverage grid — Lintel's signature.

Seven defences, laid out as a dashboard of tiles: each one coloured by whether it
is in place, undercut, or missing, so the shape of a site's protection reads at a
glance before a single finding is read. It is painted rather than listed because
the *pattern* — a wall of green, or a scatter of red — is the thing worth seeing
first.
"""

from __future__ import annotations

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QBrush, QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import QWidget

from . import theme
from ..core.model import Protection, State

_STATE_TOKEN = {
    State.PRESENT: "sev_good",
    State.WEAK: "sev_warning",
    State.ABSENT: "sev_alert",
    State.NA: "sev_info",
}
_STATE_WORD = {
    State.PRESENT: "IN PLACE", State.WEAK: "WEAK",
    State.ABSENT: "MISSING", State.NA: "N/A",
}
_SHORT = {
    "hsts": "HSTS", "csp": "Content Security Policy", "nosniff": "MIME sniffing",
    "clickjack": "Clickjacking", "referrer": "Referrer policy",
    "permissions": "Permissions policy", "cookies": "Cookie flags",
}

_COLS = 2
_TILE_H = 60
_GAP = 10


class CoverageGrid(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._prot: list[Protection] = []
        self._mode = theme.LIGHT
        self.setMinimumHeight(_TILE_H)

    def set_data(self, protections: list[Protection], mode: str) -> None:
        self._prot = protections
        self._mode = mode
        rows = (len(protections) + _COLS - 1) // _COLS
        self.setMinimumHeight(rows * _TILE_H + (rows - 1) * _GAP + 4)
        self.updateGeometry()
        self.update()

    def paintEvent(self, event):  # noqa: N802
        if not self._prot:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        c = lambda n: QColor(theme.color(n, self._mode))  # noqa: E731

        w = self.width()
        tile_w = (w - _GAP * (_COLS - 1)) / _COLS
        for i, prot in enumerate(self._prot):
            row, col = divmod(i, _COLS)
            x = col * (tile_w + _GAP)
            y = row * (_TILE_H + _GAP)
            tok = _STATE_TOKEN[prot.state]
            wash = c(tok + "_wash") if tok + "_wash" in theme.PALETTE else c("surface_alt")
            accent = c(tok)

            rect = QRectF(x, y, tile_w, _TILE_H)
            p.setPen(QPen(c("rule"), 1))
            p.setBrush(QBrush(wash))
            p.drawRoundedRect(rect, 6, 6)
            # accent bar on the left edge
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(accent))
            p.drawRoundedRect(QRectF(x, y, 4, _TILE_H), 2, 2)

            tx = x + 16
            p.setPen(c("ink"))
            p.setFont(self._font("body_bold"))
            p.drawText(QRectF(tx, y + 9, tile_w - 24, 18),
                       Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                       _SHORT.get(prot.key, prot.key))

            p.setPen(accent)
            p.setFont(self._font("label"))
            p.drawText(QRectF(tx, y + 30, tile_w - 24, 14),
                       Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                       _STATE_WORD[prot.state])

            if prot.note:
                p.setPen(c("ink_faint"))
                p.setFont(self._font("mono_small"))
                note = self._elide(prot.note, tile_w - 24, "mono_small")
                p.drawText(QRectF(tx + 70, y + 30, tile_w - 24 - 70, 14),
                           Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                           note)
        p.end()

    def _font(self, role: str) -> QFont:
        family, size, weight = theme.TYPE[role]
        f = QFont()
        f.setFamilies([family.split(",")[0].strip().strip('"')])
        f.setPixelSize(size)
        f.setWeight(QFont.Weight.DemiBold if weight >= 600 else QFont.Weight.Normal)
        return f

    def _elide(self, text: str, width: float, role: str) -> str:
        from PyQt6.QtGui import QFontMetrics
        fm = QFontMetrics(self._font(role))
        return fm.elidedText(text, Qt.TextElideMode.ElideRight, int(width))
