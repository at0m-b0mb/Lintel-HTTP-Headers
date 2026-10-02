"""
The shapes the analysis produces.

Lintel reads the response headers of an HTTP reply and reports on the protections
they carry. These dataclasses are the result: the parsed header set, each
security protection resolved to a state for the coverage grid, each cookie with
its flags, and the findings and grade built on top. Nothing here parses or
judges — these are the nouns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    GOOD = "good"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ALERT = "alert"

    @property
    def rank(self) -> int:
        return {
            Severity.GOOD: 0, Severity.INFO: 1, Severity.NOTICE: 2,
            Severity.WARNING: 3, Severity.ALERT: 4,
        }[self]


class State(Enum):
    """How well one protection is covered — the cell colour on the grid."""

    PRESENT = "present"   # in place and sound
    WEAK = "weak"         # present but undercut
    ABSENT = "absent"     # not there at all
    NA = "na"             # not applicable to this response


@dataclass
class Protection:
    """One named defence and how well this response provides it."""

    key: str
    label: str
    state: State
    note: str = ""


@dataclass
class Cookie:
    name: str
    secure: bool = False
    http_only: bool = False
    same_site: str = ""   # "", "Strict", "Lax", "None"
    raw: str = ""


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str
    points: int = 0
    category: str = "general"


@dataclass
class Grade:
    letter: str
    score: int
    headline: str
    ceiling_note: str


@dataclass
class Report:
    status_line: str = ""
    status_code: Optional[int] = None
    scheme_https: Optional[bool] = None   # inferred from the request URL if given

    headers: dict[str, list[str]] = field(default_factory=dict)  # lower-name -> values
    header_order: list[str] = field(default_factory=list)        # as seen, original case

    protections: list[Protection] = field(default_factory=list)
    cookies: list[Cookie] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    grade: Optional[Grade] = None
    notes: list[str] = field(default_factory=list)

    def get(self, name: str) -> Optional[str]:
        """First value of a header, case-insensitive, or None."""
        vals = self.headers.get(name.lower())
        return vals[0] if vals else None

    def get_all(self, name: str) -> list[str]:
        return self.headers.get(name.lower(), [])

    def has(self, name: str) -> bool:
        return name.lower() in self.headers
