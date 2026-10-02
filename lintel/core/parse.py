"""
From a pasted response to a :class:`Report`.

The input is whatever a person can get hold of: the output of ``curl -I``, a
block copied from a browser's network panel, or a raw response typed by hand. So
the parser is forgiving. It finds the status line if there is one, skips a
request block if the paste happens to include one, folds continuation lines,
keeps every ``Set-Cookie`` separately, and preserves the original header casing
for display while indexing case-insensitively for lookup. It does not judge
anything — that is :mod:`lintel.core.checks` and :mod:`lintel.core.grade`.
"""

from __future__ import annotations

import re

from .model import Report

_STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", re.IGNORECASE)
_REQUEST_LINE_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+\S+\s+HTTP/",
    re.IGNORECASE,
)


def parse_response(text: str) -> Report:
    report = Report()
    lines = (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")

    # Find the response status line. If the paste includes a request first,
    # there may be an earlier "GET ... HTTP/1.1" line; skip past it.
    start = 0
    for i, line in enumerate(lines):
        if _STATUS_RE.match(line.strip()):
            m = _STATUS_RE.match(line.strip())
            report.status_line = line.strip()
            report.status_code = int(m.group(1))
            start = i + 1
            break
    else:
        # no status line: start at the first header-looking line, skipping any
        # request line and leading blanks
        for i, line in enumerate(lines):
            if _REQUEST_LINE_RE.match(line.strip()):
                continue
            if ":" in line and not line.startswith((" ", "\t")):
                start = i
                break

    last_name: str | None = None
    for raw in lines[start:]:
        if raw.strip() == "":
            # a blank line ends the header block (anything after is the body)
            if report.headers:
                break
            continue
        if raw[:1] in (" ", "\t") and last_name is not None:
            # folded continuation of the previous header
            report.headers[last_name][-1] += " " + raw.strip()
            continue
        if ":" not in raw:
            continue
        name, _, value = raw.partition(":")
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        low = name.lower()
        report.headers.setdefault(low, []).append(value)
        report.header_order.append(name)
        last_name = low

    # scheme hint: a secure URL anywhere in the paste suggests HTTPS
    if "https://" in (text or "").lower():
        report.scheme_https = True

    if not report.headers:
        report.notes.append(
            "No response headers were found. Paste the headers from `curl -I`, "
            "or your browser's network panel.")
    return report
