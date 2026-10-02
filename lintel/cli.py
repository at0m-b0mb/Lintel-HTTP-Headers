"""
Lintel on the command line.

The same engine the window uses, with no Qt — so it drops into a pipe or a
script. Point it at a saved response, or pipe one in; add ``--json`` for machine
output. Pairs naturally with curl:

    curl -sI https://example.com | lintel -
    lintel response.http
    lintel response.http --json
"""

from __future__ import annotations

import argparse
import json
import sys

from .core.grade import analyze
from .core.model import Report, State

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "good": "\033[32m", "notice": "\033[33m", "warning": "\033[33m",
    "alert": "\033[31m", "info": "\033[90m",
    "present": "\033[32m", "weak": "\033[33m", "absent": "\033[31m", "na": "\033[90m",
}


def _paint(text, key, color):
    return f"{_C.get(key,'')}{text}{_C['reset']}" if color else text


def _report_text(r: Report, color: bool) -> str:
    g = r.grade
    out = [
        _paint(f"  {g.letter}  ", "bold", color) + f" {g.headline}  "
        + _paint(f"({g.score}/100)", "dim", color),
        _paint(g.ceiling_note, "dim", color),
        "",
    ]
    if r.protections:
        out.append("Coverage")
        for p in r.protections:
            word = {State.PRESENT: "in place", State.WEAK: "weak",
                    State.ABSENT: "missing", State.NA: "n/a"}[p.state]
            note = f"  {p.note}" if p.note else ""
            out.append(f"  {_paint(f'{word:<8}', p.state.value, color)} "
                       f"{p.label}{_paint(note, 'dim', color)}")
        out.append("")
    if r.cookies:
        out.append(f"Cookies ({len(r.cookies)})")
        for ck in r.cookies:
            flags = []
            flags.append(_paint("Secure", "good" if ck.secure else "alert", color))
            flags.append(_paint("HttpOnly", "good" if ck.http_only else "alert", color))
            ss = f"SameSite={ck.same_site}" if ck.same_site else "no-SameSite"
            flags.append(_paint(ss, "good" if ck.same_site else "warning", color))
            out.append(f"  {ck.name:<16} {'  '.join(flags)}")
        out.append("")
    out.append(f"Findings ({len(r.findings)})")
    for f in r.findings:
        tag = _paint(f"[{f.severity.value:^7}]", f.severity.value, color)
        pts = _paint(f" -{f.points}", "dim", color) if f.points else ""
        out.append(f"  {tag} {f.title}{pts}")
        out.append(_paint(f"          {f.detail}", "dim", color))
    for n in r.notes:
        out.append(_paint(f"  note: {n}", "dim", color))
    return "\n".join(out)


def _report_json(r: Report) -> str:
    data = {
        "grade": {"letter": r.grade.letter, "score": r.grade.score,
                  "headline": r.grade.headline, "ceiling_note": r.grade.ceiling_note},
        "status_line": r.status_line,
        "status_code": r.status_code,
        "coverage": [{"key": p.key, "label": p.label, "state": p.state.value,
                      "note": p.note} for p in r.protections],
        "cookies": [{"name": c.name, "secure": c.secure, "http_only": c.http_only,
                     "same_site": c.same_site} for c in r.cookies],
        "findings": [{"severity": f.severity.value, "title": f.title,
                      "detail": f.detail, "points": f.points, "category": f.category}
                     for f in r.findings],
        "notes": r.notes,
    }
    return json.dumps(data, indent=2)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="lintel", description="Grade the security headers of an HTTP response.")
    ap.add_argument("source", nargs="?", default="-",
                    help="path to a saved response, or - for standard input")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-color", action="store_true", help="plain text")
    args = ap.parse_args(argv)

    if args.source == "-":
        raw = sys.stdin.read()
    else:
        try:
            with open(args.source, encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError as exc:
            print(f"lintel: cannot read {args.source}: {exc}", file=sys.stderr)
            return 2
    if not raw.strip():
        print("lintel: no response given", file=sys.stderr)
        return 2

    r = analyze(raw)
    if args.json:
        print(_report_json(r))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print(_report_text(r, color))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
