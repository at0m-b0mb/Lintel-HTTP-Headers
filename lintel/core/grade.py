"""
The judgement — protections and findings first, then a letter.

The grader runs every check, lays out the coverage grid, gathers the findings,
and turns the total into an A+..F letter. Two principles, shared with the rest of
the catalogue:

* **Honesty ceiling.** Lintel sees only the headers you pasted — not your TLS
  setup, not whether a CSP matches your actual markup, not cookies set later by
  script, not what a proxy added or stripped. A high grade means the headers are
  well configured, never that a site is secure, and the word "secure" is never
  used as a verdict.
* **Mainstream thresholds.** Every penalty tracks accepted practice (a long HSTS
  max-age, a CSP without unsafe-inline, Secure/HttpOnly cookies), not one
  person's taste.
"""

from __future__ import annotations

from . import checks
from .model import Finding, Grade, Report, Severity, State

_LETTERS = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"]

_CEILING = (
    "Lintel grades the response headers you pasted. It cannot see your TLS "
    "configuration, whether a CSP matches your markup, cookies set later by "
    "script, or headers a proxy added or stripped. A high grade means the "
    "headers are well configured — not that a site is secure."
)


def _letter_for_score(score: int) -> str:
    bands = [(97, "A+"), (93, "A"), (90, "A-"), (87, "B+"), (83, "B"),
             (80, "B-"), (77, "C+"), (73, "C"), (70, "C-"), (67, "D+"),
             (63, "D"), (60, "D-")]
    for floor, letter in bands:
        if score >= floor:
            return letter
    return "F"


def _cap(letter: str, ceiling: str) -> str:
    return letter if _LETTERS.index(letter) >= _LETTERS.index(ceiling) else ceiling


def grade_report(r: Report) -> Report:
    if not r.headers:
        r.grade = Grade("F", 0, "No response headers to grade", _CEILING)
        return r

    r.cookies = checks.parse_cookies(r)

    protections: list = []
    findings: list[Finding] = []
    for fn in (checks.check_hsts, checks.check_csp, checks.check_nosniff,
               checks.check_clickjacking, checks.check_referrer,
               checks.check_permissions, checks.check_cookies):
        prot, fs = fn(r)
        protections.append(prot)
        findings.extend(fs)
    findings.extend(checks.check_disclosure(r))
    findings.extend(checks.check_deprecated(r))

    score = 100 - sum(f.points for f in findings)
    score = max(0, min(100, score))
    letter = _letter_for_score(score)

    # --- ceiling: A+ only for complete, clean coverage ----------------------
    core = {p.key: p.state for p in protections}
    all_present = all(
        core.get(k) in (State.PRESENT, State.NA)
        for k in ("hsts", "csp", "nosniff", "clickjack", "referrer", "cookies")
    )
    clean = not any(f.severity.rank >= Severity.NOTICE.rank for f in findings)

    if all_present and clean and score >= 97:
        letter = "A+"
        headline = "Every protection Lintel checks is in place"
    else:
        letter = _cap(letter, "A")
        if score >= 90:
            headline = "Well configured, with minor gaps"
        elif score >= 75:
            headline = "Decent, but missing some protections"
        elif score >= 60:
            headline = "Several protections are missing"
        else:
            headline = "Few protections are in place"

    r.protections = protections
    r.findings = sorted(findings, key=lambda f: -f.severity.rank)
    r.grade = Grade(letter, score, headline, _CEILING)
    return r


def analyze(text: str) -> Report:
    """Parse then grade — the whole pipeline in one call."""
    from .parse import parse_response

    return grade_report(parse_response(text))
