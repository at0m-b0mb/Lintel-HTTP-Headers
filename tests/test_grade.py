"""End-to-end: parse plus grade, and the honesty ceiling."""

import os

from lintel.core.grade import analyze
from lintel.core.model import State

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def _sample(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return fh.read()


def _titles(r):
    return {f.title for f in r.findings}


def test_hardened_is_top():
    r = analyze(_sample("hardened.http"))
    assert r.grade.letter == "A+"
    assert all(p.state in (State.PRESENT, State.NA) for p in r.protections)


def test_good_cdn_is_high():
    r = analyze(_sample("good-cdn.http"))
    assert r.grade.letter[0] in ("A", "B")


def test_moderate_is_mid_or_low():
    r = analyze(_sample("moderate.http"))
    assert r.grade.letter[0] in ("C", "D")
    assert "No clickjacking protection" in _titles(r)


def test_default_server_fails():
    r = analyze(_sample("default-server.http"))
    assert r.grade.letter == "F"
    assert "No HSTS header" in _titles(r)
    assert "No Content-Security-Policy" in _titles(r)


def test_never_says_secure():
    for name in ("hardened.http", "good-cdn.http", "moderate.http",
                 "default-server.http"):
        r = analyze(_sample(name))
        assert "is secure" not in r.grade.headline.lower()
        assert "not that a site is secure" in r.grade.ceiling_note


def test_findings_sorted_most_severe_first():
    r = analyze(_sample("default-server.http"))
    ranks = [f.severity.rank for f in r.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_coverage_grid_has_seven():
    r = analyze(_sample("hardened.http"))
    assert len(r.protections) == 7


def test_empty_input_graded_f():
    r = analyze("")
    assert r.grade.letter == "F"
    assert r.notes


def test_a_plus_requires_clean_and_complete():
    # remove one protection from the hardened sample -> no longer A+
    raw = _sample("hardened.http").replace(
        "x-content-type-options: nosniff\n", "")
    r = analyze(raw)
    assert r.grade.letter != "A+"
