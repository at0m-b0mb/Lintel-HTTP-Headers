"""The individual protection checks."""

from lintel.core import checks
from lintel.core.parse import parse_response
from lintel.core.model import State


def _r(headers: str):
    return parse_response("HTTP/2 200\n" + headers)


def test_hsts_present_long():
    prot, f = checks.check_hsts(_r(
        "strict-transport-security: max-age=63072000; includeSubDomains; preload\n"))
    assert prot.state is State.PRESENT
    assert "preload" in prot.note


def test_hsts_absent():
    prot, f = checks.check_hsts(_r("content-type: text/html\n"))
    assert prot.state is State.ABSENT
    assert f[0].points > 0


def test_hsts_short_is_weak():
    prot, f = checks.check_hsts(_r("strict-transport-security: max-age=3600\n"))
    assert prot.state is State.WEAK


def test_hsts_zero_disables():
    prot, f = checks.check_hsts(_r("strict-transport-security: max-age=0\n"))
    assert prot.state is State.WEAK
    assert "disabled" in f[0].title.lower()


def test_csp_unsafe_inline_is_weak():
    prot, f = checks.check_csp(_r(
        "content-security-policy: default-src 'self'; script-src 'unsafe-inline'\n"))
    assert prot.state is State.WEAK
    assert any("unsafe" in x.title.lower() for x in f)


def test_csp_report_only_is_weak():
    prot, f = checks.check_csp(_r(
        "content-security-policy-report-only: default-src 'self'\n"))
    assert prot.state is State.WEAK
    assert "report-only" in f[0].title.lower()


def test_csp_clean_is_present():
    prot, f = checks.check_csp(_r(
        "content-security-policy: default-src 'self'; script-src 'self'\n"))
    assert prot.state is State.PRESENT


def test_nosniff():
    assert checks.check_nosniff(_r("x-content-type-options: nosniff\n"))[0].state is State.PRESENT
    assert checks.check_nosniff(_r("content-type: text/html\n"))[0].state is State.ABSENT


def test_clickjacking_frame_ancestors_counts():
    prot, _ = checks.check_clickjacking(_r(
        "content-security-policy: frame-ancestors 'none'\n"))
    assert prot.state is State.PRESENT


def test_clickjacking_xfo_deny_counts():
    assert checks.check_clickjacking(_r("x-frame-options: DENY\n"))[0].state is State.PRESENT


def test_clickjacking_absent():
    assert checks.check_clickjacking(_r("content-type: text/html\n"))[0].state is State.ABSENT


def test_cookie_flags_parsed():
    r = _r("set-cookie: id=1; Path=/; Secure; HttpOnly; SameSite=Strict\n")
    cookies = checks.parse_cookies(r)
    assert cookies[0].secure and cookies[0].http_only
    assert cookies[0].same_site == "Strict"


def test_cookie_without_flags_flagged():
    r = _r("set-cookie: id=1; Path=/\n")
    r.cookies = checks.parse_cookies(r)
    prot, f = checks.check_cookies(r)
    assert prot.state is State.ABSENT
    assert any("not Secure" in x.title for x in f)


def test_cookie_missing_only_samesite_is_weak():
    r = _r("set-cookie: id=1; Secure; HttpOnly\n")
    r.cookies = checks.parse_cookies(r)
    prot, f = checks.check_cookies(r)
    assert prot.state is State.WEAK


def test_disclosure_server_version():
    f = checks.check_disclosure(_r("server: Apache/2.4.29\nx-powered-by: PHP/7\n"))
    titles = " ".join(x.title for x in f)
    assert "Server version" in titles
    assert "X-Powered-By" in titles


def test_deprecated_hpkp_and_xss():
    f = checks.check_deprecated(_r("x-xss-protection: 1; mode=block\npublic-key-pins: x\n"))
    assert len(f) == 2
