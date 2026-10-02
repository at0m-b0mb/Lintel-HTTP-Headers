"""
The protection checks.

Each function reads the parsed headers and answers one question: is this defence
in place, undercut, or missing? It returns a :class:`Protection` for the coverage
grid and any findings for the report. The thresholds are deliberately mainstream
— the long HSTS max-age the preload list wants, a CSP without ``unsafe-inline``,
cookies that are ``Secure`` and ``HttpOnly`` — so the grade reflects accepted
practice rather than one person's preference.
"""

from __future__ import annotations

import re

from .model import Cookie, Finding, Protection, Report, Severity, State

_HSTS_MIN = 15552000  # 180 days, the floor the preload list expects


def _f(sev, title, detail, pts=0, cat="general"):
    return Finding(sev, title, detail, pts, cat)


def check_hsts(r: Report) -> tuple[Protection, list[Finding]]:
    v = r.get("Strict-Transport-Security")
    if not v:
        return (Protection("hsts", "HTTPS enforced (HSTS)", State.ABSENT),
                [_f(Severity.WARNING, "No HSTS header",
                    "Without Strict-Transport-Security a browser can be talked "
                    "back down to plain HTTP on the next visit, where traffic is "
                    "open to tampering.", 14, "hsts")])
    m = re.search(r"max-age\s*=\s*(\d+)", v, re.IGNORECASE)
    max_age = int(m.group(1)) if m else 0
    sub = "includesubdomains" in v.lower()
    preload = "preload" in v.lower()
    if max_age == 0:
        return (Protection("hsts", "HTTPS enforced (HSTS)", State.WEAK,
                           "max-age=0 switches HSTS off"),
                [_f(Severity.WARNING, "HSTS is disabled (max-age=0)",
                    "An HSTS header with max-age=0 tells the browser to forget "
                    "the policy — the same as having none.", 12, "hsts")])
    if max_age < _HSTS_MIN:
        days = max_age // 86400
        return (Protection("hsts", "HTTPS enforced (HSTS)", State.WEAK,
                           f"max-age is only {days} days"),
                [_f(Severity.NOTICE, "HSTS max-age is short",
                    f"max-age is {days} days; the preload list expects at least "
                    f"180. A short window leaves a gap after it lapses.", 5, "hsts")])
    extra = "" if sub else " It does not cover subdomains (includeSubDomains)."
    note = "preloaded" if preload else ("covers subdomains" if sub else "")
    return (Protection("hsts", "HTTPS enforced (HSTS)", State.PRESENT, note),
            [_f(Severity.GOOD, "HSTS in force",
                f"Strict-Transport-Security pins HTTPS for {max_age // 86400} "
                f"days.{extra}", 0, "hsts")])


def check_csp(r: Report) -> tuple[Protection, list[Finding]]:
    enforced = r.get("Content-Security-Policy")
    reportonly = r.get("Content-Security-Policy-Report-Only")
    if not enforced and not reportonly:
        return (Protection("csp", "Content Security Policy", State.ABSENT),
                [_f(Severity.WARNING, "No Content-Security-Policy",
                    "Without a CSP the browser will run any script the page "
                    "contains, which is the main line of defence against "
                    "cross-site scripting.", 16, "csp")])
    if not enforced and reportonly:
        return (Protection("csp", "Content Security Policy", State.WEAK,
                           "report-only, not enforced"),
                [_f(Severity.NOTICE, "CSP is report-only",
                    "A report-only policy logs violations but blocks nothing. It "
                    "is a staging step, not a protection.", 8, "csp")])
    v = enforced
    low = v.lower()
    findings = []
    weak = False
    if "'unsafe-inline'" in low or "'unsafe-eval'" in low:
        weak = True
        findings.append(_f(Severity.WARNING, "CSP allows unsafe inline or eval",
            "The policy permits 'unsafe-inline' or 'unsafe-eval', which lets much "
            "of the injected script a CSP is meant to stop run anyway.", 8, "csp"))
    if re.search(r"(default-src|script-src)\s+[^;]*\*", low):
        weak = True
        findings.append(_f(Severity.NOTICE, "CSP has a wildcard source",
            "A * source in default-src or script-src allows scripts from "
            "anywhere, loosening the policy considerably.", 5, "csp"))
    if "default-src" not in low and "script-src" not in low:
        findings.append(_f(Severity.NOTICE, "CSP sets no script baseline",
            "The policy names neither default-src nor script-src, so script "
            "loading is not actually constrained.", 5, "csp"))
        weak = True
    if not findings:
        return (Protection("csp", "Content Security Policy", State.PRESENT,
                           "enforced"),
                [_f(Severity.GOOD, "Content-Security-Policy enforced",
                    "An enforced CSP constrains where scripts and other content "
                    "may come from.", 0, "csp")])
    state = State.WEAK if weak else State.PRESENT
    return (Protection("csp", "Content Security Policy", state, "has gaps"), findings)


def check_nosniff(r: Report) -> tuple[Protection, list[Finding]]:
    v = r.get("X-Content-Type-Options")
    if v and v.strip().lower() == "nosniff":
        return (Protection("nosniff", "MIME sniffing blocked", State.PRESENT),
                [_f(Severity.GOOD, "X-Content-Type-Options: nosniff",
                    "The browser is told to trust declared content types rather "
                    "than guessing, closing a class of content-type tricks.",
                    0, "nosniff")])
    return (Protection("nosniff", "MIME sniffing blocked", State.ABSENT),
            [_f(Severity.NOTICE, "No X-Content-Type-Options: nosniff",
                "Without nosniff a browser may second-guess a response's content "
                "type and treat, say, an upload as a script.", 6, "nosniff")])


def check_clickjacking(r: Report) -> tuple[Protection, list[Finding]]:
    xfo = r.get("X-Frame-Options")
    csp = (r.get("Content-Security-Policy") or "").lower()
    frame_ancestors = "frame-ancestors" in csp
    if frame_ancestors or (xfo and xfo.strip().lower() in ("deny", "sameorigin")):
        return (Protection("clickjack", "Clickjacking blocked", State.PRESENT),
                [_f(Severity.GOOD, "Framing is restricted",
                    "X-Frame-Options or a CSP frame-ancestors directive stops the "
                    "page being framed by an attacker's site.", 0, "clickjack")])
    if xfo:
        return (Protection("clickjack", "Clickjacking blocked", State.WEAK,
                           f"X-Frame-Options: {xfo}"),
                [_f(Severity.NOTICE, "Weak X-Frame-Options value",
                    f"X-Frame-Options is \"{xfo}\" — ALLOW-FROM is deprecated and "
                    f"widely ignored. Prefer CSP frame-ancestors.", 5, "clickjack")])
    return (Protection("clickjack", "Clickjacking blocked", State.ABSENT),
            [_f(Severity.WARNING, "No clickjacking protection",
                "Neither X-Frame-Options nor a CSP frame-ancestors directive is "
                "present, so the page can be framed and overlaid to trick a "
                "click.", 12, "clickjack")])


def check_referrer(r: Report) -> tuple[Protection, list[Finding]]:
    v = r.get("Referrer-Policy")
    if not v:
        return (Protection("referrer", "Referrer leakage limited", State.ABSENT),
                [_f(Severity.NOTICE, "No Referrer-Policy",
                    "Without a policy the browser's default may send the full URL "
                    "of your page to other sites it links to.", 4, "referrer")])
    weak = v.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade", "")
    if weak:
        return (Protection("referrer", "Referrer leakage limited", State.WEAK,
                           v),
                [_f(Severity.NOTICE, "Loose Referrer-Policy",
                    f"\"{v}\" still sends the full referring URL in common cases.",
                    3, "referrer")])
    return (Protection("referrer", "Referrer leakage limited", State.PRESENT, v),
            [_f(Severity.GOOD, "Referrer-Policy set", f"Referrer-Policy is "
                f"\"{v}\".", 0, "referrer")])


def check_permissions(r: Report) -> tuple[Protection, list[Finding]]:
    if r.has("Permissions-Policy") or r.has("Feature-Policy"):
        return (Protection("permissions", "Feature access limited", State.PRESENT),
                [_f(Severity.GOOD, "Permissions-Policy set",
                    "The response limits which browser features (camera, "
                    "geolocation, and so on) the page may use.", 0, "permissions")])
    return (Protection("permissions", "Feature access limited", State.ABSENT),
            [_f(Severity.NOTICE, "No Permissions-Policy",
                "Powerful browser features are left at their defaults rather than "
                "being explicitly restricted.", 3, "permissions")])


def parse_cookies(r: Report) -> list[Cookie]:
    cookies = []
    for raw in r.get_all("Set-Cookie"):
        name = raw.split("=", 1)[0].strip() if "=" in raw else raw.strip()
        low = raw.lower()
        ss = ""
        m = re.search(r"samesite\s*=\s*(strict|lax|none)", low)
        if m:
            ss = m.group(1).capitalize()
        cookies.append(Cookie(
            name=name,
            secure="secure" in re.split(r";\s*", low),
            http_only="httponly" in re.split(r";\s*", low),
            same_site=ss,
            raw=raw,
        ))
    return cookies


def check_cookies(r: Report) -> tuple[Protection, list[Finding]]:
    cookies = r.cookies
    if not cookies:
        return (Protection("cookies", "Cookie safety", State.NA,
                           "no cookies set"), [])
    findings = []
    penalty = 0
    bad = 0
    for ck in cookies:
        issues = []
        if not ck.secure:
            issues.append("not Secure")
        if not ck.http_only:
            issues.append("not HttpOnly")
        if not ck.same_site:
            issues.append("no SameSite")
        elif ck.same_site == "None" and not ck.secure:
            issues.append("SameSite=None without Secure")
        if issues:
            bad += 1
            sev = Severity.WARNING if ("not Secure" in issues or
                                       "not HttpOnly" in issues) else Severity.NOTICE
            penalty += 6 if sev is Severity.WARNING else 3
            findings.append(_f(sev, f"Cookie “{ck.name}”: {', '.join(issues)}",
                "A cookie without these flags can be read by scripts, sent over "
                "plain HTTP, or attached to cross-site requests.",
                0, "cookies"))
    penalty = min(penalty, 20)
    if penalty:
        findings.append(_f(Severity.INFO, "Cookie flags cost (capped)",
            f"{bad} of {len(cookies)} cookies are missing protective flags.",
            penalty, "cookies"))
    unprotected = sum(1 for ck in cookies if not ck.secure and not ck.http_only)
    if bad == 0:
        state = State.PRESENT
    elif unprotected == len(cookies):
        # every cookie lacks both Secure and HttpOnly — essentially open
        state = State.ABSENT
    else:
        state = State.WEAK
    return (Protection("cookies", "Cookie safety", state,
                       f"{len(cookies) - bad}/{len(cookies)} flagged"), findings)


def check_disclosure(r: Report) -> list[Finding]:
    out = []
    server = r.get("Server")
    if server and re.search(r"\d+\.\d+", server):
        out.append(_f(Severity.NOTICE, "Server version disclosed",
            f"The Server header reveals \"{server}\", handing an attacker the "
            f"exact software and version to look up.", 3, "disclosure"))
    xpb = r.get("X-Powered-By")
    if xpb:
        out.append(_f(Severity.NOTICE, "X-Powered-By discloses the stack",
            f"\"{xpb}\" advertises the server technology; remove it.", 4, "disclosure"))
    for h in ("X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        if r.has(h):
            out.append(_f(Severity.NOTICE, f"{h} disclosed",
                f"{h} leaks the framework version.", 3, "disclosure"))
    return out


def check_deprecated(r: Report) -> list[Finding]:
    out = []
    xxss = r.get("X-XSS-Protection")
    if xxss and xxss.strip().startswith("1"):
        out.append(_f(Severity.NOTICE, "Legacy X-XSS-Protection enabled",
            "The browser XSS auditor this enables is deprecated and has itself "
            "caused vulnerabilities. Rely on CSP instead; set it to 0.",
            2, "deprecated"))
    if r.has("Public-Key-Pins"):
        out.append(_f(Severity.NOTICE, "Public-Key-Pins is deprecated",
            "HPKP is removed from browsers and can lock users out if mis-set. "
            "Remove it.", 4, "deprecated"))
    return out
