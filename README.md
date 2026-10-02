<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/banner-dark.png">
  <img src="images/banner.png" alt="Lintel — mind the headers" width="100%">
</picture>

<br>

**Mind the headers.** An offline grader for the security headers of an HTTP
response. Paste what a page sends back and Lintel shows which protections are in
place, which are undercut, and which are missing — and grades them A+ to F,
without ever running a scan or calling a site secure.

<br>

![Python](https://img.shields.io/badge/Python-3.10%2B-7A5D18?style=flat-square)
![PyQt6](https://img.shields.io/badge/UI-PyQt6-7A5D18?style=flat-square)
![Offline](https://img.shields.io/badge/network-never-2C6249?style=flat-square)
![Tests](https://img.shields.io/badge/tests-157%20passing-2C6249?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-847D6E?style=flat-square)

</div>

---

## Why

A handful of response headers decide whether a browser will fall back to plain
HTTP, run injected script, let your page be framed and clickjacked, or hand your
cookies to any script on the page. They are cheap to set and easy to forget, and
whether they are present is a yes/no fact sitting right there in the response —
if you know which ones to look for.

Lintel looks for them. Paste a response — from `curl -I` or your browser's
network panel — and it shows you:

- **A coverage grid** — HSTS, Content-Security-Policy, MIME-sniffing,
  clickjacking, referrer policy, permissions policy and cookie flags, each tile
  green, amber or red, so the shape of a site's protection reads before you've
  read a word.
- **Your cookies and their flags** — `Secure`, `HttpOnly`, `SameSite`, per
  cookie, because one unflagged session cookie undoes a lot.
- **Every finding, in plain words** — what is missing, what is undercut by an
  `unsafe-inline` or a short `max-age`, and what the `Server` header is quietly
  telling an attacker.

Then it grades the headers A+ to F.

<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/screens-dark.png">
  <img src="images/screens.png" alt="A partly-hardened site graded D- beside a fully-hardened one graded A+" width="100%">
</picture>
<br>
<sub>A partly-configured response (D-) beside a fully-hardened one (A+).</sub>
</div>

## The honest part

Lintel grades **only the headers you paste**. It cannot see your TLS
configuration, whether your CSP actually matches your markup, cookies your
JavaScript sets later, or headers a proxy added or stripped between the server
and you. A high grade means the headers are well configured — **not that a site
is secure**, and Lintel never uses that word as a verdict.

- **A+ is reserved** for complete, clean coverage: every core protection in
  place and not one undercut.
- **Thresholds are mainstream**, not personal — the long HSTS `max-age` the
  preload list wants, a CSP without `unsafe-inline`, cookies that are `Secure`
  and `HttpOnly`. The grade tracks accepted practice.

## Install

```bash
git clone https://github.com/at0m-b0mb/Lintel.git
cd Lintel
python3 -m pip install -r requirements.txt   # just PyQt6, for the window
```

The engine and the command line need **no dependencies** — only the standard
library. PyQt6 is required solely for the graphical grader.

## Run

**The window:**

```bash
python3 -m lintel          # or:  python3 run.py
```

Paste a response, open a saved one, or load a sample. Switch between **Light**,
**Dark** and **Auto** from the top-right.

**The command line** — same engine, no Qt, pairs with curl:

```bash
curl -sI https://example.com | lintel -     # grade a live site's headers
lintel response.http                        # a saved response
lintel response.http --json                 # machine-readable
python3 -m lintel response.http             # without installing
```

```
  D-  Several protections are missing  (62/100)
  Lintel grades the response headers you pasted… not that a site is secure.

  Coverage
    weak     HTTPS enforced (HSTS)       max-age is only 30 days
    weak     Content Security Policy     has gaps
    in place MIME sniffing blocked
    missing  Clickjacking blocked
    missing  Referrer leakage limited
    …

  Findings (9)
    [warning] No clickjacking protection
    [warning] CSP allows unsafe inline or eval
    …
```

## What it checks

| Protection | What Lintel wants to see |
|---|---|
| **HSTS** | a long `max-age`, ideally `includeSubDomains; preload` |
| **CSP** | present and enforced, no `unsafe-inline` / `unsafe-eval` / wildcard |
| **MIME sniffing** | `X-Content-Type-Options: nosniff` |
| **Clickjacking** | `X-Frame-Options` or a CSP `frame-ancestors` |
| **Referrer** | a `Referrer-Policy` that doesn't leak the full URL |
| **Permissions** | a `Permissions-Policy` restricting powerful features |
| **Cookies** | `Secure`, `HttpOnly` and a sound `SameSite`, per cookie |
| **Disclosure** | `Server` / `X-Powered-By` version leaks, deprecated headers |

## Privacy

Lintel never touches the network. It parses text you already have with the
standard library, and that is all — a response you paste in never leaves your
machine. (Fetching the headers is curl's job, or your browser's; Lintel only
reads them.)

## Tests

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

157 tests cover the parser (status lines, folding, request blocks, multiple
cookies), every protection check, the full grading pipeline against the sample
set, and a WCAG-AA contrast suite over every text/background pairing in both
themes.

## Layout

```
lintel/
  core/            the engine — pure standard library, no Qt
    model.py         the dataclasses everything speaks in
    parse.py         a pasted response  ->  a header set
    checks.py        the per-protection checks
    grade.py         coverage, findings, and the letter, with the ceiling
  ui/
    theme.py         the design system: one place for every token
    coverage.py      the coverage grid — Lintel's signature element
    widgets.py       cards, chips, key/value rows
    main_window.py   the grader itself
  cli.py           the same engine on the command line
samples/           synthetic responses: hardened, good, moderate, bare
tests/             157 tests, including the contrast suite
tools/             screenshot capture and repository art
```

## Colophon

Set in **Iowan Old Style** for identity, the system **sans** for anything you
read, and a **mono** for the headers. Warm paper and two golds in the light
theme; true black, with nothing that reads as blue, in the dark. Every colour is
a light/dark pair, held to WCAG AA by a test suite so the theme cannot quietly
regress.

## License

MIT — see [LICENSE](LICENSE). A reader, for authorised, educational and personal
use. Every response in `samples/` is synthetic.
