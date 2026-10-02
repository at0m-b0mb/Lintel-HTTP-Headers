# Changelog

All notable changes to Lintel are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[semantic versioning](https://semver.org/).

## [1.0.0] — 2026-10-02

First release.

### The grader
- Parses a pasted HTTP response — `curl -I` output, a browser's network-panel
  copy, or a raw response — tolerating a request block, folded headers, and
  multiple `Set-Cookie` lines, and indexing case-insensitively.
- **Coverage grid** — seven protections (HSTS, CSP, MIME-sniffing, clickjacking,
  referrer policy, permissions policy, cookie flags) each resolved to in-place,
  weak, or missing, so the shape of a site's protection reads at a glance.
- **Checks** against mainstream thresholds: HSTS max-age and preload, a CSP
  without `unsafe-inline` or wildcards, `nosniff`, framing restrictions, a sound
  referrer policy, per-cookie `Secure` / `HttpOnly` / `SameSite`, plus version
  disclosure (`Server`, `X-Powered-By`) and deprecated headers (HPKP,
  `X-XSS-Protection`).
- **Grade** — A+ to F, with an honesty ceiling: A+ requires complete, clean
  coverage; the grade reflects only the headers you pasted, not TLS, not actual
  CSP effectiveness, not script-set cookies; and the word "secure" is never a
  verdict.

### Interfaces
- A PyQt6 window in the house style — warm paper and gold, true-black dark mode,
  an Auto theme that follows the OS — with the coverage grid and per-cookie flag
  chips.
- A dependency-free command line sharing the same engine, with text and `--json`
  output, that pipes straight from `curl -sI`.

### Engineering
- The engine (`lintel.core`) is pure standard library — no third-party
  dependencies, no network.
- 159 tests across the parser, every protection check, the full grading pipeline
  against the sample set, and a WCAG-AA contrast suite over both themes.
- Off-screen screenshot capture and a repository-art generator whose social card
  is held inside GitHub's safe border by a registered-rectangle check.
