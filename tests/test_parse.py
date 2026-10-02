"""Parsing a pasted HTTP response."""

from lintel.core.parse import parse_response


def test_status_line_and_headers():
    r = parse_response(
        "HTTP/1.1 200 OK\nServer: nginx\nContent-Type: text/html\n")
    assert r.status_code == 200
    assert r.get("server") == "nginx"
    assert r.get("Content-Type") == "text/html"


def test_case_insensitive_lookup():
    r = parse_response("HTTP/2 200\nSTRICT-Transport-Security: max-age=1\n")
    assert r.has("strict-transport-security")
    assert r.get("Strict-Transport-Security") == "max-age=1"


def test_multiple_set_cookie_preserved():
    r = parse_response("HTTP/1.1 200 OK\nSet-Cookie: a=1\nSet-Cookie: b=2\n")
    assert r.get_all("set-cookie") == ["a=1", "b=2"]


def test_folded_header_joined():
    r = parse_response("HTTP/1.1 200 OK\nX-Long: part-one\n   part-two\n")
    assert r.get("x-long") == "part-one part-two"


def test_no_status_line_still_parses():
    r = parse_response("content-type: text/html\nx-frame-options: DENY\n")
    assert r.status_code is None
    assert r.get("x-frame-options") == "DENY"


def test_request_block_skipped():
    raw = ("GET /index.html HTTP/1.1\nHost: example.com\n\n"
           "HTTP/1.1 200 OK\nServer: nginx\n")
    r = parse_response(raw)
    assert r.status_code == 200
    assert r.get("server") == "nginx"
    # the request's Host header should not leak into the response
    assert not r.has("host")


def test_body_after_blank_line_ignored():
    raw = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>Server: fake</html>\n"
    r = parse_response(raw)
    assert r.get("content-type") == "text/html"
    assert not r.has("server")


def test_https_scheme_inferred():
    r = parse_response("HTTP/2 200\nLocation: https://example.com/next\n")
    assert r.scheme_https is True


def test_empty_input_notes():
    r = parse_response("")
    assert not r.headers
    assert r.notes
