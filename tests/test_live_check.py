"""live_check.py, driven against a local stand-in for urlscan.io.

The script exists to check the things offline tests cannot — real screenshot
sizes, whether `total` comes back — which means nothing in the suite exercises
it, which means it is exactly the kind of file that rots unnoticed and fails on
line 40 the first time someone runs it with a real key.

So: a stand-in serving responses of the right shape, and an assertion that the
script runs all four stages to completion against them. This proves the
plumbing, not urlscan's behaviour; the whole point of the script is that its
behaviour cannot be proven from here.
"""

from __future__ import annotations

import json
import runpy
import struct
import sys
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

LIVE_CHECK = Path(__file__).resolve().parent.parent / "live_check.py"


def _png(width: int, height: int) -> bytes:
    """A valid PNG without a Pillow dependency — Pillow is an optional extra,
    and this test has to run in the configuration that lacks it too."""

    def chunk(tag: bytes, body: bytes) -> bytes:
        return (struct.pack(">I", len(body)) + tag + body
                + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF))

    raw = b"".join(b"\x00" + bytes([(y * 7) % 256, 200, 240] * width)
                   for y in range(height))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6))
            + chunk(b"IEND", b""))


SCREENSHOT = _png(400, 1600)  # taller than MAX_ASPECT_RATIO, so cropping runs
UUID_PREFIX = "0198fb1a-6f0d-7b2c-9c31-2a4f9d0e1c"

RESULT_DOC = {
    "task": {"uuid": f"{UUID_PREFIX}01", "url": "https://example.com/login",
             "time": "2026-08-20T10:00:00.000Z"},
    "page": {"url": "https://cdn-elsewhere.net/x", "domain": "cdn-elsewhere.net",
             "country": "US", "asnname": "CLOUDFLARENET", "title": "Sign in"},
    "verdicts": {"overall": {"score": 0, "malicious": False, "categories": []}},
    "stats": {"uniqIPs": 4, "requests": 61},
    "lists": {"domains": ["cdn-elsewhere.net"], "urls": []},
}


def _hit(index: int, domain: str) -> dict:
    # One in five bounced elsewhere, so the landed/redirected split is exercised.
    landed = domain if index % 5 else "cdn-elsewhere.net"
    return {
        "task": {"uuid": f"{UUID_PREFIX}{index:02d}", "url": f"https://{domain}/login",
                 "time": "2026-08-20T10:00:00.000Z", "domain": domain,
                 "tags": ["phishing"]},
        "page": {"domain": landed, "url": f"https://{landed}/", "ip": "104.21.44.9",
                 "country": "US", "asn": "AS13335", "asnname": "CLOUDFLARENET",
                 "apexDomain": landed},
        "stats": {"uniqIPs": 4, "requests": 61},
    }


class _Handler(BaseHTTPRequestHandler):
    #: uuids the stand-in has no screenshot for, so the multi-candidate walk
    #: has something to walk past.
    missing = {f"{UUID_PREFIX}00", f"{UUID_PREFIX}01"}

    def log_message(self, *args):  # keep pytest output readable
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        path = urlparse(self.path).path
        if path == "/api/v1/search/":
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            domain = "example.com"
            if "domain:" in q:
                domain = q.split("domain:")[1].split(" ")[0].rstrip(")").replace("\\", "")
            payload = {"results": [_hit(i, domain) for i in range(100)],
                       "total": 2417, "has_more": True}
            self._send(200, json.dumps(payload).encode(), "application/json")
        elif path.startswith("/api/v1/result/"):
            if not self.headers.get("API-Key"):
                self._send(401, b'{"message":"key required"}', "application/json")
            else:
                self._send(200, json.dumps(RESULT_DOC).encode(), "application/json")
        elif path.startswith("/screenshots/"):
            uuid = path.rsplit("/", 1)[-1].removesuffix(".png")
            if uuid in self.missing:
                self._send(404, b"missing", "text/plain")
            else:
                self._send(200, SCREENSHOT, "image/png")
        else:
            self._send(404, b'{"message":"not found"}', "application/json")


@pytest.fixture
def stub_urlscan(monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    from urlscan_mcp import client as client_mod
    from urlscan_mcp import screenshots

    monkeypatch.setattr(client_mod, "BASE_URL", base)
    monkeypatch.setattr(screenshots, "SCREENSHOT_URL", base + "/screenshots/{uuid}.png")
    # A proxy in the environment would otherwise be asked to reach loopback.
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("URLSCAN_API_KEY", "stub-key-not-a-real-credential")
    try:
        yield base
    finally:
        server.shutdown()


def _run_live_check(argv_target: str) -> tuple[int, str]:
    sys.argv = ["live_check.py", argv_target]
    try:
        runpy.run_path(str(LIVE_CHECK), run_name="__main__")
    except SystemExit as exc:
        return int(exc.code or 0), ""
    return 0, ""


def test_live_check_runs_all_four_stages(stub_urlscan, monkeypatch, capsys):
    code, _ = _run_live_check("example.com")
    out = capsys.readouterr().out
    assert code == 0, out

    # Stage 1: the redirector query, and the sampling disclosure firing because
    # total (2417) exceeds what one page returns.
    assert "(page.domain:example.com OR task.domain:example.com)" in out
    assert "scans_found=100  total_matching=2417" in out
    assert "sampled=True" in out
    assert "Read the 100 most recent of 2417 matching scans" in out
    # No verdicts in search hits, and the script must not imply otherwise.
    assert "verdicts.available=False" in out
    assert "landed=80  redirected=20" in out

    # Stage 2: the second identical GET is served from cache.
    assert "'hits': 1" in out

    # Stage 3: the first two candidates 404, so this only passes if the walk
    # continues past a scan that never rendered — and it measures every
    # remaining candidate rather than stopping at the first that works.
    assert "no screenshot available" not in out
    assert "captures measured:" in out
    assert "raw bytes:" in out

    # Stage 3b is the reason the script exists: it has to reach a verdict on
    # each threshold rather than print numbers for a human to squint at.
    assert "are the thresholds right?" in out
    assert "MAX_IMAGE_BYTES" in out
    assert "MAX_ASPECT_RATIO" in out
    assert "TARGET_WIDTH" in out

    # Stage 4: the brief ships the domain and the redirect, and refuses to read
    # a missing verdict as clean.
    assert "cdn-elsewhere.net" in out
    assert "this scan redirected" in out
    assert "NOT a clean verdict" in out


def test_live_check_reports_unreachable_rather_than_traceback(monkeypatch, capsys):
    from urlscan_mcp import client as client_mod

    # Port 1 refuses connections everywhere; the point is the failure is
    # reported in the client's own words, not as a stack trace.
    monkeypatch.setattr(client_mod, "BASE_URL", "http://127.0.0.1:1")
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    code, _ = _run_live_check("example.com")
    out = capsys.readouterr().out
    assert code == 1
    assert "FAILED: Could not reach urlscan.io" in out


def test_live_check_rejects_an_unclassifiable_indicator(stub_urlscan, capsys):
    code, _ = _run_live_check("not an indicator")
    assert code == 2
    assert "cannot classify" in capsys.readouterr().out
