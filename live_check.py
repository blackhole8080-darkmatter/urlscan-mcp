#!/usr/bin/env python3
"""Live check against the real urlscan.io API — the things offline tests cannot prove.

    export URLSCAN_API_KEY=...        # optional; only submissions need it
    python live_check.py [URL-or-domain]

Everything in the test suite drives synthetic data, because the sandbox this was
built in blocks urlscan.io at the network policy. What that leaves unverified is
not the logic but the *shapes*: how big a real screenshot is, whether the
1024px/2.5-aspect thresholds are sensible against real captures, and whether
`total` really comes back on a busy indicator so the sampling note fires.
"""
from __future__ import annotations

import asyncio
import os
import sys

from urlscan_mcp import assess, query, screenshots
from urlscan_mcp.client import ImageTooLarge, ScanPending, UrlscanClient, UrlscanError
from urlscan_mcp.shaping import summarize_result, summarize_search_hit

TARGET = sys.argv[1] if len(sys.argv) > 1 else "github.com"


def head(title: str) -> None:
    print(f"\n{'─' * 68}\n{title}\n{'─' * 68}")


async def main() -> int:
    client = UrlscanClient()
    print(f"key configured: {client.authenticated}")
    print(f"capabilities:   {client.capabilities()}")

    # 1. Search — no key required. Proves reachability and the redirector query.
    head(f"1. search + assess: {TARGET}")
    classified = query.classify(TARGET)
    if classified is None:
        print(f"cannot classify {TARGET!r}")
        return 2
    kind, base = classified
    q = base + (query.time_filter(180) if kind != "hash" else "")
    print(f"kind={kind}\nquery={q}")

    try:
        raw = await client.request(
            "GET", "/api/v1/search/", action="Searching", params={"q": q, "size": 100}
        )
    except UrlscanError as exc:
        print(f"FAILED: {exc}")
        return 1

    hits = [summarize_search_hit(h) for h in (raw.get("results") or [])]
    report = assess.build_assessment(TARGET, kind, hits, days=180, total_matching=raw.get("total"))
    print(f"scans_found={report['scans_found']}  total_matching={report['total_matching']}")
    print(f"sampled={report['sampled']}")
    if report.get("sampling_note"):
        print(f"  → {report['sampling_note']}")
    print(f"verdicts.available={report['verdicts']['available']}")
    print(f"landed={report['scans_landing_on_indicator']}  "
          f"redirected={report['scans_redirected_away']}")
    print(f"risk_signals={report['risk_signals']}")
    print(f"assessment: {report['assessment']}")

    # 2. Cache — the second identical call must not leave the process.
    head("2. cache")
    before = dict(client.cache_stats)
    await client.request("GET", "/api/v1/search/", action="Searching",
                         params={"q": q, "size": 100})
    print(f"before={before}  after={client.cache_stats}  (hits should be +1)")

    # 3. Screenshot — the real dimensions and byte sizes I could only guess at.
    if not report.get("sample_scans"):
        print("\n(no sample scans, so no screenshot to fetch)")
        await client.aclose()
        return 0

    uuid = report["sample_scans"][0]["uuid"]
    head(f"3. screenshot: {uuid}")
    try:
        data = await client.request_bytes(
            screenshots.SCREENSHOT_URL.format(uuid=uuid),
            action="Fetching a screenshot",
            max_bytes=screenshots.MAX_IMAGE_BYTES,
        )
    except ImageTooLarge as exc:
        print(f"refused at {exc.size_bytes:,} bytes — ceiling is "
              f"{screenshots.MAX_IMAGE_BYTES:,}. If real captures routinely hit "
              "this, the ceiling is too low.")
        await client.aclose()
        return 0
    except (ScanPending, UrlscanError) as exc:
        print(f"no screenshot: {exc}")
        await client.aclose()
        return 0

    print(f"raw: {len(data):,} bytes")
    try:
        from io import BytesIO

        from PIL import Image

        with Image.open(BytesIO(data)) as img:
            print(f"raw dimensions: {img.size[0]}x{img.size[1]}")
    except ImportError:
        print("(install pillow to see dimensions and exercise downscaling)")

    prepared, note = screenshots.prepare(data)
    print(f"prepared: {len(prepared):,} bytes  ({len(prepared) / max(1, len(data)):.0%} of raw)")
    print(f"note: {note}")
    print(f"base64 to the model: ~{len(prepared) * 4 // 3:,} chars")

    # 4. What ships alongside the image.
    head("4. analysis brief")
    try:
        result = await client.request(
            "GET", f"/api/v1/result/{uuid}/", require_key=True, action="Fetching a result"
        )
        summary = summarize_result(result)
    except UrlscanError as exc:
        print(f"(no result document: {exc})")
        summary = {"page": {}, "verdict": {}}
    print(screenshots.analysis_brief(summary))

    await client.aclose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
