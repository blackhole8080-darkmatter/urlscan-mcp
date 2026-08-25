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
from typing import Any

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

    # 3. Screenshots — the shapes the thresholds were guessed against.
    #
    # Every capture the sample offers, not the first that works. One screenshot
    # answers "does this path function"; only a spread answers "are 3 MB, 1024px
    # and 2.5:1 the right numbers", which is the question that cannot be settled
    # without the live API. The verdict below is the point of the whole script.
    candidates = [s["uuid"] for s in report.get("sample_scans", []) if s.get("uuid")]
    if not candidates:
        print("\n(no sample scans, so no screenshots to measure)")
        await client.aclose()
        return 0

    head(f"3. screenshots ({len(candidates)} candidate(s))")
    measured: list[dict[str, Any]] = []
    oversized = 0
    for uuid in candidates:
        try:
            raw = await client.request_bytes(
                screenshots.SCREENSHOT_URL.format(uuid=uuid),
                action="Fetching a screenshot",
                max_bytes=screenshots.MAX_IMAGE_BYTES,
            )
        except ImageTooLarge as exc:
            oversized += 1
            print(f"  {uuid[:8]}  REFUSED at {exc.size_bytes:>10,} bytes "
                  f"(ceiling {screenshots.MAX_IMAGE_BYTES:,})")
            measured.append({"uuid": uuid, "raw": exc.size_bytes, "refused": True})
            continue
        except (ScanPending, UrlscanError) as exc:
            print(f"  {uuid[:8]}  {exc}")
            continue

        entry: dict[str, Any] = {"uuid": uuid, "raw": len(raw), "refused": False}
        try:
            from io import BytesIO

            from PIL import Image

            with Image.open(BytesIO(raw)) as img:
                entry["width"], entry["height"] = img.size
                entry["aspect"] = img.size[1] / max(1, img.size[0])
        except ImportError:
            pass

        prepared, note = screenshots.prepare(raw)
        entry["prepared"] = len(prepared)
        entry["note"] = note
        measured.append(entry)

        shape = (f'{entry["width"]}x{entry["height"]} {entry["aspect"]:.1f}:1'
                 if "width" in entry else "(install pillow for dimensions)")
        print(f'  {uuid[:8]}  {entry["raw"]:>10,} -> {entry["prepared"]:>9,} bytes  {shape}')

    if not measured:
        print("\nno screenshot available from any sample scan")
        await client.aclose()
        return 0

    # ---- the verdict -------------------------------------------------------
    head("3b. are the thresholds right?")
    fetched = [m for m in measured if not m["refused"]]
    raws = sorted(m["raw"] for m in measured)
    median = raws[len(raws) // 2]
    print(f"captures measured:     {len(measured)}")
    print(f"raw bytes:             min {raws[0]:,}  median {median:,}  max {raws[-1]:,}")

    print(f"\nMAX_IMAGE_BYTES = {screenshots.MAX_IMAGE_BYTES:,}")
    if oversized == 0:
        print(f"  OK — nothing hit the ceiling. Headroom over the largest: "
              f"{screenshots.MAX_IMAGE_BYTES / max(1, raws[-1]):.1f}x.")
    elif oversized <= len(measured) // 4:
        print(f"  Borderline — {oversized} of {len(measured)} refused. A rare "
              "refusal is the ceiling doing its job.")
    else:
        print(f"  TOO LOW — {oversized} of {len(measured)} refused. Refusing the "
              "common case makes the tool useless, not safe. Raise it.")

    aspects = [m["aspect"] for m in fetched if "aspect" in m]
    if aspects:
        cropped = [a for a in aspects if a > screenshots.MAX_ASPECT_RATIO]
        print(f"\nMAX_ASPECT_RATIO = {screenshots.MAX_ASPECT_RATIO}")
        print(f"  page aspect: min {min(aspects):.1f}:1  median "
              f"{sorted(aspects)[len(aspects) // 2]:.1f}:1  max {max(aspects):.1f}:1")
        if not cropped:
            print("  Never fires on this sample — either these pages are short, "
                  "or the threshold is too generous to protect anything.")
        elif len(cropped) == len(aspects):
            print("  Fires on every capture. Cropping every page means the "
                  "threshold is below the normal page, not above it — the model "
                  "is losing content it should be seeing.")
        else:
            print(f"  Fires on {len(cropped)} of {len(aspects)} — a threshold "
                  "that discriminates, which is what it is for.")

    widths = [m["width"] for m in fetched if "width" in m]
    if widths:
        print(f"\nTARGET_WIDTH = {screenshots.TARGET_WIDTH}")
        print(f"  capture width: {sorted(set(widths))}")
        if all(w <= screenshots.TARGET_WIDTH for w in widths):
            print("  No downscaling happens — captures are already this narrow, "
                  "so the setting costs nothing and does nothing.")
        else:
            ratios = [m["prepared"] / max(1, m["raw"]) for m in fetched if "prepared" in m]
            if ratios:
                print(f"  Downscaling to {screenshots.TARGET_WIDTH}px leaves "
                      f"{sum(ratios) / len(ratios):.0%} of the bytes on average.")

    data = next((m for m in fetched), None)
    if data is None:
        await client.aclose()
        return 0
    uuid = data["uuid"]
    print(f"\nnote from {uuid[:8]}: {data.get('note')}")
    print(f"base64 to the model: ~{data['prepared'] * 4 // 3:,} chars")

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
