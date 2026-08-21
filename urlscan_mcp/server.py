"""MCP server for urlscan.io.

Fourteen tools over the urlscan.io API, shaped for agent use: summarised
responses instead of multi-megabyte JSON, honest errors, and read-only
operation when no API key is present.

This module is the MCP transport and nothing else. Query construction lives in
``query.py`` and the reputation analysis in ``assess.py``, both of which import
no ``mcp`` and perform no I/O, so an application embedding urlscan.io through
its own HTTP stack reaches the same conclusions as this server rather than
reimplementing them.
"""

from __future__ import annotations

import asyncio
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import query as q
from .assess import build_assessment
from .client import ScanPending, UrlscanClient, UrlscanError
from .shaping import summarize_result, summarize_search_hit, truncate

mcp = FastMCP("urlscan")
client = UrlscanClient()

def _fail(exc: Exception) -> dict[str, Any]:
    return {"error": str(exc)}


# --------------------------------------------------------------------------
# Submission
# --------------------------------------------------------------------------


@mcp.tool()
async def scan_url(
    url: str,
    visibility: str = "public",
    tags: list[str] | None = None,
    country: str | None = None,
    referer: str | None = None,
    user_agent: str | None = None,
) -> dict[str, Any]:
    """Submit a URL to urlscan.io for scanning. Returns immediately with a UUID.

    The scan takes roughly 10-30 seconds to complete. Use scan_and_wait instead
    if you want the finished result in one call.

    Requires an API key. visibility must be one of: public, unlisted, private.
    country is a 2-letter ISO code selecting the scanner's exit location.
    """
    if visibility not in ("public", "unlisted", "private"):
        return {"error": "visibility must be 'public', 'unlisted' or 'private'."}
    if tags and len(tags) > 10:
        return {"error": "urlscan.io accepts at most 10 tags per submission."}

    payload: dict[str, Any] = {"url": url, "visibility": visibility}
    if tags:
        payload["tags"] = tags
    if country:
        payload["country"] = country
    if referer:
        payload["referer"] = referer
    if user_agent:
        payload["customagent"] = user_agent

    try:
        data = await client.request(
            "POST",
            "/api/v1/scan/",
            require_key=True,
            action="Submitting a scan",
            json=payload,
        )
    except UrlscanError as exc:
        return _fail(exc)

    return {
        "uuid": data.get("uuid"),
        "result_url": data.get("result"),
        "api_url": data.get("api"),
        "visibility": data.get("visibility"),
        "message": "Scan submitted. Results are usually ready in 10-30 seconds; "
        "call get_scan_result with this uuid.",
    }


@mcp.tool()
async def scan_and_wait(
    url: str,
    visibility: str = "public",
    tags: list[str] | None = None,
    country: str | None = None,
    timeout_seconds: int = 90,
) -> dict[str, Any]:
    """Submit a URL and wait for the finished, summarised result.

    This is the tool to reach for in most workflows — it handles the submit,
    poll and summarise cycle in one call. Requires an API key.
    """
    submitted = await scan_url(
        url, visibility=visibility, tags=tags, country=country
    )
    if "error" in submitted:
        return submitted

    uuid = submitted["uuid"]
    deadline = asyncio.get_event_loop().time() + max(10, timeout_seconds)
    delay = 5.0

    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(delay)
        try:
            data = await client.request(
                "GET", f"/api/v1/result/{uuid}/", action="Fetching a scan result"
            )
        except ScanPending:
            delay = min(delay * 1.4, 15.0)
            continue
        except UrlscanError as exc:
            return _fail(exc)
        return summarize_result(data)

    return {
        "uuid": uuid,
        "error": f"Scan did not finish within {timeout_seconds}s. It is probably "
        "still running — call get_scan_result with this uuid shortly.",
    }


# --------------------------------------------------------------------------
# Retrieval
# --------------------------------------------------------------------------


@mcp.tool()
async def get_scan_result(uuid: str, full: bool = False) -> dict[str, Any]:
    """Fetch the result of a completed scan by UUID. Requires an API key.

    Returns a summary by default. Set full=True for the complete document —
    be aware that it is frequently several megabytes and will dominate the
    context window.
    """
    try:
        data = await client.request(
            "GET",
            f"/api/v1/result/{uuid}/",
            require_key=True,
            action="Fetching a scan result",
        )
    except ScanPending as exc:
        return {"uuid": uuid, "status": "pending", "message": str(exc)}
    except UrlscanError as exc:
        return _fail(exc)

    return data if full else summarize_result(data)


@mcp.tool()
async def get_page_dom(uuid: str, max_chars: int = 20000) -> dict[str, Any]:
    """Fetch the captured DOM snapshot for a scan. Requires an API key.

    Useful for inspecting injected scripts, hidden form fields, or obfuscated
    payloads. Truncated to max_chars — full DOMs regularly exceed 1 MB.
    """
    try:
        text = await client.request(
            "GET",
            f"/dom/{uuid}/",
            require_key=True,
            action="Fetching a DOM snapshot",
            expect_json=False,
        )
    except ScanPending:
        return {"uuid": uuid, "status": "pending"}
    except UrlscanError as exc:
        return _fail(exc)

    return {
        "uuid": uuid,
        "length": len(text),
        "dom": truncate(text, max_chars),
    }


@mcp.tool()
async def get_screenshot_url(uuid: str) -> dict[str, Any]:
    """Get the screenshot URL for a scan.

    Returns a link rather than image bytes — screenshots are large and usually
    meant for a human to open.
    """
    return {
        "uuid": uuid,
        "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
        "report_url": f"https://urlscan.io/result/{uuid}/",
    }


# --------------------------------------------------------------------------
# Search
# --------------------------------------------------------------------------


async def _search(query: str, size: int) -> dict[str, Any]:
    size = max(1, min(size, 100))
    try:
        data = await client.request(
            "GET",
            "/api/v1/search/",
            action="Searching scans",
            params={"q": query, "size": size},
        )
    except UrlscanError as exc:
        return _fail(exc)

    results = data.get("results") or []
    return {
        "query": query,
        "total": data.get("total"),
        "returned": len(results),
        "has_more": bool(data.get("has_more")),
        "results": [summarize_search_hit(hit) for hit in results],
    }


@mcp.tool()
async def search_scans(query: str, size: int = 20) -> dict[str, Any]:
    """Search historical urlscan.io scans with an ElasticSearch query string.

    Useful fields: page.domain, page.ip, page.asn, page.server, page.status,
    domain, ip, asn, country, hash, filename, task.tags, verdicts.score,
    verdicts.malicious, date.

    Examples:
      page.domain:example.com AND page.status:200
      task.tags:phishing AND date:>now-30d
      verdicts.score:>50 AND page.asn:AS15169

    Works without an API key, at lower rate limits.
    """
    return await _search(query, size)


@mcp.tool()
async def search_by_domain(
    domain: str, days: int = 90, size: int = 20
) -> dict[str, Any]:
    """Find recent scans of a domain. Matches the domain and its subdomains.

    Matches both scans that landed on the domain and scans that were pointed at
    it but redirected elsewhere.
    """
    return await _search(q.domain_query(domain, days), size)


@mcp.tool()
async def search_by_ip(ip: str, days: int = 90, size: int = 20) -> dict[str, Any]:
    """Find recent scans of pages served from an IP address.

    Good for spotting what else is hosted alongside something suspicious.
    """
    try:
        query = q.ip_query(ip, days)
    except ValueError:
        return {"error": f"'{ip}' is not a valid IP address."}
    return await _search(query, size)


@mcp.tool()
async def search_by_asn(asn: str, days: int = 30, size: int = 20) -> dict[str, Any]:
    """Find recent scans hosted within an autonomous system, e.g. 'AS15169'."""
    query = q.asn_query(asn, days)
    if not query:
        return {"error": f"'{asn}' is not a valid ASN. Expected a form like AS15169."}
    return await _search(query, size)


@mcp.tool()
async def search_by_hash(sha256: str, size: int = 20) -> dict[str, Any]:
    """Find scans that loaded a resource with this SHA-256 response hash.

    Pivots from one known-bad file to every other page serving it — often the
    fastest way to map a campaign.
    """
    if not q.is_sha256(sha256):
        return {"error": "Expected a 64-character hex SHA-256 hash."}
    return await _search(q.hash_query(sha256), size)


# --------------------------------------------------------------------------
# Account
# --------------------------------------------------------------------------


@mcp.tool()
async def get_quotas() -> dict[str, Any]:
    """Show remaining urlscan.io API quota for the configured key.

    Worth checking before a batch of scans. Requires an API key.
    """
    try:
        return await client.request(
            "GET", "/user/quotas/", require_key=True, action="Reading quotas"
        )
    except UrlscanError as exc:
        return _fail(exc)


@mcp.tool()
async def list_available_countries() -> dict[str, Any]:
    """List country codes available as scanner exit locations.

    Geo-targeted phishing frequently only serves the payload to one region, so
    re-scanning from the right country is often what makes it visible.
    """
    try:
        data = await client.request(
            "GET", "/api/v1/availableCountries/", action="Listing countries"
        )
    except UrlscanError as exc:
        return _fail(exc)
    return data if isinstance(data, dict) else {"countries": data}


@mcp.tool()
async def server_capabilities() -> dict[str, Any]:
    """Report which operations are available with the current configuration.

    Submission and quota lookup need an API key; search and result retrieval
    do not. Call this first if something is unexpectedly refused.
    """
    caps = client.capabilities()
    return {
        "authenticated": client.authenticated,
        "available": caps,
        "note": (
            "Read-only mode: set URLSCAN_API_KEY to enable scan submission."
            if not client.authenticated
            else "Fully configured."
        ),
    }


# --------------------------------------------------------------------------
# Assessment — the layer above the raw API
# --------------------------------------------------------------------------


@mcp.tool()
async def assess_indicator(indicator: str, days: int = 180) -> dict[str, Any]:
    """Build a reputation picture for a domain, IP, URL or SHA-256 hash.

    Aggregates every recent urlscan.io scan of the indicator into one
    assessment: how often it has been scanned, how many scans were flagged
    malicious, the highest and mean verdict scores, which tags and brands
    recur, and the hosting spread.

    This is analysis on top of the raw API rather than a passthrough — it
    answers "should I care about this?" instead of returning a scan document.
    Read the caveats field before acting on the result.
    """
    classified = q.classify(indicator)
    if classified is None:
        return {
            "error": f"Could not classify '{indicator}'. Expected a domain, IP "
            "address, URL, or SHA-256 hash."
        }
    kind, base_query = classified
    query = base_query + (q.time_filter(days) if kind != "hash" else "")

    found = await _search(query, size=100)
    if "error" in found:
        return found

    return build_assessment(
        indicator,
        kind,
        found["results"],
        days=days,
        total_matching=found.get("total"),
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
