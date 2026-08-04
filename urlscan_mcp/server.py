"""MCP server for urlscan.io.

Thirteen tools over the urlscan.io API, shaped for agent use: summarised
responses instead of multi-megabyte JSON, honest errors, and read-only
operation when no API key is present.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import ScanPending, UrlscanClient, UrlscanError
from .shaping import summarize_result, summarize_search_hit, truncate

mcp = FastMCP("urlscan")
client = UrlscanClient()

# ES query-string reserved characters. Anything user-supplied gets escaped
# before it is interpolated into a query, so a domain containing a hyphen or a
# colon cannot silently change the query's meaning.
_RESERVED = r'+-=&|><!(){}[]^"~*?:\/'


def _escape(value: str) -> str:
    return "".join(f"\\{c}" if c in _RESERVED else c for c in value)


def _fail(exc: Exception) -> dict[str, Any]:
    return {"error": str(exc)}


def _time_filter(days: int | None) -> str:
    if not days or days <= 0:
        return ""
    return f" AND date:>now-{int(days)}d"


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
    """Find recent scans of a domain. Matches the domain and its subdomains."""
    query = f"page.domain:{_escape(domain)}{_time_filter(days)}"
    return await _search(query, size)


@mcp.tool()
async def search_by_ip(ip: str, days: int = 90, size: int = 20) -> dict[str, Any]:
    """Find recent scans of pages served from an IP address.

    Good for spotting what else is hosted alongside something suspicious.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": f"'{ip}' is not a valid IP address."}
    query = f"page.ip:{_escape(ip)}{_time_filter(days)}"
    return await _search(query, size)


@mcp.tool()
async def search_by_asn(asn: str, days: int = 30, size: int = 20) -> dict[str, Any]:
    """Find recent scans hosted within an autonomous system, e.g. 'AS15169'."""
    normalised = asn.upper()
    if not normalised.startswith("AS"):
        normalised = f"AS{normalised}"
    if not re.fullmatch(r"AS\d+", normalised):
        return {"error": f"'{asn}' is not a valid ASN. Expected a form like AS15169."}
    query = f"page.asn:{normalised}{_time_filter(days)}"
    return await _search(query, size)


@mcp.tool()
async def search_by_hash(sha256: str, size: int = 20) -> dict[str, Any]:
    """Find scans that loaded a resource with this SHA-256 response hash.

    Pivots from one known-bad file to every other page serving it — often the
    fastest way to map a campaign.
    """
    if not re.fullmatch(r"[A-Fa-f0-9]{64}", sha256.strip()):
        return {"error": "Expected a 64-character hex SHA-256 hash."}
    return await _search(f"hash:{sha256.strip().lower()}", size)


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


def _classify(indicator: str) -> tuple[str, str] | None:
    value = indicator.strip()
    if re.fullmatch(r"[A-Fa-f0-9]{64}", value):
        return "hash", f"hash:{value.lower()}"
    try:
        ipaddress.ip_address(value)
        return "ip", f"page.ip:{_escape(value)}"
    except ValueError:
        pass
    if value.lower().startswith(("http://", "https://")):
        return "url", f'page.url:"{value}"'
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value):
        return "domain", f"page.domain:{_escape(value)}"
    return None


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
    classified = _classify(indicator)
    if classified is None:
        return {
            "error": f"Could not classify '{indicator}'. Expected a domain, IP "
            "address, URL, or SHA-256 hash."
        }
    kind, base_query = classified
    query = base_query + (_time_filter(days) if kind != "hash" else "")

    found = await _search(query, size=100)
    if "error" in found:
        return found

    results = found["results"]
    if not results:
        return {
            "indicator": indicator,
            "type": kind,
            "scans_found": 0,
            "assessment": "No urlscan.io scans found in the selected window.",
            "caveats": [
                "Absence of scans is not evidence of safety — it usually just "
                "means nobody has submitted this indicator.",
            ],
        }

    scores = [r["verdict_score"] for r in results if isinstance(r["verdict_score"], (int, float))]
    flagged = [r for r in results if r.get("malicious") is True]
    # The free search tier omits verdicts entirely. Distinguishing "no verdict
    # data" from "verdicts say clean" is the whole point — conflating them
    # would make this tool confidently wrong about malicious indicators.
    verdicts_available = bool(scores) or any(r.get("malicious") is not None for r in results)

    tags = _tally(tag for r in results for tag in (r.get("tags") or []))
    countries = _tally(r["country"] for r in results if r.get("country"))
    asns = _tally(r["asn_name"] for r in results if r.get("asn_name"))
    domains = _tally(r["domain"] for r in results if r.get("domain"))
    times = sorted(r["scanned_at"] for r in results if r.get("scanned_at"))

    ages = [r["apex_domain_age_days"] for r in results if isinstance(r.get("apex_domain_age_days"), int)]
    ranks = [r["umbrella_rank"] for r in results if isinstance(r.get("umbrella_rank"), int)]

    verdicts: dict[str, Any] = {"available": verdicts_available}
    if verdicts_available:
        verdicts.update(
            {
                "flagged_malicious": len(flagged),
                "malicious_ratio": round(len(flagged) / len(results), 3),
                "max_score": max(scores) if scores else None,
                "mean_score": round(sum(scores) / len(scores), 1) if scores else None,
            }
        )
    else:
        verdicts["note"] = (
            "The urlscan.io search API does not return verdict data on this plan, "
            "with or without an API key. It does NOT mean the indicator is clean. "
            "Call get_scan_result on a specific uuid for that scan's verdict."
        )

    return {
        "indicator": indicator,
        "type": kind,
        "window_days": days if kind != "hash" else None,
        "scans_found": len(results),
        "total_matching": found.get("total"),
        "first_seen": times[0] if times else None,
        "last_seen": times[-1] if times else None,
        "verdicts": verdicts,
        "reputation_signals": {
            "min_apex_domain_age_days": min(ages) if ages else None,
            "best_umbrella_rank": min(ranks) if ranks else None,
            "ranked_in_umbrella": bool(ranks),
            "distinct_hosting_countries": len(countries),
            "distinct_asns": len(asns),
        },
        "risk_signals": _risk_signals(ages, ranks, tags, flagged, scores),
        "recurring_tags": tags[:10],
        "hosting_countries": countries[:10],
        "hosting_asns": asns[:10],
        "related_domains": domains[:10] if kind != "domain" else [],
        "assessment": _assessment_sentence(
            kind, len(results), flagged, scores, verdicts_available, ages, ranks
        ),
        "sample_scans": [
            {
                "uuid": r["uuid"],
                "url": r["url"],
                "scanned_at": r["scanned_at"],
                "score": r["verdict_score"],
            }
            for r in results[:5]
        ],
        "caveats": [
            "Absence of a malicious verdict is not evidence of safety.",
            "urlscan.io verdicts are heuristic and community-influenced, not ground truth.",
            "A low scan count means low visibility, not low risk.",
            "Shared hosting means co-located indicators are frequently unrelated.",
            "Scans reflect what the page served to that scanner, at that time, from "
            "that country — cloaked pages routinely serve something else.",
        ],
    }


def _risk_signals(
    ages: list[int],
    ranks: list[int],
    tags: list[dict[str, Any]],
    flagged: list[dict[str, Any]],
    scores: list[float],
) -> list[str]:
    """Observable signals, available even when verdict data is not.

    Domain age and popularity rank catch freshly-registered phishing that no
    verdict engine has scored yet — which is most of it, at the point it
    matters.
    """
    signals: list[str] = []
    if ages:
        youngest = min(ages)
        if youngest < 30:
            signals.append(f"Apex domain is very young ({youngest} days) — common in phishing.")
        elif youngest < 180:
            signals.append(f"Apex domain is relatively new ({youngest} days).")
    if not ranks:
        signals.append("Not present in the Umbrella popularity ranking — no established traffic.")
    tag_values = {t["value"].lower() for t in tags}
    for marker in ("phishing", "malicious", "malware", "credential", "scam"):
        if any(marker in t for t in tag_values):
            signals.append(f"Submitters tagged scans with '{marker}'.")
            break
    if flagged:
        signals.append(f"{len(flagged)} scan(s) carry an explicit malicious verdict.")
    if scores and max(scores) >= 50:
        signals.append(f"Peak verdict score {max(scores)}.")
    return signals


def _assessment_sentence(
    kind: str,
    total: int,
    flagged: list[dict[str, Any]],
    scores: list[float],
    verdicts_available: bool,
    ages: list[int],
    ranks: list[int],
) -> str:
    if flagged or (scores and max(scores) >= 40):
        ratio = len(flagged) / total if total else 0
        peak = max(scores) if scores else "n/a"
        strength = "Strong" if ratio >= 0.5 or (scores and max(scores) >= 70) else "Moderate"
        return (
            f"{strength} negative signal: {len(flagged)} of {total} scans "
            f"({ratio:.0%}) flagged malicious, peak verdict score {peak}. "
            "Review the sample scans before acting."
        )

    young = ages and min(ages) < 30
    unranked = not ranks
    if young or unranked:
        parts = []
        if young:
            parts.append(f"the apex domain is only {min(ages)} days old")
        if unranked:
            parts.append("it has no Umbrella popularity ranking")
        joined = " and ".join(parts)
        return (
            f"No malicious verdict across {total} scan(s), but {joined}. "
            "Treat as unproven rather than benign."
        )

    if not verdicts_available:
        return (
            f"{total} scan(s) found for this {kind}. The search API returned no "
            "verdict data, so this is a record of observation only — it says nothing "
            "about whether the indicator is malicious. Use get_scan_result on one of "
            "the sample scans for a verdict."
        )

    return (
        f"{total} scan(s) found for this {kind}; none carried a malicious verdict, "
        "and the domain is established. Weak positive evidence, not a clean bill of health."
    )


def _tally(values: Any) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return [
        {"value": k, "count": v}
        for k, v in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    ]


def _verdict_sentence(
    kind: str, total: int, malicious: int, ratio: float, scores: list[float]
) -> str:
    if malicious == 0:
        return (
            f"{total} scan(s) found for this {kind}; none were flagged malicious. "
            "That is weak positive evidence, not a clean bill of health."
        )
    high = max(scores) if scores else 0
    if ratio >= 0.5 or high >= 70:
        strength = "Strong"
    elif ratio >= 0.2 or high >= 40:
        strength = "Moderate"
    else:
        strength = "Weak"
    return (
        f"{strength} negative signal: {malicious} of {total} scans "
        f"({ratio:.0%}) were flagged malicious, peak verdict score {high}. "
        "Review the sample scans before acting."
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
