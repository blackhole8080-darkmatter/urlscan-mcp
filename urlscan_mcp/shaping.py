"""Turn urlscan.io responses into something an LLM can actually use.

A single urlscan result document is frequently several megabytes — every
request, every response header, every cookie, the full DOM. Handing that to a
model verbatim burns the context window and buries the three facts anyone
actually wanted.

Every tool in this server returns a shaped summary by default. The raw
document stays one flag away for the cases that need it.
"""

from __future__ import annotations

from typing import Any

MAX_LIST_ITEMS = 15
MAX_CONSOLE_MESSAGES = 5


def _g(obj: Any, *path: str, default: Any = None) -> Any:
    """Nested get that never raises. urlscan's schema varies by scan age."""
    current = obj
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return f"{text[:max_chars]}\n\n[truncated — {omitted:,} more characters]"


def _capped(items: Any, limit: int = MAX_LIST_ITEMS) -> dict[str, Any]:
    """A list plus an honest note about what was cut."""
    if not isinstance(items, list):
        return {"items": [], "total": 0}
    out: dict[str, Any] = {"items": items[:limit], "total": len(items)}
    if len(items) > limit:
        out["note"] = f"showing {limit} of {len(items)}"
    return out


def summarize_result(data: dict[str, Any]) -> dict[str, Any]:
    """The ~40 fields that matter, out of the several thousand available."""
    task = data.get("task") or {}
    page = data.get("page") or {}
    stats = data.get("stats") or {}
    lists = data.get("lists") or {}
    overall = _g(data, "verdicts", "overall", default={}) or {}

    summary: dict[str, Any] = {
        "uuid": task.get("uuid"),
        "submitted_url": task.get("url"),
        "final_url": page.get("url"),
        "scanned_at": task.get("time"),
        "visibility": task.get("visibility"),
        "tags": task.get("tags") or [],
        "verdict": {
            "score": overall.get("score"),
            "malicious": overall.get("malicious"),
            "has_verdicts": overall.get("hasVerdicts"),
            "categories": overall.get("categories") or [],
            "brands": overall.get("brands") or [],
            "tags": overall.get("tags") or [],
        },
        "page": {
            "domain": page.get("domain"),
            "apex_domain": page.get("apexDomain"),
            "ip": page.get("ip"),
            "asn": page.get("asn"),
            "asn_name": page.get("asnname"),
            "country": page.get("country"),
            "city": page.get("city"),
            "server": page.get("server"),
            "status": page.get("status"),
            "mime_type": page.get("mimeType"),
            "title": page.get("title"),
        },
        "tls": {
            "valid_days": page.get("tlsValidDays"),
            "age_days": page.get("tlsAgeDays"),
            "valid_from": page.get("tlsValidFrom"),
            "issuer": page.get("tlsIssuer"),
        },
        "activity": {
            "total_requests": len(_g(data, "data", "requests", default=[]) or []),
            "unique_ips": len(lists.get("ips") or []),
            "unique_countries": stats.get("uniqCountries"),
            "unique_domains": len(lists.get("domains") or []),
            "secure_percentage": stats.get("securePercentage"),
            "malicious_requests": stats.get("malicious"),
            "ads_blocked": stats.get("adBlocked"),
            "outgoing_links": stats.get("totalLinks"),
            "cookies": len(_g(data, "data", "cookies", default=[]) or []),
        },
        "contacted_ips": _capped(lists.get("ips")),
        "contacted_domains": _capped(lists.get("domains")),
        "contacted_countries": _capped(lists.get("countries")),
        "servers": _capped(lists.get("servers")),
        "redirect_chain": _redirect_chain(data),
        "console_errors": _console_errors(data),
        "links": {
            "report": task.get("reportURL"),
            "screenshot": task.get("screenshotURL"),
            "dom": task.get("domURL"),
        },
    }
    return summary


def _redirect_chain(data: dict[str, Any]) -> list[str]:
    """Where the URL actually took you. Often the whole story on its own."""
    chain: list[str] = []
    for entry in _g(data, "data", "requests", default=[]) or []:
        redirect = _g(entry, "request", "redirectResponse")
        if isinstance(redirect, dict) and redirect.get("url"):
            chain.append(redirect["url"])
    submitted = _g(data, "task", "url")
    final = _g(data, "page", "url")
    if submitted and submitted not in chain:
        chain.insert(0, submitted)
    if final and final not in chain:
        chain.append(final)
    return chain[:MAX_LIST_ITEMS] if len(chain) > 1 else []


def _console_errors(data: dict[str, Any]) -> list[str]:
    """Console output is noisy, but obfuscation and injected script errors show here."""
    messages: list[str] = []
    for entry in _g(data, "data", "console", default=[]) or []:
        message = _g(entry, "message", "text") or _g(entry, "message", "description")
        level = _g(entry, "message", "level")
        if message and level in ("error", "warning"):
            messages.append(truncate(str(message).strip(), 200))
        if len(messages) >= MAX_CONSOLE_MESSAGES:
            break
    return messages


def summarize_search_hit(hit: dict[str, Any]) -> dict[str, Any]:
    """One compact row per search result — enough to decide what to open.

    Note on verdicts: the search API does not return verdict data on the free
    tier, so `verdict_score` and `malicious` are normally None. The fields are
    kept because authenticated and Pro responses do populate them — but nothing
    downstream may treat None as "clean". See assess_indicator.

    Domain age and Umbrella rank are the useful free-tier signals and are worth
    more than a verdict score for freshly-registered phishing anyway.
    """
    page = hit.get("page") or {}
    task = hit.get("task") or {}
    stats = hit.get("stats") or {}
    return {
        "uuid": hit.get("_id") or task.get("uuid"),
        "url": task.get("url") or page.get("url"),
        "domain": page.get("domain"),
        "apex_domain": page.get("apexDomain"),
        "ip": page.get("ip"),
        "ptr": page.get("ptr"),
        "asn": page.get("asn"),
        "asn_name": page.get("asnname"),
        "country": page.get("country"),
        "server": page.get("server"),
        "status": page.get("status"),
        "title": truncate(str(page.get("title") or ""), 120) or None,
        "scanned_at": task.get("time"),
        "tags": task.get("tags") or [],
        "domain_age_days": page.get("domainAgeDays"),
        "apex_domain_age_days": page.get("apexDomainAgeDays"),
        "umbrella_rank": page.get("umbrellaRank"),
        "tls_issuer": page.get("tlsIssuer"),
        "tls_age_days": page.get("tlsAgeDays"),
        "unique_ips": stats.get("uniqIPs"),
        "requests": stats.get("requests"),
        "verdict_score": _g(hit, "verdicts", "overall", "score"),
        "malicious": _g(hit, "verdicts", "overall", "malicious"),
        "result": hit.get("result"),
        "screenshot": hit.get("screenshot"),
    }
