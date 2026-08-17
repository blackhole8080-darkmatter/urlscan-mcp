"""Indicator classification and ElasticSearch query construction.

Split out of ``server.py`` so it can be imported without ``mcp`` — and
therefore without a running MCP transport — installed. The query semantics
here are the part that is easy to get subtly wrong, so anything embedding
this package (see ``assess.py``) should build its queries from these
functions rather than re-deriving them.

Pure functions, stdlib only. No I/O.
"""

from __future__ import annotations

import ipaddress
import re

#: ES query-string reserved characters. Anything user-supplied is escaped
#: before interpolation, so a domain containing a hyphen or a colon cannot
#: silently change the query's meaning.
RESERVED = r'+-=&|><!(){}[]^"~*?:\/'

_SHA256_RE = re.compile(r"[A-Fa-f0-9]{64}")
_DOMAIN_RE = re.compile(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_ASN_RE = re.compile(r"AS\d+")


def escape(value: str) -> str:
    """Escape ES query-string reserved characters in a user-supplied value."""
    return "".join(f"\\{c}" if c in RESERVED else c for c in value)


def time_filter(days: int | None) -> str:
    """An ` AND date:>now-Nd` clause, or empty when unbounded."""
    if not days or days <= 0:
        return ""
    return f" AND date:>now-{int(days)}d"


def submitted_or_final(field: str, value: str, quoted: bool = False) -> str:
    """Match both what was submitted and where the scan actually landed.

    urlscan records the submitted URL under `task.*` and the final,
    post-redirect page under `page.*`. Querying `page.*` alone silently misses
    every domain that redirects away — which is precisely what link shorteners,
    phishing redirectors and traffic distribution systems do. Verified against
    the live API: `page.domain:lzphy.top` returns 0 hits while
    `task.domain:lzphy.top` returns the scan, because the page redirected to
    github.com.

    Reporting "no scans found" for an indicator that has been scanned is the
    same class of error as reading a missing verdict as "clean": it turns a gap
    in the query into an apparent absence of findings.
    """
    rendered = f'"{value}"' if quoted else escape(value)
    return f"(page.{field}:{rendered} OR task.{field}:{rendered})"


def normalise_asn(asn: str) -> str | None:
    """`15169`, `as15169`, `AS15169` → `AS15169`. None when not an ASN."""
    normalised = asn.strip().upper()
    if not normalised.startswith("AS"):
        normalised = f"AS{normalised}"
    return normalised if _ASN_RE.fullmatch(normalised) else None


def is_sha256(value: str) -> bool:
    return bool(_SHA256_RE.fullmatch(value.strip()))


def classify(indicator: str) -> tuple[str, str] | None:
    """Infer the indicator's kind and build the query that finds it.

    Returns ``(kind, query)`` where kind is one of ``hash``, ``ip``, ``url``,
    ``domain`` — or None when the value is none of those.
    """
    value = (indicator or "").strip()
    if not value:
        return None
    if is_sha256(value):
        return "hash", f"hash:{value.lower()}"
    try:
        ipaddress.ip_address(value)
        return "ip", f"page.ip:{escape(value)}"
    except ValueError:
        pass
    if value.lower().startswith(("http://", "https://")):
        return "url", submitted_or_final("url", value, quoted=True)
    if _DOMAIN_RE.fullmatch(value):
        return "domain", submitted_or_final("domain", value)
    return None


def domain_query(domain: str, days: int | None = 90) -> str:
    """Recent scans of a domain and its subdomains, redirectors included."""
    return f"{submitted_or_final('domain', domain)}{time_filter(days)}"


def ip_query(ip: str, days: int | None = 90) -> str:
    """Recent scans of pages served from an IP. Raises ValueError if not an IP."""
    ipaddress.ip_address(ip)
    return f"page.ip:{escape(ip)}{time_filter(days)}"


def asn_query(asn: str, days: int | None = 30) -> str:
    """Recent scans hosted within an autonomous system. None when not an ASN."""
    normalised = normalise_asn(asn)
    if normalised is None:
        return ""
    return f"page.asn:{normalised}{time_filter(days)}"


def hash_query(sha256: str) -> str:
    """Scans that loaded a resource with this SHA-256 response hash."""
    return f"hash:{sha256.strip().lower()}"
