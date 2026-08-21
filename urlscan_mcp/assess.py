"""Reputation assessment over a set of urlscan.io search hits.

This is the analysis the server does *on top of* the API, and it is the part
worth reusing: the rules about what a missing verdict means, and about which
scans may lend their reputation to the indicator, are the difference between a
useful assessment and a confidently wrong one.

It is deliberately free of both transport and MCP. Everything here takes
already-shaped search hits (see :func:`urlscan_mcp.shaping.summarize_search_hit`)
and returns plain dictionaries, so an embedding application can fetch through
its own HTTP stack — its own cache, its own rate limiting, its own failure
isolation — and still reach the same conclusions. DEEP does exactly that.

Two rules hold throughout, and both exist because breaking them is worse than
returning nothing:

* **No verdict data is not a clean verdict.** The free search tier returns no
  verdicts at all. Code that reads a missing verdict as "clean" reports every
  malicious indicator on earth as safe.
* **Reputation is only attributed to scans that landed on the indicator.** A
  scan reached via ``task.domain`` may have redirected somewhere else entirely,
  and its ``page.*`` fields then describe the destination. Crediting those to
  the indicator manufactures a good reputation for a throwaway redirector.
"""

from __future__ import annotations

from typing import Any, Iterable

#: Caveats attached to every assessment. Stated in the output rather than left
#: for the model to infer, because an omitted caveat reads as an absent risk.
CAVEATS = (
    "Absence of a malicious verdict is not evidence of safety.",
    "urlscan.io verdicts are heuristic and community-influenced, not ground truth.",
    "A low scan count means low visibility, not low risk.",
    "Shared hosting means co-located indicators are frequently unrelated.",
    "Scans reflect what the page served to that scanner, at that time, from "
    "that country — cloaked pages routinely serve something else.",
)

NO_SCANS_CAVEAT = (
    "Absence of scans is not evidence of safety — it usually just means nobody "
    "has submitted this indicator."
)

NO_VERDICT_NOTE = (
    "The urlscan.io search API does not return verdict data on this plan, with "
    "or without an API key. It does NOT mean the indicator is clean. Call "
    "get_scan_result on a specific uuid for that scan's verdict."
)

NO_LANDED_SCANS_NOTE = (
    "Every scan of this indicator redirected elsewhere, so no reputation signal "
    "can be attributed to it. The values above are empty by design — they are "
    "NOT evidence of good standing. See redirect_destinations."
)


def tally(values: Iterable[Any]) -> list[dict[str, Any]]:
    """Count occurrences, most frequent first."""
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return [
        {"value": k, "count": v}
        for k, v in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    ]


def partition_by_landing(
    indicator: str, kind: str, results: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split scans into those that landed on the indicator and those that left.

    Matching `task.domain` as well as `page.domain` finds redirectors, but the
    page.* fields of a redirected scan describe wherever it ended up. Reading
    apex domain age or Umbrella rank off those would credit the indicator with
    the destination's reputation — reporting a day-old throwaway domain as a
    decade-old top-1500 site because it bounced to github.com.

    Only domain lookups can be partitioned meaningfully; for IP, URL and hash
    lookups every result is treated as landed.
    """
    if kind != "domain":
        return list(results), []

    target = indicator.strip().lower().lstrip(".")
    landed: list[dict[str, Any]] = []
    redirected: list[dict[str, Any]] = []
    for r in results:
        page_domain = (r.get("domain") or "").lower()
        if page_domain == target or page_domain.endswith(f".{target}"):
            landed.append(r)
        else:
            redirected.append(r)
    return landed, redirected


def risk_signals(
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
    tag_values = {str(t.get("value", "")).lower() for t in tags}
    for marker in ("phishing", "malicious", "malware", "credential", "scam"):
        if any(marker in t for t in tag_values):
            signals.append(f"Submitters tagged scans with '{marker}'.")
            break
    if flagged:
        signals.append(f"{len(flagged)} scan(s) carry an explicit malicious verdict.")
    if scores and max(scores) >= 50:
        signals.append(f"Peak verdict score {max(scores)}.")
    return signals


def assessment_sentence(
    kind: str,
    total: int,
    flagged: list[dict[str, Any]],
    scores: list[float],
    verdicts_available: bool,
    ages: list[int],
    ranks: list[int],
) -> str:
    """One sentence a human can act on, with its own uncertainty stated."""
    if flagged or (scores and max(scores) >= 40):
        ratio = len(flagged) / total if total else 0
        peak = max(scores) if scores else "n/a"
        strength = "Strong" if ratio >= 0.5 or (scores and max(scores) >= 70) else "Moderate"
        return (
            f"{strength} negative signal: {len(flagged)} of {total} scans "
            f"({ratio:.0%}) flagged malicious, peak verdict score {peak}. "
            "Review the sample scans before acting."
        )

    young = bool(ages) and min(ages) < 30
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


def build_assessment(
    indicator: str,
    kind: str,
    results: list[dict[str, Any]],
    *,
    days: int | None = None,
    total_matching: Any = None,
) -> dict[str, Any]:
    """Aggregate shaped search hits into one reputation picture.

    ``results`` are hits already passed through
    :func:`urlscan_mcp.shaping.summarize_search_hit`. Nothing here performs
    I/O, so a caller supplying results from its own HTTP stack gets exactly the
    assessment the MCP tool would have produced.
    """
    if not results:
        return {
            "indicator": indicator,
            "type": kind,
            "scans_found": 0,
            "assessment": "No urlscan.io scans found in the selected window.",
            "caveats": [NO_SCANS_CAVEAT],
        }

    landed, redirected = partition_by_landing(indicator, kind, results)
    signal_source = landed if landed else []

    scores = [
        r["verdict_score"] for r in results
        if isinstance(r.get("verdict_score"), (int, float))
    ]
    flagged = [r for r in results if r.get("malicious") is True]
    # The free search tier omits verdicts entirely. Distinguishing "no verdict
    # data" from "verdicts say clean" is the whole point — conflating them
    # would make this confidently wrong about malicious indicators.
    verdicts_available = bool(scores) or any(r.get("malicious") is not None for r in results)

    tags = tally(tag for r in results for tag in (r.get("tags") or []))
    times = sorted(r["scanned_at"] for r in results if r.get("scanned_at"))
    domains = tally(r["domain"] for r in results if r.get("domain"))

    # Hosting and reputation are read only from scans that actually landed on
    # the indicator. See partition_by_landing.
    countries = tally(r["country"] for r in signal_source if r.get("country"))
    asns = tally(r["asn_name"] for r in signal_source if r.get("asn_name"))
    ages = [
        r["apex_domain_age_days"] for r in signal_source
        if isinstance(r.get("apex_domain_age_days"), int)
    ]
    ranks = [
        r["umbrella_rank"] for r in signal_source
        if isinstance(r.get("umbrella_rank"), int)
    ]

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
        verdicts["note"] = NO_VERDICT_NOTE

    return {
        "indicator": indicator,
        "type": kind,
        "window_days": days if kind != "hash" else None,
        "scans_found": len(results),
        "total_matching": total_matching,
        "first_seen": times[0] if times else None,
        "last_seen": times[-1] if times else None,
        "verdicts": verdicts,
        "scans_landing_on_indicator": len(landed),
        "scans_redirected_away": len(redirected),
        "redirect_destinations": tally(
            r["domain"] for r in redirected if r.get("domain")
        )[:10],
        "reputation_signals": {
            "derived_from_scans": len(signal_source),
            "min_apex_domain_age_days": min(ages) if ages else None,
            "best_umbrella_rank": min(ranks) if ranks else None,
            "ranked_in_umbrella": bool(ranks),
            "distinct_hosting_countries": len(countries),
            "distinct_asns": len(asns),
            **({"note": NO_LANDED_SCANS_NOTE} if not landed else {}),
        },
        "risk_signals": risk_signals(ages, ranks, tags, flagged, scores),
        "recurring_tags": tags[:10],
        "hosting_countries": countries[:10],
        "hosting_asns": asns[:10],
        "related_domains": domains[:10] if kind != "domain" else [],
        "assessment": assessment_sentence(
            kind, len(results), flagged, scores, verdicts_available, ages, ranks
        ),
        "sample_scans": [
            {
                "uuid": r.get("uuid"),
                "url": r.get("url"),
                "scanned_at": r.get("scanned_at"),
                "score": r.get("verdict_score"),
            }
            for r in results[:5]
        ],
        "caveats": list(CAVEATS),
    }
