# urlscan-mcp

An MCP server for the [urlscan.io](https://urlscan.io) API. Scan URLs, search
the historical scan corpus, and assess indicators from Claude Code, Claude
Desktop, Cursor, or any other MCP client.

Fourteen tools. Python 3.10+. MIT.

---

## Why another one

The existing urlscan MCP servers expose roughly one tool — "scan a URL" — and
return the raw API response. That is a problem in practice, because a urlscan
result document is frequently **several megabytes**: every request, every
response header, every cookie. Handed to a model verbatim it swallows the
context window and buries the handful of facts anyone wanted.

This server is built around three decisions:

1. **Responses are shaped, not forwarded.** Every tool returns a summary built
   for a model to reason over. The raw document stays one `full=True` away.
   Measured against live scans of a news site: **2.7 MB → 3.3 KB, a 812×
   reduction**, on a page making 244 requests. Three real scans came in at
   240×, 571× and 812×.
2. **It degrades instead of failing.** Search and the country list work with no
   API key at all. `server_capabilities` reports exactly what is available, so
   the model never has to discover a limitation by hitting it.
3. **It never implies safety it cannot evidence.** The search API returns no
   verdict data at all — with or without a key. A tool that reads a missing
   verdict as "clean" reports every malicious indicator on earth as safe, so
   this one distinguishes *no data* from *no findings*, everywhere, and falls
   back to signals it can actually observe: apex domain age, Umbrella
   popularity rank, and submitter tags.

---

## Install

```bash
git clone <this repo>
cd urlscan-mcp
pip install -e .
```

Optional but recommended — a free API key from
[urlscan.io/user/signup](https://urlscan.io/user/signup):

```bash
cp .env.example .env   # then set URLSCAN_API_KEY
```

### Claude Code

```bash
claude mcp add urlscan --env URLSCAN_API_KEY=your_key_here -- python -m urlscan_mcp.server
```

### Claude Desktop / Cursor

Add to your MCP config:

```json
{
  "mcpServers": {
    "urlscan": {
      "command": "python",
      "args": ["-m", "urlscan_mcp.server"],
      "env": { "URLSCAN_API_KEY": "your_key_here" }
    }
  }
}
```

---

## What needs a key

Verified against the live API on 2026-08-03 — note this differs from what the
public docs imply, which is why `server_capabilities` exists.

| Works without a key | Requires a key |
|---|---|
| `search_scans` and all `search_by_*` | `scan_url`, `scan_and_wait` |
| `list_available_countries` | `get_scan_result`, `get_page_dom` |
| `assess_indicator` | `get_quotas` |
| `get_screenshot_url` | verdicts (present in results only) |

Verdicts never appear in **search** responses on the free plan, key or not —
only in individual result documents. `assess_indicator` runs on search, so it
reports `verdicts.available: false` and reasons from observable signals
instead. That is deliberate, and the reason is in the tool's own output.

---

## Tools

**Scanning**
- `scan_url` — submit a URL, return immediately with a UUID
- `scan_and_wait` — submit, poll, and return the finished summary in one call

**Retrieval**
- `get_scan_result` — summarised scan result (`full=True` for the raw document)
- `get_page_dom` — captured DOM, truncated
- `get_screenshot_url` — screenshot and report links

**Search**
- `search_scans` — raw ElasticSearch query string
- `search_by_domain` — a domain and its subdomains
- `search_by_ip` — what else was served from an address
- `search_by_asn` — everything within an autonomous system
- `search_by_hash` — pivot from a known-bad resource to every page serving it

**Assessment**
- `assess_indicator` — aggregate every recent scan of a domain, IP, URL or
  SHA-256 into one reputation picture, with explicit caveats

**Account**
- `get_quotas`, `list_available_countries`, `server_capabilities`

---

## Example

```
> assess_indicator for the domain in this phishing report

{
  "indicator": "…",
  "scans_found": 92,
  "verdicts": {
    "available": false,
    "note": "urlscan.io did not return verdict data for these scans. This is
             normal without an API key. It does NOT mean the indicator is clean."
  },
  "reputation_signals": {
    "min_apex_domain_age_days": 6,
    "ranked_in_umbrella": false
  },
  "risk_signals": [
    "Apex domain is very young (6 days) — common in phishing.",
    "Not present in the Umbrella popularity ranking — no established traffic.",
    "Submitters tagged scans with 'phishing'."
  ],
  "assessment": "No malicious verdict across 92 scan(s), but the apex domain is
                 only 6 days old and it has no Umbrella popularity ranking.
                 Treat as unproven rather than benign."
}
```

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

26 offline tests — no network, no key required. They cover query escaping,
input validation, auth degradation, response shaping against malformed
documents, and the assessment logic's refusal to imply safety.

---

## Limits

- Verdict-based search (`verdicts.score:>50`) requires a paid urlscan plan and
  returns HTTP 403 otherwise.
- Structure and similarity search are Pro-only and are not wrapped here.
- `assess_indicator` reads the last 100 matching scans, not the full history.
- urlscan verdicts are heuristic and community-influenced. Nothing here is
  ground truth, and the tools say so in their own output rather than leaving
  the model to infer it.
- Cloaked pages routinely serve different content to scanners than to victims.
  A clean scan is evidence about one fetch, from one country, at one time.

---

MIT. Not affiliated with urlscan.io.
