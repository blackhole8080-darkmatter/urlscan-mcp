# urlscan-mcp

An MCP server for the [urlscan.io](https://urlscan.io) API. Scan URLs, search
the historical scan corpus, and assess indicators from Claude Code, Claude
Desktop, Cursor, or any other MCP client.

Fifteen tools. Cached reads. Sees the page. Python 3.10+. MIT.

---

## Why another one

The existing urlscan MCP servers expose roughly one tool — "scan a URL" — and
return the raw API response. That is a problem in practice, because a urlscan
result document is frequently **several megabytes**: every request, every
response header, every cookie. Handed to a model verbatim it swallows the
context window and buries the handful of facts anyone wanted.

This server is built around five decisions:

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
4. **Reads are cached, and a sample says it is one.** Scans are immutable once
   written, so GETs are held for an hour — an agent pivoting around one
   investigation asks the same question repeatedly, and the free tier should
   not be spent on answers already known. Submissions are never cached:
   replaying one would hand back a scan id for a scan that never ran. And when
   more scans match than the API's 100-per-page cap returns, `assess_indicator`
   sets `sampled` and says so, because a sample presented as a total is the
   same class of error as a missing verdict presented as clean.
5. **Domain and URL lookups match redirectors.** urlscan records the submitted
   URL under `task.*` and the final, post-redirect page under `page.*`.
   Querying `page.*` alone — which is what the obvious implementation does —
   silently misses every domain that redirects away, and redirecting away is
   exactly what link shorteners, phishing redirectors and traffic distribution
   systems do. Verified against the live API: `page.domain:lzphy.top` returns
   zero hits while `task.domain:lzphy.top` returns the scan, because the page
   redirected to github.com. Reporting "no scans found" for an indicator that
   *has* been scanned is the same failure as reading a missing verdict as
   "clean", so both lookups query `(page.X OR task.X)`.

   The trap is what comes next. A redirected scan's `page.*` fields describe
   the *destination*, so reading apex domain age or Umbrella rank off them
   credits the indicator with someone else's reputation — `lzphy.top` inherited
   github.com's 13-year age and rank 1508, which in turn suppressed the "no
   established traffic" risk signal. `assess_indicator` therefore derives
   reputation only from scans that actually landed on the indicator, reports
   `scans_redirected_away` and `redirect_destinations` separately, and says
   explicitly when no signal can be attributed. Manufacturing a good reputation
   is a worse failure than withholding a verdict.

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
| `analyze_screenshot` | |

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
- `get_screenshot_url` — screenshot and report links, for a human to open
- `analyze_screenshot` — **the page itself**, as an image your model can read

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

## Seeing the page

Every other tool returns metadata *about* a page. `analyze_screenshot` returns
the page. Domain age and popularity rank say a site is suspicious; only looking
at it says *this is a Microsoft 365 sign-in form* — which is the question
someone triaging a phishing report is actually asking. It needs no API key.

The model doing the looking is **your client's**, not a second vendor's. MCP
carries images natively, so the screenshot comes back as image content and
whatever multimodal model is driving the session reads it. No extra key, no
extra bill, and the analysis improves when your model does.

What ships with the image matters as much as the image:

- **A brand is not a verdict.** A real Microsoft login page and a perfect clone
  are the same pixels. What makes one phishing is the brand not matching the
  domain serving it — so the domain travels with the picture and the
  instruction says to compare them. Told only "look for phishing", a model
  reports every login form it sees.
- **A redirect is surfaced.** Judging the brand against the *submitted* domain
  after a scan bounced elsewhere compares the page to a host that never served
  it.
- **One fetch, one country, one moment.** Cloaked pages serve scanners
  something bland and victims something else, and a blank capture usually means
  blocked rather than safe.
- **The image is attacker-controlled.** Text rendered into a page can carry
  instructions aimed at whatever reads it. The brief says so explicitly rather
  than hoping.

Install Pillow (`pip install 'urlscan-mcp[vision]'`) and full-page captures are
cropped to the part that matters and downscaled before they reach the model — a
1920×9000 capture goes out at roughly a fifth the bytes. Without Pillow the
image still goes out, unmodified, with a note saying so.

---

## Using it as a library, not just a server

The rules that make this server's output trustworthy — *no verdict data is not
a clean verdict*, and *only scans that landed on the indicator may lend it
their reputation* — are worth more than the transport around them. They live in
two modules that import no `mcp` and perform no I/O:

- `urlscan_mcp.query` — indicator classification and ElasticSearch query
  construction, including the `(page.X OR task.X)` redirector matching.
- `urlscan_mcp.assess` — `build_assessment()`, which turns shaped search hits
  into the same dictionary `assess_indicator` returns.

So an application with its own HTTP stack — its own cache, rate limiting and
failure isolation — can reach the same conclusions without either running a
subprocess or reimplementing the judgment:

```python
from urlscan_mcp import query, assess
from urlscan_mcp.shaping import summarize_search_hit

kind, q = query.classify("lzphy.top")
raw = my_http.get_json(f"https://urlscan.io/api/v1/search/?q={q}&size=100")
hits = [summarize_search_hit(h) for h in raw["results"]]

report = assess.build_assessment("lzphy.top", kind, hits, days=180)
```

[DEEP](https://github.com/blackhole8080-darkmatter/DEEP) consumes it exactly
this way, alongside running this server over stdio — the two paths share one
implementation of the analysis rather than drifting apart.

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

A live check is `python live_check.py [domain-or-url]` — it exercises what
offline tests cannot: real search reachability, whether `total` comes back so
the sampling note fires, real screenshot dimensions and byte sizes, and whether
the downscale thresholds suit real captures. No key needed for the search and
screenshot parts. It is itself covered by `tests/test_live_check.py`, which
drives it against a local stand-in — a script whose whole purpose is to be run
rarely, by hand, is the one most likely to have rotted by the time you run it.

77 offline tests — no network, no key required. They cover query escaping,
redirector matching (`page.*` vs `task.*`), input validation, auth degradation,
response shaping against malformed documents, and the assessment logic's
refusal to imply safety — including `build_assessment` directly, since
embedding applications depend on those guarantees too.

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

## Who built this

I build MCP servers and LLM agent integrations against real systems. If you have
an internal API your team would want to drive from Claude, Cursor, or any other
MCP client, that is a fixed-price, five-day job — aryan.kshir10@gmail.com.

Also: [DEEP](https://github.com/blackhole8080-darkmatter/DEEP), a local-first AI
assistant with a cybersecurity engine, MIT.

---

MIT. Not affiliated with urlscan.io.
