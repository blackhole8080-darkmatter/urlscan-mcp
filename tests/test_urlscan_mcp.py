"""Offline tests — no network, no API key required."""

from __future__ import annotations

import pytest

from urlscan_mcp import assess as a
from urlscan_mcp import query as q
from urlscan_mcp import server as s
from urlscan_mcp.client import UrlscanClient, UrlscanError
from urlscan_mcp.shaping import summarize_result, summarize_search_hit, truncate


# -- query construction ----------------------------------------------------


def test_escape_neutralises_query_syntax():
    assert q.escape("a:b") == r"a\:b"
    assert q.escape("evil AND page.domain") == r"evil AND page.domain"  # words are fine
    assert q.escape("a(b)c") == r"a\(b\)c"


def test_time_filter():
    assert q.time_filter(30) == " AND date:>now-30d"
    assert q.time_filter(0) == ""
    assert q.time_filter(None) == ""


@pytest.mark.parametrize(
    "value,kind",
    [
        ("example.com", "domain"),
        ("8.8.8.8", "ip"),
        ("2001:4860:4860::8888", "ip"),
        ("https://example.com/x", "url"),
        ("a" * 64, "hash"),
    ],
)
def test_classify(value, kind):
    result = q.classify(value)
    assert result is not None
    assert result[0] == kind


def test_classify_rejects_garbage():
    assert q.classify("!!!") is None
    assert q.classify("") is None


# -- redirect blind spot ---------------------------------------------------
# A domain that redirects away is recorded under task.domain but NOT under
# page.domain. Querying page.* alone reported "no scans found" for indicators
# that had in fact been scanned — the same class of error as reading a missing
# verdict as "clean". Verified live: page.domain:lzphy.top -> 0 hits,
# task.domain:lzphy.top -> 1 hit (the page redirected to github.com).


def test_domain_query_matches_submitted_and_final():
    query = q.submitted_or_final("domain", "lzphy.top")
    assert "page.domain:" in query
    assert "task.domain:" in query
    assert query.startswith("(") and query.endswith(")")
    assert " OR " in query


def test_classify_domain_covers_redirectors():
    kind, query = q.classify("lzphy.top")
    assert kind == "domain"
    assert "task.domain:lzphy.top" in query
    assert "page.domain:lzphy.top" in query


def test_classify_url_covers_redirectors():
    kind, query = q.classify("https://example.com/x")
    assert kind == "url"
    assert 'task.url:"https://example.com/x"' in query
    assert 'page.url:"https://example.com/x"' in query


# -- reputation must not leak from the redirect destination ----------------
# Matching task.* finds redirectors, but their page.* fields describe wherever
# the scan landed. Reading apex domain age / Umbrella rank off those credits
# the indicator with the destination's reputation — a throwaway .top domain
# inheriting github.com's 13-year age and rank 1508, which also suppressed the
# "no established traffic" risk signal. Manufacturing good reputation is worse
# than withholding a verdict.

_REDIRECTED = {"domain": "github.com", "apex_domain_age_days": 4887, "umbrella_rank": 1508}
_LANDED = {"domain": "lzphy.top", "apex_domain_age_days": 3, "umbrella_rank": None}


def test_partition_separates_redirected_scans():
    landed, redirected = a.partition_by_landing(
        "lzphy.top", "domain", [_LANDED, _REDIRECTED]
    )
    assert landed == [_LANDED]
    assert redirected == [_REDIRECTED]


def test_partition_counts_subdomains_as_landed():
    hit = {"domain": "tmdb.lzphy.top"}
    landed, redirected = a.partition_by_landing("lzphy.top", "domain", [hit])
    assert landed == [hit]
    assert redirected == []


def test_partition_is_case_insensitive():
    hit = {"domain": "LZPHY.TOP"}
    landed, _ = a.partition_by_landing("lzphy.top", "domain", [hit])
    assert landed == [hit]


def test_partition_does_not_match_suffix_lookalikes():
    """evil-lzphy.top must not count as landing on lzphy.top."""
    hit = {"domain": "evil-lzphy.top"}
    landed, redirected = a.partition_by_landing("lzphy.top", "domain", [hit])
    assert landed == []
    assert redirected == [hit]


def test_partition_passes_through_non_domain_lookups():
    hits = [_REDIRECTED]
    for kind in ("ip", "url", "hash"):
        landed, redirected = a.partition_by_landing("whatever", kind, hits)
        assert landed == hits
        assert redirected == []


def test_submitted_or_final_still_escapes_query_syntax():
    """Injected input cannot become a live field query.

    _escape deliberately leaves bare words (including AND/OR) alone — see
    test_escape_neutralises_query_syntax — so what matters is that the
    structural characters are neutralised: an attacker-supplied
    'page.domain:' must not survive as a field selector, and unbalanced
    parentheses must not break out of the clause.
    """
    query = q.submitted_or_final("domain", "evil.com) OR page.domain:(good.com")
    assert "page.domain\\:" in query  # colon escaped -> literal term, not a field
    assert "\\)" in query and "\\(" in query
    # exactly one live field selector per side, both of them ours
    assert query.count("page.domain:") == 1
    assert query.count("task.domain:") == 1
    # the clause stays balanced: one real opening and closing paren
    assert query.startswith("(") and query.endswith(")")


# -- validation ------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalid_ip_rejected_before_network():
    result = await s.search_by_ip("not-an-ip")
    assert "error" in result


@pytest.mark.asyncio
async def test_invalid_hash_rejected_before_network():
    result = await s.search_by_hash("abc")
    assert "error" in result


@pytest.mark.asyncio
async def test_invalid_asn_rejected_before_network():
    result = await s.search_by_asn("banana")
    assert "error" in result


@pytest.mark.asyncio
async def test_invalid_visibility_rejected():
    result = await s.scan_url("https://example.com", visibility="secret")
    assert "error" in result


@pytest.mark.asyncio
async def test_too_many_tags_rejected():
    result = await s.scan_url("https://example.com", tags=[f"t{i}" for i in range(11)])
    assert "error" in result


# -- auth degradation ------------------------------------------------------


def test_capabilities_without_key():
    caps = UrlscanClient(api_key="").capabilities()
    assert caps["search"] is True
    assert caps["submit_scans"] is False
    assert caps["read_results"] is False


def test_capabilities_with_key():
    caps = UrlscanClient(api_key="x").capabilities()
    assert caps["submit_scans"] is True
    assert caps["read_results"] is True
    assert caps["verdicts_in_results"] is True
    # Search hits carry no verdicts on any plan we can reach, key or not.
    assert caps["verdicts_in_search"] is False


def test_missing_key_message_is_actionable():
    client = UrlscanClient(api_key="")
    with pytest.raises(UrlscanError) as exc:
        client._headers(require_key=True, action="Submitting a scan")
    assert "URLSCAN_API_KEY" in str(exc.value)


# -- shaping ---------------------------------------------------------------


def test_truncate_marks_omission():
    out = truncate("x" * 100, 10)
    assert out.startswith("x" * 10)
    assert "truncated" in out


def test_summarize_result_tolerates_empty_document():
    summary = summarize_result({})
    assert summary["uuid"] is None
    assert summary["activity"]["total_requests"] == 0


def test_summarize_result_extracts_key_fields():
    doc = {
        "task": {"uuid": "u1", "url": "https://a.test/", "time": "2026-01-01T00:00:00Z"},
        "page": {"domain": "a.test", "ip": "1.2.3.4", "status": "200"},
        "stats": {"uniqCountries": 2},
        "lists": {"ips": ["1.2.3.4"], "domains": ["a.test", "b.test"]},
        "verdicts": {"overall": {"score": 80, "malicious": True}},
        "data": {"requests": [{}, {}], "cookies": [{}]},
    }
    summary = summarize_result(doc)
    assert summary["uuid"] == "u1"
    assert summary["verdict"]["malicious"] is True
    assert summary["activity"]["total_requests"] == 2
    assert summary["activity"]["unique_domains"] == 2


def test_summarize_search_hit_handles_absent_verdicts():
    hit = {"_id": "u2", "task": {"url": "https://b.test/"}, "page": {"domain": "b.test"}}
    row = summarize_search_hit(hit)
    assert row["uuid"] == "u2"
    # Absent verdicts must be None, never coerced into a "clean" value.
    assert row["verdict_score"] is None
    assert row["malicious"] is None


# -- assessment honesty ----------------------------------------------------


def test_risk_signals_flag_young_domain():
    signals = a.risk_signals(ages=[5], ranks=[1], tags=[], flagged=[], scores=[])
    assert any("young" in sig for sig in signals)


def test_risk_signals_flag_unranked_domain():
    signals = a.risk_signals(ages=[9000], ranks=[], tags=[], flagged=[], scores=[])
    assert any("Umbrella" in sig for sig in signals)


def test_assessment_never_claims_clean_without_verdicts():
    sentence = a.assessment_sentence(
        "domain", total=10, flagged=[], scores=[], verdicts_available=False,
        ages=[9000], ranks=[1000],
    )
    assert "says nothing about whether the indicator is malicious" in sentence


def test_assessment_flags_malicious_when_verdicts_present():
    sentence = a.assessment_sentence(
        "domain", total=10, flagged=[{}] * 6, scores=[90], verdicts_available=True,
        ages=[9000], ranks=[1000],
    )
    assert "Strong negative signal" in sentence


def test_assessment_downgrades_young_unranked_domain():
    sentence = a.assessment_sentence(
        "domain", total=3, flagged=[], scores=[], verdicts_available=True,
        ages=[4], ranks=[],
    )
    assert "unproven rather than benign" in sentence


def test_tally_orders_by_frequency():
    tallied = a.tally(["a", "b", "a", "a", "b", "c"])
    assert tallied[0] == {"value": "a", "count": 3}
    assert tallied[1] == {"value": "b", "count": 2}


# -- build_assessment: the contract embedding applications depend on ---------
#
# DEEP fetches urlscan through its own HTTP stack and calls build_assessment
# directly, so these guarantees are load-bearing outside this server too.


def _hit(**overrides):
    base = {
        "uuid": "u1",
        "url": "https://evil.test/",
        "domain": "evil.test",
        "country": "US",
        "asn_name": "EXAMPLE",
        "scanned_at": "2026-01-01T00:00:00Z",
        "tags": [],
        "apex_domain_age_days": 9000,
        "umbrella_rank": 1000,
        "verdict_score": None,
        "malicious": None,
    }
    base.update(overrides)
    return base


def test_build_assessment_reports_no_scans_without_implying_safety():
    out = a.build_assessment("evil.test", "domain", [], days=180)
    assert out["scans_found"] == 0
    assert "not evidence of safety" in " ".join(out["caveats"])
    assert "clean" not in out["assessment"].lower()


def test_build_assessment_marks_verdicts_unavailable_when_absent():
    out = a.build_assessment("evil.test", "domain", [_hit()], days=180)
    assert out["verdicts"]["available"] is False
    assert "does NOT mean the indicator is clean" in out["verdicts"]["note"]
    assert "flagged_malicious" not in out["verdicts"]


def test_build_assessment_reads_verdicts_when_present():
    out = a.build_assessment(
        "evil.test", "domain",
        [_hit(verdict_score=80, malicious=True), _hit(verdict_score=0, malicious=False)],
        days=180,
    )
    assert out["verdicts"]["available"] is True
    assert out["verdicts"]["flagged_malicious"] == 1
    assert out["verdicts"]["max_score"] == 80


def test_build_assessment_withholds_reputation_from_redirected_scans():
    """A redirector must not inherit its destination's age and rank."""
    redirected = _hit(domain="github.com", apex_domain_age_days=4700, umbrella_rank=1508)
    out = a.build_assessment("lzphy.top", "domain", [redirected], days=180)

    assert out["scans_landing_on_indicator"] == 0
    assert out["scans_redirected_away"] == 1
    assert out["redirect_destinations"][0]["value"] == "github.com"
    signals = out["reputation_signals"]
    assert signals["min_apex_domain_age_days"] is None
    assert signals["best_umbrella_rank"] is None
    assert signals["ranked_in_umbrella"] is False
    assert "NOT evidence of good standing" in signals["note"]


def test_build_assessment_attributes_reputation_to_landed_scans():
    landed = _hit(domain="sub.lzphy.top", apex_domain_age_days=6, umbrella_rank=None)
    out = a.build_assessment("lzphy.top", "domain", [landed], days=180)

    assert out["scans_landing_on_indicator"] == 1
    assert out["reputation_signals"]["min_apex_domain_age_days"] == 6
    assert any("very young" in s for s in out["risk_signals"])


def test_build_assessment_hash_lookup_has_no_window():
    out = a.build_assessment("a" * 64, "hash", [_hit()], days=180)
    assert out["window_days"] is None


# -- query helpers ----------------------------------------------------------


def test_ip_query_rejects_non_ip():
    with pytest.raises(ValueError):
        q.ip_query("not-an-ip")


def test_asn_query_normalises_and_rejects():
    assert q.asn_query("15169", days=0) == "page.asn:AS15169"
    assert q.asn_query("as15169", days=0) == "page.asn:AS15169"
    assert q.asn_query("nonsense") == ""


def test_domain_query_bounds_the_window():
    assert q.domain_query("example.com", 30).endswith(" AND date:>now-30d")
