"""Offline tests — no network, no API key required."""

from __future__ import annotations

import pytest

from urlscan_mcp import server as s
from urlscan_mcp.client import UrlscanClient, UrlscanError
from urlscan_mcp.shaping import summarize_result, summarize_search_hit, truncate


# -- query construction ----------------------------------------------------


def test_escape_neutralises_query_syntax():
    assert s._escape("a:b") == r"a\:b"
    assert s._escape("evil AND page.domain") == r"evil AND page.domain"  # words are fine
    assert s._escape("a(b)c") == r"a\(b\)c"


def test_time_filter():
    assert s._time_filter(30) == " AND date:>now-30d"
    assert s._time_filter(0) == ""
    assert s._time_filter(None) == ""


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
    result = s._classify(value)
    assert result is not None
    assert result[0] == kind


def test_classify_rejects_garbage():
    assert s._classify("!!!") is None
    assert s._classify("") is None


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
    signals = s._risk_signals(ages=[5], ranks=[1], tags=[], flagged=[], scores=[])
    assert any("young" in sig for sig in signals)


def test_risk_signals_flag_unranked_domain():
    signals = s._risk_signals(ages=[9000], ranks=[], tags=[], flagged=[], scores=[])
    assert any("Umbrella" in sig for sig in signals)


def test_assessment_never_claims_clean_without_verdicts():
    sentence = s._assessment_sentence(
        "domain", total=10, flagged=[], scores=[], verdicts_available=False,
        ages=[9000], ranks=[1000],
    )
    assert "says nothing about whether the indicator is malicious" in sentence


def test_assessment_flags_malicious_when_verdicts_present():
    sentence = s._assessment_sentence(
        "domain", total=10, flagged=[{}] * 6, scores=[90], verdicts_available=True,
        ages=[9000], ranks=[1000],
    )
    assert "Strong negative signal" in sentence


def test_assessment_downgrades_young_unranked_domain():
    sentence = s._assessment_sentence(
        "domain", total=3, flagged=[], scores=[], verdicts_available=True,
        ages=[4], ranks=[],
    )
    assert "unproven rather than benign" in sentence


def test_tally_orders_by_frequency():
    tallied = s._tally(["a", "b", "a", "a", "b", "c"])
    assert tallied[0] == {"value": "a", "count": 3}
    assert tallied[1] == {"value": "b", "count": 2}
