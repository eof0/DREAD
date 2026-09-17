"""Infrastructure intel plugin's ASN lookup: previously a hard-coded no-op despite
being wired into the plugin registry and loading a local ASN database it never
consulted. Team Cymru's DNS-based IP-to-ASN service resolves the live announcing
ASN (a local snapshot can't track BGP announcements); the locally maintained
registry-allocation DB then enriches that ASN with country/RIR/status metadata.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from plugins import infrastructure_intel as ii
from plugins.infrastructure_intel import InfrastructureIntelPlugin


# -- _parse_cymru_asn: pure parsing, no network -------------------------------------

def test_parse_cymru_asn_extracts_first_field():
    txt = "13335 | 104.16.0.0/13 | US | arin | 2014-03-28"
    assert ii._parse_cymru_asn(txt) == "13335"


def test_parse_cymru_asn_rejects_non_numeric_field():
    assert ii._parse_cymru_asn("NA | 0.0.0.0/0 | | |") is None


def test_parse_cymru_asn_handles_empty_input():
    assert ii._parse_cymru_asn("") is None
    assert ii._parse_cymru_asn(None) is None


# -- _lookup_asn: live-lookup + local enrichment, network injected via monkeypatch --

def test_lookup_asn_merges_local_registry_metadata(monkeypatch):
    monkeypatch.setattr(ii, "_cymru_txt_query",
                        lambda query: "13335 | 104.16.0.0/13 | US | arin | 2014-03-28")
    asn_db = {"asns": {"13335": {"registry": "arin", "country": "US",
                                  "status": "allocated", "allocated": "20140328"}}}

    plugin = InfrastructureIntelPlugin()
    result = plugin._lookup_asn("104.16.1.1", asn_db)

    assert result["asn"] == "13335"
    assert result["registry"] == "arin"
    assert result["country"] == "US"


def test_lookup_asn_returns_asn_even_without_local_metadata(monkeypatch):
    monkeypatch.setattr(ii, "_cymru_txt_query", lambda query: "64512 | 1.2.3.0/24 | | |")
    plugin = InfrastructureIntelPlugin()

    result = plugin._lookup_asn("1.2.3.4", {"asns": {}})
    assert result == {"asn": "64512"}


def test_lookup_asn_returns_none_when_cymru_lookup_fails(monkeypatch):
    monkeypatch.setattr(ii, "_cymru_txt_query", lambda query: None)
    plugin = InfrastructureIntelPlugin()
    assert plugin._lookup_asn("8.8.8.8", {"asns": {}}) is None


def test_lookup_asn_skips_non_ipv4_without_querying(monkeypatch):
    called = []
    monkeypatch.setattr(ii, "_cymru_txt_query", lambda query: called.append(query) or None)
    plugin = InfrastructureIntelPlugin()

    assert plugin._lookup_asn("2001:db8::1", {"asns": {}}) is None
    assert called == []          # never even attempted a DNS query


def test_lookup_asn_queries_the_reversed_octet_cymru_hostname(monkeypatch):
    seen = {}

    def fake_query(query):
        seen["query"] = query
        return "15169 | 8.8.8.0/24 | US | arin | 2000-03-30"

    monkeypatch.setattr(ii, "_cymru_txt_query", fake_query)
    plugin = InfrastructureIntelPlugin()

    plugin._lookup_asn("8.8.8.8", {"asns": {}})
    assert seen["query"] == "8.8.8.8.origin.asn.cymru.com"


# -- scan(): the finding's evidence now actually carries ASN info -------------------

class _Resp:
    def __init__(self, headers=None):
        self.headers = headers or {}


class _Handler:
    def get(self, url, **kwargs):
        return _Resp({"Server": "nginx"})


def test_scan_includes_asn_in_finding_evidence(monkeypatch):
    monkeypatch.setattr(ii, "_cymru_txt_query",
                        lambda query: "13335 | 104.16.0.0/13 | US | arin | 2014-03-28")
    monkeypatch.setattr(InfrastructureIntelPlugin, "_resolve_ip", lambda self, host: "104.16.1.1")
    monkeypatch.setattr(InfrastructureIntelPlugin, "_load_asn_db",
                        lambda self: {"asns": {"13335": {"registry": "arin", "country": "US"}}})
    monkeypatch.setattr(InfrastructureIntelPlugin, "_reverse_dns", lambda self, ip: None)

    plugin = InfrastructureIntelPlugin()
    findings = plugin.scan({"url": "https://example.test/", "depth": 0}, _Handler())

    intel_finding = next(f for f in findings if f.title == "Infrastructure Intelligence")
    assert intel_finding.evidence["asn"]["asn"] == "13335"
    assert intel_finding.evidence["asn"]["registry"] == "arin"
