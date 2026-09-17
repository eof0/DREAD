from __future__ import annotations

from scope.discovery import cloud_assets
from scope.discovery.cloud_assets import CloudDiscovery


class _FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


def test_find_s3_buckets_picks_one_match_per_bucket_in_pattern_order(monkeypatch) -> None:
    cd = CloudDiscovery()

    # example-com-assets exists (public) in eu-west-1 only; everything else 404s.
    def _fake_head(url: str, timeout: int = 5):
        if url == "https://example-com-assets.s3.eu-west-1.amazonaws.com":
            return _FakeResponse(200)
        if url == "https://example-com.s3.us-east-1.amazonaws.com":
            return _FakeResponse(403)
        return _FakeResponse(404)

    monkeypatch.setattr(cd.session, "head", _fake_head)

    found = cd._find_s3_buckets("example.com")
    buckets = {entry["bucket"]: entry for entry in found}

    assert buckets["example-com"]["public"] is False
    assert buckets["example-com"]["region"] == "us-east-1"
    assert buckets["example-com-assets"]["public"] is True
    assert buckets["example-com-assets"]["region"] == "eu-west-1"
    # Pattern order preserved: base name before "-assets".
    assert [e["bucket"] for e in found][:2] == ["example-com", "example-com-assets"]


def test_scan_aggregates_all_four_categories(monkeypatch) -> None:
    cd = CloudDiscovery()
    monkeypatch.setattr(cd, "_find_s3_buckets", lambda d: [{"bucket": "b"}])
    monkeypatch.setattr(cd, "_find_cloudfront", lambda d: [])
    monkeypatch.setattr(cd, "_find_azure_blobs", lambda d: [{"account": "a"}])
    monkeypatch.setattr(cd, "_find_gcs_buckets", lambda d: [])

    results = cd.scan("example.com")
    assert results == {
        "s3_buckets": [{"bucket": "b"}],
        "cloudfront": [],
        "azure_blob": [{"account": "a"}],
        "gcs": [],
    }


def test_find_cloudfront_flags_a_cname_pointed_at_cloudfront(monkeypatch) -> None:
    cd = CloudDiscovery()

    def fake_resolve(host: str):
        if host == "cdn.example.com":
            return "d111111abcdef8.cloudfront.net"
        return None

    monkeypatch.setattr(cloud_assets, "resolve_cname", fake_resolve)

    found = cd._find_cloudfront("example.com")
    assert found == [{"hostname": "cdn.example.com", "cname": "d111111abcdef8.cloudfront.net"}]


def test_find_cloudfront_ignores_cnames_to_other_services(monkeypatch) -> None:
    cd = CloudDiscovery()
    monkeypatch.setattr(cloud_assets, "resolve_cname",
                        lambda host: "somewhere.fastly.net" if host == "example.com" else None)

    assert cd._find_cloudfront("example.com") == []


def test_find_cloudfront_returns_empty_when_nothing_resolves(monkeypatch) -> None:
    cd = CloudDiscovery()
    monkeypatch.setattr(cloud_assets, "resolve_cname", lambda host: None)

    assert cd._find_cloudfront("example.com") == []
