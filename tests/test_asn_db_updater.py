from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

import scanner.asn_db_updater as m
import scanner.update_state as st


class _FakeResponse:
    def __init__(self, text: str, status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code
        self.headers: dict[str, str] = {}


def _fake_delegated_text(registry: str, asn: int, cc: str, value: int = 1) -> str:
    return (
        f"2.3|{registry}|3|20240101|18800|20240101|+0000\n"
        f"{registry}|*|asn|*|1|summary\n"
        f"{registry}|{cc}|asn|{asn}|{value}|20200101|allocated\n"
    )


def test_update_asn_db_merges_all_five_registries(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(st, "STATE_DIR", tmp_path / ".dread")
    monkeypatch.setattr(st, "STATE_PATH", tmp_path / ".dread" / "state.json")
    monkeypatch.setattr(m, "ASN_DB_PATH", str(tmp_path / "asn_db.json"))

    fixtures = {
        "ripencc": _fake_delegated_text("ripencc", 100, "DE"),
        "arin": _fake_delegated_text("arin", 200, "US"),
        "apnic": _fake_delegated_text("apnic", 300, "JP"),
        "lacnic": _fake_delegated_text("lacnic", 400, "BR"),
        "afrinic": _fake_delegated_text("afrinic", 500, "ZA"),
    }

    def _fake_get(url: str, timeout: int = 120):
        for registry, text in fixtures.items():
            if registry in url:
                return _FakeResponse(text)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(m.requests, "get", _fake_get)

    m.update_asn_db(verbose=False, force=True)

    with open(m.ASN_DB_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert set(data["metadata"]["sources"]) == set(m.ASN_SOURCES.values())
    registries = {entry["registry"] for entry in data["asns"].values()}
    assert registries == {"ripencc", "arin", "apnic", "lacnic", "afrinic"}
    assert data["asns"]["100"] == {
        "registry": "ripencc",
        "country": "DE",
        "status": "allocated",
        "allocated": "20200101",
    }
    assert data["asns"]["500"]["country"] == "ZA"


def test_update_asn_db_expands_multi_asn_allocation_blocks(tmp_path, monkeypatch) -> None:
    # 'value' in the RIR delegated format is a count of consecutive ASNs
    # starting at 'start', not a single ASN -- e.g. start=306 value=2 covers
    # ASNs 306 and 307, both of which must be recorded.
    monkeypatch.setattr(st, "STATE_DIR", tmp_path / ".dread")
    monkeypatch.setattr(st, "STATE_PATH", tmp_path / ".dread" / "state.json")
    monkeypatch.setattr(m, "ASN_DB_PATH", str(tmp_path / "asn_db.json"))

    fixtures = {name: _fake_delegated_text(name, 100, "XX") for name in m.ASN_SOURCES}
    fixtures["arin"] = _fake_delegated_text("arin", 306, "US", value=2)

    def _fake_get(url: str, timeout: int = 120):
        for registry, text in fixtures.items():
            if registry in url:
                return _FakeResponse(text)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(m.requests, "get", _fake_get)

    m.update_asn_db(verbose=False, force=True)

    with open(m.ASN_DB_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["asns"]["306"]["country"] == "US"
    assert data["asns"]["307"]["country"] == "US"


def test_identities_match_prefers_etag_over_stale_last_modified() -> None:
    # Matching Last-Modified shouldn't win over a real ETag mismatch --
    # Last-Modified can be coarse enough to stay equal across a real change.
    assert m._identities_match(
        old_lm="Mon, 01 Jan 2024 00:00:00 GMT",
        old_etag='"abc"',
        new_lm="Mon, 01 Jan 2024 00:00:00 GMT",
        new_etag='"xyz"',
    ) is False


def test_identities_match_falls_back_to_last_modified_without_etag() -> None:
    assert m._identities_match(
        old_lm="Mon, 01 Jan 2024 00:00:00 GMT",
        old_etag=None,
        new_lm="Mon, 01 Jan 2024 00:00:00 GMT",
        new_etag=None,
    ) is True


def test_update_asn_db_does_not_persist_identity_on_download_failure(tmp_path, monkeypatch) -> None:
    # A failure partway through the download loop must not leave state
    # believing an already-downloaded registry is "unchanged" next run --
    # the DB file was never written, so that would silently strand stale
    # data as trusted.
    monkeypatch.setattr(st, "STATE_DIR", tmp_path / ".dread")
    monkeypatch.setattr(st, "STATE_PATH", tmp_path / ".dread" / "state.json")
    monkeypatch.setattr(m, "ASN_DB_PATH", str(tmp_path / "asn_db.json"))

    def _fake_get(url: str, timeout: int = 120):
        if "ripencc" in url:
            resp = _FakeResponse(_fake_delegated_text("ripencc", 100, "DE"))
            resp.headers["ETag"] = '"ripencc-etag"'
            return resp
        raise RuntimeError("simulated network failure")

    monkeypatch.setattr(m.requests, "get", _fake_get)

    try:
        m.update_asn_db(verbose=False, force=True)
    except Exception:
        pass

    assert not Path(m.ASN_DB_PATH).exists()
    lm, etag = m._stored_source_identity("ripencc")
    assert lm is None and etag is None, "identity must not be persisted before a successful write"


def test_update_asn_db_does_not_persist_identity_when_file_write_fails(tmp_path, monkeypatch) -> None:
    # Every registry downloads successfully this time -- only the final
    # write to ASN_DB_PATH fails. Same requirement: no identity persisted,
    # since the data that identity would vouch for was never written.
    monkeypatch.setattr(st, "STATE_DIR", tmp_path / ".dread")
    monkeypatch.setattr(st, "STATE_PATH", tmp_path / ".dread" / "state.json")

    # A directory in place of the DB file path makes the write raise
    # IsADirectoryError -- a real write failure, no need to monkeypatch
    # open() directly.
    bad_path = tmp_path / "asn_db.json"
    bad_path.mkdir()
    monkeypatch.setattr(m, "ASN_DB_PATH", str(bad_path))

    fixtures = {name: _fake_delegated_text(name, i, "XX") for i, name in enumerate(m.ASN_SOURCES)}

    def _fake_get(url: str, timeout: int = 120):
        for registry, text in fixtures.items():
            if registry in url:
                resp = _FakeResponse(text)
                resp.headers["ETag"] = f'"{registry}-etag"'
                return resp
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(m.requests, "get", _fake_get)

    with pytest.raises(IsADirectoryError):
        m.update_asn_db(verbose=False, force=True)

    for registry in m.ASN_SOURCES:
        lm, etag = m._stored_source_identity(registry)
        assert lm is None and etag is None, f"{registry} identity must not persist when the write failed"


def test_update_asn_db_skips_download_when_all_sources_unchanged(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(st, "STATE_DIR", tmp_path / ".dread")
    monkeypatch.setattr(st, "STATE_PATH", tmp_path / ".dread" / "state.json")
    monkeypatch.setattr(m, "ASN_DB_PATH", str(tmp_path / "asn_db.json"))

    fixtures = {name: _fake_delegated_text(name, i, "XX") for i, name in enumerate(m.ASN_SOURCES)}
    calls = {"get": 0}

    def _fake_get(url: str, timeout: int = 120):
        calls["get"] += 1
        for registry, text in fixtures.items():
            if registry in url:
                resp = _FakeResponse(text)
                resp.headers["ETag"] = f'"{registry}-etag"'
                return resp
        raise AssertionError(f"unexpected URL: {url}")

    def _fake_head(url: str, timeout=30, allow_redirects=True, headers=None):
        for registry in fixtures:
            if registry in url:
                resp = _FakeResponse("")
                resp.headers["ETag"] = f'"{registry}-etag"'
                return resp
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(m.requests, "get", _fake_get)
    monkeypatch.setattr(m.requests, "head", _fake_head)

    m.update_asn_db(verbose=False, force=True)
    assert calls["get"] == 5

    # Force past the age-based "up to date" short-circuit so the per-source
    # identity check (the thing this test actually exercises) runs again.
    st.set_state_timestamp("asn", "last_updated", "2000-01-01T00:00:00.000")

    m.update_asn_db(verbose=False, force=False)
    assert calls["get"] == 5, "unchanged ETags should skip re-downloading every source"
