import json
import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from plugins.access_control import AccessControlPlugin
from scanner.access_control.comparison import idor_verdict, summarize
from scanner.access_control.engine import AccessControlContext, scan_url_for_idor
from scanner.access_control.identifiers import (
    classify_value,
    find_id_locations,
    harvest_identifiers,
    mutation_values,
)

UUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
OID = "507f1f77bcf86cd799439011"


class Resp:
    def __init__(self, status=200, body="", ctype="application/json"):
        self.status_code = status
        self.text = body
        self.headers = {"Content-Type": ctype}


# --- identifiers -------------------------------------------------------------

def test_classify_value():
    assert classify_value("42") == "numeric"
    assert classify_value(UUID) == "uuid"
    assert classify_value(OID) == "oid"
    assert classify_value("not-an-id") is None
    assert classify_value("1234567890123456789012") is None


def test_find_id_locations_skips_pagination_keeps_identifiers():
    locs = find_id_locations("https://x.test/api/users/42?page=2&user_id=7&limit=10&id=9")
    names = {(l.where, l.name, l.value) for l in locs}

    assert ("query", "user_id", "7") in names
    assert ("query", "id", "9") in names
    assert ("path", "users[2]", "42") in names
    assert not any(l.name == "page" for l in locs)
    assert not any(l.name == "limit" for l in locs)


def test_mutation_values_numeric_and_harvested():
    loc = find_id_locations("https://x.test/?id=42")[0]
    values = mutation_values(loc, harvested=["99", "42", UUID])

    assert values[:4] == ["41", "43", "40", "44"]
    assert "99" in values
    assert "42" not in values
    assert len(values) <= 6


def test_harvest_identifiers_pulls_paths_and_uuids():
    text = f'<a href="/users/17">x</a> <a href="/orders/5001">y</a> token={UUID}'
    harvested = harvest_identifiers(text)

    assert "17" in harvested
    assert "5001" in harvested
    assert UUID in harvested


# --- comparison ------------------------------------------------------------

def test_summarize_json_shape_matches_for_same_structure():
    a = summarize(Resp(200, json.dumps({"id": 1, "name": "alice"})))
    b = summarize(Resp(200, json.dumps({"id": 2, "name": "bob"})))

    assert a.is_json and a.shape == b.shape
    assert a.body_hash != b.body_hash


def test_idor_verdict_positive_for_secondary_principal():
    base = summarize(Resp(200, json.dumps({"id": 1, "name": "alice"})))
    other = summarize(Resp(200, json.dumps({"id": 2, "name": "bob"})))

    verdict = idor_verdict(base, other, principal="secondary")
    assert verdict["severity"] == "high"

    assert idor_verdict(base, other, principal="self")["severity"] == "low"


def test_idor_verdict_negative_cases():
    base = summarize(Resp(200, json.dumps({"id": 1, "name": "alice"})))

    assert idor_verdict(base, summarize(Resp(403, "denied")), principal="secondary") is None
    assert idor_verdict(base, summarize(Resp(404, "not found")), principal="secondary") is None
    assert idor_verdict(base, base, principal="secondary") is None  # identical body
    assert (
        idor_verdict(base, summarize(Resp(200, "<html><body>x</body></html>", "text/html")), principal="secondary")
        is None  # different shape
    )
    denied_body = json.dumps({"id": 2, "name": "bob", "note": "access denied"})
    assert idor_verdict(base, summarize(Resp(200, denied_body)), principal="secondary") is None


# --- engine --------------------------------------------------------------

def _object_router(owner_body, other_body):
    def get(url):
        if "id=5" in url or url.rstrip("/").endswith("/5"):
            return Resp(200, owner_body)
        return Resp(200, other_body)
    return get


def test_scan_url_for_idor_flags_secondary_reading_primary_object():
    # The secondary identity requests the primary's own baseline URL and gets
    # back the primary's object -> confirmed IDOR.
    owner = json.dumps({"id": 5, "email": "me@x.test"})
    other = json.dumps({"id": 4, "email": "victim@x.test"})
    ctx = AccessControlContext(
        primary_get=_object_router(owner, other),
        secondary_get=_object_router(owner, other),
    )

    results = scan_url_for_idor(ctx, "https://x.test/api/account?id=5")

    assert len(results) == 1
    assert results[0]["parameter"] == "id"
    assert results[0]["principal"] == "secondary"
    assert results[0]["severity"] == "high"


def test_secondary_own_object_is_not_a_finding():
    # If the weaker principal is denied the primary's baseline object, there is
    # no IDOR — even though a mutated identifier would have returned a 200.
    owner = json.dumps({"id": 5, "email": "me@x.test"})

    def primary(url):
        return Resp(200, owner)

    def secondary(url):
        return Resp(403, json.dumps({"error": "forbidden"}))

    ctx = AccessControlContext(primary_get=primary, secondary_get=secondary)

    assert scan_url_for_idor(ctx, "https://x.test/api/account?id=5") == []


def test_scan_url_for_idor_merges_separate_params():
    owner = json.dumps({"id": 5, "email": "me@x.test"})
    ctx = AccessControlContext(
        primary_get=lambda url: Resp(200, owner),
        secondary_get=lambda url: Resp(200, owner),
    )

    results = scan_url_for_idor(
        ctx, "https://x.test/api/account", params={"id": "5"}
    )

    assert len(results) == 1
    assert results[0]["principal"] == "secondary"


def test_scan_url_for_idor_respects_budget():
    ctx = AccessControlContext(
        primary_get=lambda url: Resp(200, "{}"),
        secondary_get=lambda url: Resp(200, '{"x":1}'),
        budget=1,
    )
    assert scan_url_for_idor(ctx, "https://x.test/api/account?id=5") == []


def test_scan_url_for_idor_anonymous_principal_when_authenticated():
    owner = json.dumps({"id": 5, "name": "me"})
    other = json.dumps({"id": 4, "name": "someone"})
    ctx = AccessControlContext(
        primary_get=_object_router(owner, other),
        primary_authenticated=True,
        anonymous_get=_object_router(owner, other),
    )

    results = scan_url_for_idor(ctx, "https://x.test/api/account?id=5")

    assert results and results[0]["principal"] == "anonymous"


# --- plugin --------------------------------------------------------------

class FakeHandler:
    def __init__(self, router, secondary=None, authenticated=False):
        self._router = router
        self.secondary = secondary
        self.authenticated = authenticated
        self.rate_limit = 1.0
        self.verbose = False

    def get(self, url, **kwargs):
        return self._router(url)


def test_plugin_reports_confirmed_idor_with_secondary_identity():
    owner = json.dumps({"id": 10, "ssn": "111"})
    other = json.dumps({"id": 9, "ssn": "222"})
    router = _object_router(owner, other)

    def id10_router(url):
        return Resp(200, owner) if "id=10" in url else Resp(200, other)

    handler = FakeHandler(id10_router, secondary=FakeHandler(id10_router))
    findings = AccessControlPlugin().scan(
        {"url": "https://x.test/api/profile?id=10"}, handler
    )

    assert len(findings) == 1
    assert findings[0].plugin_name == "access_control"
    assert findings[0].severity == "high"
    assert findings[0].metadata.get("classification") != "warning"


def test_plugin_self_mode_is_informational_only():
    def id3_router(url):
        return Resp(200, json.dumps({"id": 3})) if "id=3" in url else Resp(200, json.dumps({"id": 2}))

    handler = FakeHandler(id3_router)
    findings = AccessControlPlugin().scan(
        {"url": "https://x.test/post?id=3"}, handler
    )

    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].metadata.get("classification") == "warning"


def test_plugin_noop_without_identifiers():
    handler = FakeHandler(lambda url: Resp(200, "{}"))
    assert AccessControlPlugin().scan({"url": "https://x.test/about"}, handler) == []
