import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.active_checks.context import ActiveScanContext


def test_context_rejects_budget_exhaustion():
    calls = []
    context = ActiveScanContext(
        "https://example.test/",
        ("https", "example.test", 443),
        None,
        {"q": "x"},
        lambda **kwargs: calls.append(kwargs) or object(),
        endpoint_budget=1,
    )

    assert context.probe({"q": "one"}, module="xss") is not None
    assert context.probe({"q": "two"}, module="xss") is None
    assert len(calls) == 1


def test_context_deduplicates_same_probe():
    context = ActiveScanContext(
        "https://example.test/",
        ("https", "example.test", 443),
        None,
        {"q": "x"},
        lambda **_kwargs: object(),
    )

    assert context.probe({"q": "one"}, module="xss") is not None
    assert context.probe({"q": "one"}, module="xss") is None


def test_context_tracks_origin_budget_across_endpoints():
    first = ActiveScanContext(
        "https://example.test/a",
        ("https", "example.test", 443),
        None,
        {},
        lambda **_kwargs: object(),
        origin_budget=1,
    )
    second = ActiveScanContext(
        "https://example.test/b",
        ("https", "example.test", 443),
        None,
        {},
        lambda **_kwargs: object(),
        origin_budget=1,
        origin_state=first.origin_state,
    )

    assert first.probe({}, module="xss") is not None
    assert second.probe({}, module="sql") is None
