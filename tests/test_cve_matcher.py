from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner.cve_matcher import (
    extract_cve_info,
    match_technology_to_cve,
    version_in_range,
)


def test_version_in_range_numeric_comparison_across_digit_widths() -> None:
    # "2.4.9" sorts after "2.4.10" as plain strings, but 2.4.9 is
    # numerically inside [2.4.2, 2.4.10].
    assert version_in_range("2.4.9", "2.4.2", "2.4.10") is True
    # 2.4.10 is numerically past a range that ends at 2.4.9.
    assert version_in_range("2.4.10", "2.4.2", "2.4.9") is False


def test_version_in_range_respects_exclusive_bounds() -> None:
    assert version_in_range("2.4.49", "2.4.0", "2.4.50", max_inclusive=False) is True
    assert version_in_range("2.4.50", "2.4.0", "2.4.50", max_inclusive=False) is False
    assert version_in_range("2.4.50", "2.4.0", "2.4.50", max_inclusive=True) is True
    # Same check on the lower bound: versionStartExcluding means the
    # boundary version itself is NOT affected, only versions after it.
    assert version_in_range("2.4.0", "2.4.0", "2.4.50", min_inclusive=False) is False
    assert version_in_range("2.4.1", "2.4.0", "2.4.50", min_inclusive=False) is True


def test_version_in_range_unparseable_bound_declines_match() -> None:
    # A declared bound that can't be parsed at all must not be silently
    # treated as unbounded - that would let versions outside the real
    # (but malformed) range through as false positives.
    assert version_in_range("2.4.9", "not-a-version", "2.4.10") is False
    assert version_in_range("2.4.9", "2.4.0", "not-a-version") is False


def test_version_in_range_tolerates_distro_suffixed_versions() -> None:
    # Debian/Ubuntu-style package versions aren't valid PEP 440 and used to
    # make packaging.version.parse raise; that used to fall back to
    # "return True" unconditionally for any real range, flooding results
    # with false positives for very common real-world version strings.
    assert version_in_range("2.4.41-1ubuntu1", "2.4.0", "2.4.49") is True
    assert version_in_range("2.4.41-1ubuntu1", "2.4.42", "2.4.49") is False


def test_version_in_range_unparseable_version_does_not_match_bounded_range() -> None:
    assert version_in_range("not-a-version", "1.0", "2.0") is False
    # No constraints at all still matches regardless of detected version.
    assert version_in_range("not-a-version", None, None) is True


def test_version_in_range_no_detected_version_only_matches_unconstrained_cve() -> None:
    assert version_in_range("", "1.0", "2.0") is False
    assert version_in_range("", None, None) is True


def test_extract_cve_info_uses_excluding_bound_as_exclusive() -> None:
    cve_entry = {
        "raw": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:apache_http_server:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "2.4.0",
                                "versionEndExcluding": "2.4.50",
                            }
                        ]
                    }
                ]
            }
        ]
    }
    products = extract_cve_info(cve_entry)
    assert len(products) == 1
    assert products[0]["min_version"] == "2.4.0"
    assert products[0]["max_version"] == "2.4.50"
    assert products[0]["max_inclusive"] is False


def test_match_technology_to_cve_respects_exclusive_end_boundary() -> None:
    cve_entry = {
        "raw": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:apache_http_server:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "2.4.0",
                                "versionEndExcluding": "2.4.50",
                            }
                        ]
                    }
                ]
            }
        ]
    }
    assert match_technology_to_cve("apache", "2.4.49", cve_entry) is not None
    assert match_technology_to_cve("apache", "2.4.50", cve_entry) is None
