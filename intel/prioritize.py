"""Prioritization doctrine for CVE intelligence.

Pure functions — no database, no network — so the triage ordering can be unit
tested in isolation. The model ranks a CVE from three signals that already live
on the local store (see scanner.cve_db_manager): CISA KEV membership, FIRST EPSS
probability, and CVSS base score.

Doctrine (KEV-first, the standard vulnerability-management order):

  act_now    CISA lists it as exploited in the wild — patch immediately, no
             matter what EPSS or CVSS say.
  urgent     high modelled exploit probability (EPSS >= 0.5) or a critical CVSS.
  scheduled  elevated probability (EPSS >= 0.1) or a high CVSS.
  low        anything else we have a record for.
  unknown    no record / no scoring signal at all.

A CVE's tier is the MOST urgent signal it carries — a critical CVSS never pulls
a KEV entry down, and a KEV entry is never dragged down by a low EPSS.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

# Tiers, most urgent first. The integer is the urgency rank used for ordering.
ACT_NOW = "act_now"
URGENT = "urgent"
SCHEDULED = "scheduled"
LOW = "low"
UNKNOWN = "unknown"

_TIER_RANK = {ACT_NOW: 4, URGENT: 3, SCHEDULED: 2, LOW: 1, UNKNOWN: 0}

# EPSS probability is a 0..1 chance of exploitation in the next 30 days.
EPSS_HIGH = 0.5
EPSS_ELEVATED = 0.1

# CVSS base score bands (NVD): critical 9.0+, high 7.0+, medium 4.0+.
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0


@dataclass(frozen=True)
class Priority:
    """A CVE's computed triage priority."""

    tier: str
    rank: int  # _TIER_RANK[tier]; the higher, the more urgent.
    score: float  # continuous blended score, for ordering within a tier.
    reasons: tuple[str, ...]  # human-readable drivers, most important first.


def tier_rank(tier: str) -> int:
    """Urgency rank for a tier name (unknown tiers rank lowest)."""
    return _TIER_RANK.get(tier, 0)


def _epss_tier(epss: float | None) -> str | None:
    if epss is None:
        return None
    if epss >= EPSS_HIGH:
        return URGENT
    if epss >= EPSS_ELEVATED:
        return SCHEDULED
    return LOW


def _cvss_tier(cvss: float | None) -> str | None:
    if cvss is None or cvss <= 0:
        return None
    if cvss >= CVSS_CRITICAL:
        return URGENT
    if cvss >= CVSS_HIGH:
        return SCHEDULED
    return LOW


def prioritize(
    *,
    cvss: float | None = None,
    epss: float | None = None,
    epss_percentile: float | None = None,
    kev: bool = False,
    found: bool = True,
) -> Priority:
    """Compute the triage priority for one CVE from its scoring signals."""
    if not found:
        return Priority(UNKNOWN, _TIER_RANK[UNKNOWN], 0.0, ("no local record",))

    candidates: list[tuple[str, str]] = []  # (tier, reason)
    if kev:
        candidates.append((ACT_NOW, "CISA KEV: exploited in the wild"))
    et = _epss_tier(epss)
    if et is not None:
        candidates.append((et, f"EPSS {epss:.2f} exploit probability"))
    ct = _cvss_tier(cvss)
    if ct is not None:
        candidates.append((ct, f"CVSS {cvss:.1f} base score"))

    if not candidates:
        # We have the CVE but no CVSS, EPSS or KEV signal to grade it by.
        return Priority(LOW, _TIER_RANK[LOW], 0.0, ("record present, no scoring signal",))

    # Tier is the most urgent signal; reasons are ordered by that same urgency.
    candidates.sort(key=lambda c: _TIER_RANK[c[0]], reverse=True)
    tier = candidates[0][0]
    reasons = tuple(reason for _, reason in candidates)

    # Continuous score for stable ordering within a tier. KEV dominates, then
    # EPSS probability, then CVSS, then percentile as a fine tiebreak.
    score = (
        (1_000_000.0 if kev else 0.0)
        + (epss or 0.0) * 10_000.0
        + (cvss or 0.0) * 100.0
        + (epss_percentile or 0.0)
    )
    return Priority(tier, _TIER_RANK[tier], score, reasons)


def sort_key(priority: Priority, cve_id: str) -> tuple:
    """Ordering key: most urgent first, ties broken deterministically by id."""
    return (-priority.rank, -priority.score, cve_id)


def rank(items: Iterable[tuple[str, Priority]]) -> list[tuple[str, Priority]]:
    """Order (cve_id, Priority) pairs from most to least urgent."""
    return sorted(items, key=lambda pair: sort_key(pair[1], pair[0]))
