"""
Drive IDOR / BOLA checks for a single URL under a shared request budget.

Principal selection, strongest first:
  * a configured secondary identity  -> "secondary"
  * authenticated baseline, replay with no session -> "anonymous"
  * otherwise the same identity walks its own id space -> "self" (heuristic)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Callable, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from scanner.access_control.comparison import (
    direct_access_verdict,
    idor_verdict,
    summarize,
)
from scanner.access_control.identifiers import find_id_locations, mutation_values


@dataclass
class AccessControlContext:
    primary_get: Callable[[str], object]
    primary_authenticated: bool = False
    secondary_get: Optional[Callable[[str], object]] = None
    anonymous_get: Optional[Callable[[str], object]] = None
    per_location_mutations: int = 4
    budget: int = 150
    _used: int = field(default=0, init=False)
    _lock: Lock = field(default_factory=Lock, init=False)

    def take(self) -> bool:
        """Consume one unit of the shared request budget; False when exhausted."""
        with self._lock:
            if self._used >= self.budget:
                return False
            self._used += 1
            return True

    def principal(self):
        """(name, getter) for the weakest available principal to probe with."""
        if self.secondary_get is not None:
            return "secondary", self.secondary_get
        if self.primary_authenticated and self.anonymous_get is not None:
            return "anonymous", self.anonymous_get
        return "self", self.primary_get


def _merge_params(url: str, params) -> str:
    """Fold a separate ``params`` mapping into the URL's query string."""
    if not params:
        return url
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for name, value in params.items():
        if isinstance(value, (list, tuple)):
            pairs.extend((name, str(v)) for v in value)
        else:
            pairs.append((name, str(value)))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def _apply_mutation(url: str, location, new_value: str) -> str:
    """Return ``url`` with the identifier at ``location`` replaced by ``new_value``."""
    parsed = urlparse(url)
    if location.where == "query":
        pairs = [
            (name, new_value if name == location.name else value)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunparse(parsed._replace(query=urlencode(pairs)))

    segments = parsed.path.split("/")
    non_empty = [i for i, seg in enumerate(segments) if seg]
    if location.index is None or location.index >= len(non_empty):
        return url
    segments[non_empty[location.index]] = new_value
    return urlunparse(parsed._replace(path="/".join(segments)))


def scan_url_for_idor(
    ctx: AccessControlContext,
    url: str,
    params=None,
    harvested=None,
) -> List[dict]:
    """
    Run object-level authorization checks for a single URL.

    ``params`` (if given) is folded into the URL first, so identifier discovery,
    the baseline request and every mutation operate on one canonical URL.
    """
    findings: List[dict] = []

    url = _merge_params(url, params)
    locations = find_id_locations(url)
    if not locations or not ctx.take():
        return findings

    baseline = summarize(ctx.primary_get(url))
    if baseline is None or baseline.status != 200 or baseline.denied:
        return findings

    principal, get = ctx.principal()

    # Confirmed principals (a second identity, or an anonymous client) must be
    # tested against the authorized baseline object itself. Requesting a mutated
    # identifier instead would flag "the other user read their own record" as a
    # false positive.
    if principal in ("secondary", "anonymous"):
        if not ctx.take():
            return findings
        verdict = direct_access_verdict(
            baseline, summarize(get(url)), principal=principal
        )
        if verdict:
            first = locations[0]
            verdict.update(
                {
                    "url": url,
                    "tested_url": url,
                    "location": first.where,
                    "parameter": first.name,
                    "original_value": first.value,
                    "mutated_value": first.value,
                    "id_kind": first.kind,
                }
            )
            findings.append(verdict)
        return findings

    # Single-identity heuristic: walk the identifier space with the same
    # session. Cannot confirm cross-user access; reported as informational.
    for location in locations:
        for value in mutation_values(location, harvested)[: ctx.per_location_mutations]:
            if not ctx.take():
                return findings
            tested_url = _apply_mutation(url, location, value)
            if tested_url == url:
                continue
            verdict = idor_verdict(
                baseline, summarize(get(tested_url)), principal=principal
            )
            if verdict:
                verdict.update(
                    {
                        "url": url,
                        "tested_url": tested_url,
                        "location": location.where,
                        "parameter": location.name,
                        "original_value": location.value,
                        "mutated_value": value,
                        "id_kind": location.kind,
                    }
                )
                findings.append(verdict)
                break

    return findings
