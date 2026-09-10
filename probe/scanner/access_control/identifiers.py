"""
Find object-reference identifiers in a URL and propose safe mutations.

Only read-style identifiers are considered (query params and path segments).
Bare numbers that are obviously pagination/sizing knobs are ignored so the
IDOR engine does not waste budget walking ``?page=2``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlparse

_NUMERIC_RE = re.compile(r"\d{1,15}")
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
_OID_RE = re.compile(r"[0-9a-f]{24}", re.I)

# Query-param names that read as an object handle.
_ID_NAME_RE = re.compile(
    r"(?:^|[_-])(id|uid|guid|uuid|user|username|account|acct|customer|client|member|"
    r"order|invoice|payment|doc|document|file|attachment|record|profile|group|team|"
    r"org|organization|project|ticket|issue|node|page_id|post|comment|message|thread|"
    r"session|token|ref|key|pid|oid|gid|cid)s?$",
    re.I,
)

# Bare numbers with these names are controls, not object references.
_PAGINATION_NAMES = {
    "page", "per_page", "perpage", "limit", "offset", "count", "size", "p",
    "start", "end", "from", "to", "year", "month", "day", "page_size",
    "pagesize", "rows", "top", "skip", "index", "step", "n",
}

_MAX_MUTATIONS = 6


@dataclass(frozen=True)
class IdLocation:
    where: str            # "query" | "path"
    name: str             # param name, or "<resource>[<index>]" for a path segment
    value: str
    kind: str             # "numeric" | "uuid" | "oid"
    index: Optional[int] = None   # path-segment index when where == "path"


def classify_value(value: str) -> Optional[str]:
    """Return "numeric" | "uuid" | "oid" for id-shaped values, else None."""
    value = str(value).strip()
    if _UUID_RE.fullmatch(value):
        return "uuid"
    if _OID_RE.fullmatch(value):
        return "oid"
    if value.isdigit() and 1 <= len(value) <= 15:
        return "numeric"
    return None


def _query_pairs(url: str, params) -> List[Tuple[str, str]]:
    """(name, value) pairs from an explicit params mapping, or the URL's query."""
    if params:
        pairs: List[Tuple[str, str]] = []
        for name, value in params.items():
            if isinstance(value, (list, tuple)):
                pairs.extend((name, str(v)) for v in value)
            else:
                pairs.append((name, str(value)))
        return pairs
    return [
        (n, v)
        for n, v in parse_qsl(urlparse(url).query, keep_blank_values=True)
    ]


def find_id_locations(url: str, params=None) -> List[IdLocation]:
    """Object-reference identifiers in a URL's query params and path segments."""
    locations: List[IdLocation] = []

    for name, value in _query_pairs(url, params):
        kind = classify_value(value)
        if kind is None:
            continue
        if kind == "numeric":
            lname = name.lower()
            if lname in _PAGINATION_NAMES:
                continue
            if not _ID_NAME_RE.search(name) and lname not in {"id"}:
                # numeric value on a non-identity-looking name: skip to stay quiet
                continue
        locations.append(IdLocation("query", name, str(value), kind))

    segments = [s for s in urlparse(url).path.split("/") if s]
    for i, segment in enumerate(segments):
        kind = classify_value(segment)
        if kind is None:
            continue
        resource = segments[i - 1] if i > 0 else "path"
        locations.append(
            IdLocation("path", f"{resource}[{i}]", segment, kind, index=i)
        )

    return locations


def mutation_values(
    location: IdLocation, harvested: Optional[Iterable[str]] = None
) -> List[str]:
    """Concrete replacement values to try for a location, most useful first."""
    candidates: List[str] = []

    if location.kind == "numeric":
        n = int(location.value)
        for delta in (-1, 1, -2, 2):
            candidate = n + delta
            if candidate >= 0 and candidate != n:
                candidates.append(str(candidate))

    # Real identifiers harvested from the crawl beat blind low-number guesses.
    for token in harvested or []:
        token = str(token)
        if token != location.value and classify_value(token) == location.kind:
            candidates.append(token)

    if location.kind == "numeric":
        candidates.extend(low for low in ("1", "2") if low != location.value)

    seen = set()
    ordered: List[str] = []
    for value in candidates:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered[:_MAX_MUTATIONS]


def harvest_identifiers(text: str, kinds: Sequence[str] = ("numeric", "uuid", "oid")) -> List[str]:
    """Pull id-shaped tokens out of page text (other objects' handles)."""
    found: List[str] = []
    if "uuid" in kinds:
        found.extend(m.group(0) for m in _UUID_RE.finditer(text or ""))
    if "oid" in kinds:
        found.extend(m.group(0) for m in _OID_RE.finditer(text or ""))
    if "numeric" in kinds:
        for m in re.finditer(r"/(\d{1,15})(?=[/?\"'#]|$)", text or ""):
            found.append(m.group(1))
    seen = set()
    ordered = []
    for token in found:
        if token not in seen:
            seen.add(token)
            ordered.append(token)
    return ordered[:25]
