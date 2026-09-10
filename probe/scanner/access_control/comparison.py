"""
Classify a response and decide whether a mutated-identifier request looks like
successful cross-object access.

The signal we trust: a principal that should NOT be able to see object *B*
requested object *B* by its identifier and got back a 200 that is
structurally the same kind of object as the baseline but with different
content, and no access-denied / not-found markers.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Optional

_DENIED_RE = re.compile(
    r"(access denied|not authoriz|unauthori[sz]ed|permission denied|forbidden|"
    r"you (?:do not|don't) have (?:permission|access)|please log ?in|sign in to "
    r"continue|login required|must be logged in|authentication required)",
    re.I,
)
_NOTFOUND_RE = re.compile(
    r"(not found|no such|does not exist|resource is unavailable|deleted or moved)",
    re.I,
)

# Principal that issued the mutated request, ordered by how strong a positive is.
PRINCIPAL_SEVERITY = {
    "anonymous": "high",   # authed baseline, mutated request had no session at all
    "secondary": "high",   # a different real user saw the first user's object
    "self": "low",         # single identity walked its own id space (cannot confirm)
}


@dataclass
class ResponseFacts:
    status: int
    length: int
    is_json: bool
    body_hash: str
    shape: str
    denied: bool
    notfound: bool
    sample: str


def _json_shape(text: str) -> Optional[str]:
    """Structural signature of a JSON body (key names + value types, no values)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None

    def walk(node, depth=0):
        if depth > 6:
            return "…"
        if isinstance(node, dict):
            return "{" + ",".join(f"{k}:{walk(node[k], depth + 1)}" for k in sorted(node)) + "}"
        if isinstance(node, list):
            return "[" + (walk(node[0], depth + 1) if node else "") + "]"
        return type(node).__name__

    return "json:" + walk(data)


def _html_shape(text: str) -> str:
    """Hash of the opening-tag sequence — a cheap structural fingerprint for HTML."""
    tags = re.findall(r"<([a-zA-Z][a-zA-Z0-9]*)", text or "")
    skeleton = ">".join(tag.lower() for tag in tags[:120])
    return "html:" + hashlib.sha1(skeleton.encode("utf-8", "ignore")).hexdigest()


def summarize(response) -> Optional[ResponseFacts]:
    """Reduce an HTTP response to the facts the verdict functions compare."""
    if response is None:
        return None
    text = response.text or ""
    ctype = str(response.headers.get("Content-Type", "")).lower()
    is_json = "json" in ctype or text[:1] in ("{", "[")
    shape = _json_shape(text) if is_json else None
    if shape is None:
        shape = _html_shape(text)
        is_json = False
    return ResponseFacts(
        status=response.status_code,
        length=len(text),
        is_json=is_json,
        body_hash=hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest(),
        shape=shape,
        denied=response.status_code in (401, 403) or bool(_DENIED_RE.search(text[:4000])),
        notfound=response.status_code == 404 or bool(_NOTFOUND_RE.search(text[:2000])),
        sample=text[:300],
    )


def idor_verdict(
    baseline: Optional[ResponseFacts],
    mutated: Optional[ResponseFacts],
    *,
    principal: str,
) -> Optional[dict]:
    """
    Weak signal for the single-identity heuristic: the same session got a
    different-but-same-shaped object for a mutated identifier. Cannot prove
    cross-user access, so callers report it as informational only.
    """
    if baseline is None or mutated is None:
        return None
    if baseline.status != 200 or baseline.denied:
        return None
    if mutated.status != 200 or mutated.denied or mutated.notfound:
        return None
    if mutated.shape != baseline.shape:
        return None
    if mutated.body_hash == baseline.body_hash:
        return None
    if mutated.length == 0:
        return None
    # Guard against "every id returns the same soft-error page" — a soft error
    # would usually trip notfound/denied or differ in shape; if it slips through,
    # a near-identical length with different hash is still suspicious enough to
    # report at reduced confidence via the principal mapping.
    return {
        "severity": PRINCIPAL_SEVERITY.get(principal, "medium"),
        "principal": principal,
        "baseline_shape": baseline.shape[:80],
        "mutated_status": mutated.status,
        "mutated_length": mutated.length,
        "mutated_sample": mutated.sample,
    }


def direct_access_verdict(
    baseline: Optional[ResponseFacts],
    weaker: Optional[ResponseFacts],
    *,
    principal: str,
) -> Optional[dict]:
    """
    Decide whether a weaker principal (a second identity, or an anonymous
    client) could read the *authorized baseline object itself*.

    This is the only sound confirmation of IDOR: the baseline is the primary
    identity's object at its own URL, and ``weaker`` is the response the lower
    -privilege principal got for that same URL. A different-object comparison
    (mutated identifier) cannot distinguish "read someone else's record" from
    "read my own record", so it is not used here.
    """
    if baseline is None or weaker is None:
        return None
    if baseline.status != 200 or baseline.denied:
        return None
    if weaker.status != 200 or weaker.denied or weaker.notfound:
        return None
    if weaker.shape != baseline.shape or baseline.length == 0:
        return None

    identical = weaker.body_hash == baseline.body_hash
    near = (
        baseline.length > 50
        and abs(weaker.length - baseline.length) <= 0.1 * baseline.length
    )
    if not (identical or near):
        return None

    return {
        "severity": PRINCIPAL_SEVERITY.get(principal, "medium"),
        "principal": principal,
        "baseline_shape": baseline.shape[:80],
        "match": "identical" if identical else "near-identical",
        "mutated_status": weaker.status,
        "mutated_length": weaker.length,
        "mutated_sample": weaker.sample,
    }
