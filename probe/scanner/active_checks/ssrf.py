"""Server-Side Request Forgery (SSRF) — high-precision, metadata-reflection based.

Black-box SSRF is noisy to prove without an out-of-band collector, so this check only
fires on strong evidence: a URL-like parameter is pointed at a cloud metadata / loopback
target, and the response comes back carrying an internal-metadata marker that was NOT in
the baseline — i.e. the server actually fetched the internal resource for us. That keeps
false positives near zero, in line with the rest of the suite.
"""

import re

from .common import finding, mutated, original_value

# Parameter names that commonly carry a URL the server will fetch.
_URLISH_NAMES = (
    "url", "uri", "link", "src", "dest", "destination", "redirect", "callback",
    "webhook", "fetch", "proxy", "image", "img", "load", "domain", "host", "site",
    "path", "continue", "return", "next", "target", "feed", "reference", "ref",
    "avatar", "download", "upload", "remote", "endpoint", "source", "data", "file",
)

# Internal targets whose content, if reflected, proves a server-side fetch.
_TARGETS = (
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://127.0.0.1/",
)

_MARKERS = re.compile(
    r"ami-id|instance-id|iam/security-credentials|computeMetadata|meta-data/|"
    r"local-hostname|instance-action|reservation-id",
    re.I,
)


def _is_urlish(parameter: str, value) -> bool:
    name = (parameter or "").lower()
    if any(key in name for key in _URLISH_NAMES):
        return True
    raw = original_value(value).lower()
    return raw.startswith(("http://", "https://", "//")) or "://" in raw


def check(context, parameter):
    if not _is_urlish(parameter, context.params.get(parameter)):
        return []
    baseline_text = ""
    if context.baseline is not None:
        baseline_text = context.baseline.text or ""
    if _MARKERS.search(baseline_text):
        return []  # the marker is always present — reflecting it proves nothing

    for target in _TARGETS:
        response = context.probe(mutated(context.params, parameter, target), module="ssrf")
        if response is None:
            continue
        match = _MARKERS.search(response.text or "")
        if match:
            return [finding(
                "Server-Side Request Forgery (SSRF)", "high", context.endpoint, parameter,
                target,
                f"Server fetched internal target {target}; the response carried an "
                f"internal-metadata marker '{match.group(0)}' that is absent from the "
                "baseline, proving the request was made server-side.",
                response,
            )]
    return []
