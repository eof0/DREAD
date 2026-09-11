"""
Boolean-based (blind) SQL injection.

Some SQLi never surfaces a database error. Here we send a condition that is always
TRUE and one that is always FALSE and compare the responses: if the TRUE response
looks like the normal page while the FALSE response clearly differs, the parameter
is being evaluated inside a SQL query. Uses response similarity, and only fires
when TRUE ~= baseline and FALSE clearly diverges, to avoid flapping pages.
"""

from difflib import SequenceMatcher

from .common import finding, mutated

# (true-condition, false-condition) pairs across quoting styles.
_PAYLOAD_PAIRS = (
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
    (" AND 1=1", " AND 1=2"),
    (" AND 1=1-- -", " AND 1=2-- -"),
)

_TRUE_MIN = 0.95   # TRUE response must closely match the normal page
_FALSE_MAX = 0.90  # FALSE response must clearly diverge from it


def _ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a or "", b or "").ratio()


def check(context, parameter):
    original = str(context.params.get(parameter, ""))
    baseline_text = context.baseline.text if context.baseline is not None else ""
    if not baseline_text:
        return []

    for true_cond, false_cond in _PAYLOAD_PAIRS:
        true_resp = context.probe(
            mutated(context.params, parameter, original + true_cond), module="sqli-bool")
        false_resp = context.probe(
            mutated(context.params, parameter, original + false_cond), module="sqli-bool")
        if true_resp is None or false_resp is None:
            continue

        true_ratio = _ratio(baseline_text, true_resp.text)
        false_ratio = _ratio(baseline_text, false_resp.text)
        # TRUE tracks the normal page, FALSE departs from both baseline and TRUE.
        if (
            true_ratio >= _TRUE_MIN
            and false_ratio <= _FALSE_MAX
            and _ratio(true_resp.text, false_resp.text) <= _FALSE_MAX
        ):
            return [finding(
                "SQL Injection (boolean-based blind)", "high", context.endpoint, parameter,
                original + true_cond,
                f"TRUE and FALSE conditions produced different responses "
                f"(true~baseline={true_ratio:.2f}, false~baseline={false_ratio:.2f})",
                true_resp,
                evidence_payload="boolean condition payload",
            )]
    return []
