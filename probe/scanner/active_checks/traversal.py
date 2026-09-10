from .common import finding, mutated


PAYLOADS = (
    ("../../../../../../etc/passwd", "root:x:0:0"),
    (r"..\..\..\..\windows\win.ini", "[fonts]"),
)


def check(context, parameter):
    baseline = context.baseline.text.lower()
    for payload, signature in PAYLOADS:
        response = context.probe(mutated(context.params, parameter, payload), module="traversal")
        if (
            response is not None
            and signature.lower() not in baseline
            and signature.lower() in response.text.lower()
        ):
            return [finding(
                "Path Traversal", "high", context.endpoint, parameter, payload,
                f"File signature found: {signature}", response,
            )]
    return []
