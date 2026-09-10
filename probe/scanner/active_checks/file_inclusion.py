from .common import finding, mutated


PAYLOADS = (
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vdDp4"),
    ("file:///etc/passwd", "root:x:0:0"),
)


def check(context, parameter):
    baseline = context.baseline.text.lower()
    for payload, signature in PAYLOADS:
        response = context.probe(mutated(context.params, parameter, payload), module="file-inclusion")
        if (
            response is not None
            and signature.lower() not in baseline
            and signature.lower() in response.text.lower()
        ):
            return [finding(
                "Local File Inclusion", "high", context.endpoint, parameter, payload,
                f"Local file signature found: {signature}", response,
                evidence_payload="local file signature payload",
            )]
    return []
