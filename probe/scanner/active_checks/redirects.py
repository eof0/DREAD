import re
import secrets

from .common import finding, mutated


def _redirect_vector(response, destination: str):
    """How (if at all) the response redirects to our unique destination."""
    if response is None:
        return None
    # 1. HTTP redirect: Location header points at our payload.
    if 300 <= response.status_code < 400 and response.headers.get("Location") == destination:
        return "Location header"

    body = response.text or ""
    if destination not in body:
        return None
    escaped = re.escape(destination)
    # 2. <meta http-equiv="refresh" content="0;url=PAYLOAD"> (a 200-status redirect).
    if re.search(rf'http-equiv=["\']?refresh["\']?[^>]*url=\s*["\']?{escaped}', body, re.I):
        return "meta refresh"
    # 3. JavaScript redirect: location(.href/.replace/.assign) = "PAYLOAD".
    if re.search(rf'(?:location(?:\.href|\.replace|\.assign)?\s*=\s*|location\.(?:replace|assign)\s*\(\s*)'
                 rf'["\']{escaped}', body, re.I):
        return "JavaScript location"
    return None


def check(context, parameter):
    destination = f"https://example.com/qa-redirect-{secrets.token_hex(4)}"
    response = context.probe(mutated(context.params, parameter, destination), module="redirect")
    vector = _redirect_vector(response, destination)
    if vector is None:
        return []
    return [finding(
        "Open Redirect", "medium", context.endpoint, parameter, destination,
        f"Redirects to attacker-controlled {destination} via {vector}", response,
    )]
