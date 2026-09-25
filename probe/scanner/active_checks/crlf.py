import secrets

from .common import finding, mutated, original_value


def _injected_header(response, header_name: str, marker: str):
    """Proof of injection: the exact header the probe asked for, carrying our
    random marker, actually came back in the response. A random marker in both
    the name and the value means a hit can only be our own injection reflected
    out of a response header -- never a coincidental pre-existing header, so no
    baseline comparison is needed."""
    if response is None:
        return None
    value = response.headers.get(header_name)
    if value is not None and marker in value:
        return header_name
    # Some stacks fold the split into Set-Cookie rather than emitting the raw
    # header name; catch that too, still keyed on the unguessable marker.
    cookie = response.headers.get("Set-Cookie")
    if cookie is not None and marker in cookie:
        return "Set-Cookie"
    return None


def check(context, parameter):
    marker = secrets.token_hex(6)
    header_name = f"X-Crlf-{marker}"
    # Keep the parameter's original value as the prefix so a required/typed
    # parameter still routes normally; the CRLF sequence and the marker header
    # ride on the end. requests URL-encodes the CR/LF for transport (%0D%0A);
    # a server that decodes and reflects it into a header splits here.
    prefix = original_value(context.params.get(parameter))
    payload = f"{prefix}\r\n{header_name}: {marker}"

    response = context.probe(mutated(context.params, parameter, payload), module="crlf")
    where = _injected_header(response, header_name, marker)
    if where is None:
        return []
    return [finding(
        "HTTP Header Injection (CRLF)", "medium", context.endpoint, parameter, payload,
        f"Injected header appeared in the response {where!r}: the parameter is "
        f"reflected into response headers without CRLF sanitization, enabling "
        f"response splitting, cache poisoning and header/cookie injection",
        response,
    )]
