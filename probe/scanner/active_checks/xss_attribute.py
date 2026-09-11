"""
Attribute-context reflected XSS.

The main reflected-XSS check breaks out of element content (`"><tag>`). This one
covers the other common context: input reflected *inside an HTML attribute value*,
where an attacker only needs to close the quote and add a new attribute (e.g. an
event handler) without any `<` or `>`. Detection: our injected attribute appears,
parsed, on an element in the response.
"""

import secrets

from bs4 import BeautifulSoup

from .common import finding, mutated


def check(context, parameter):
    token = f"dreadattr{secrets.token_hex(4)}"
    # Close a double- or single-quoted attribute, then add our own boolean attribute.
    payload = f'x" {token}="1'
    response = context.probe(mutated(context.params, parameter, payload), module="xss-attr")
    if response is None or "text/html" not in response.headers.get("Content-Type", "").lower():
        return []
    if token in context.baseline.text:
        return []
    tag = BeautifulSoup(response.text, "html.parser").find(attrs={token: True})
    if tag is None:
        return []
    return [finding(
        "Reflected XSS (attribute context)", "high", context.endpoint, parameter, payload,
        f"Injected attribute '{token}' was parsed onto <{tag.name}> in the response", response,
        evidence_payload="attribute breakout payload",
    )]
