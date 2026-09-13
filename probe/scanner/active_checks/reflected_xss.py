import secrets

from bs4 import BeautifulSoup

from .common import finding, mutated


def check(context, parameter):
    token = f"qaxss{secrets.token_hex(4)}"
    payload = f'\"><qa-probe data-token="{token}">'
    response = context.probe(mutated(context.params, parameter, payload), module="xss")
    if response is None or "text/html" not in response.headers.get("Content-Type", "").lower():
        return []
    if token in context.baseline.text:
        return []
    tag = BeautifulSoup(response.text, "html.parser").find(
        "qa-probe", attrs={"data-token": token}
    )
    if tag is None:
        return []
    return [finding(
        "Reflected XSS", "high", context.endpoint, parameter, payload,
        f"Injected HTML element {tag.name} was parsed in the response", response,
    )]
