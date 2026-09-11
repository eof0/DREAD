"""
CSS injection.

Detects user input reflected inside a `<style>` block, where an attacker controls
stylesheet rules — enough to exfiltrate data (attribute selectors + `background:
url(...)`), deface the page, or build a keylogger-by-CSS. We inject a unique marker
and flag it only when it lands *inside a style element*, so plain HTML reflection
(already covered by the XSS checks) doesn't double-report here.
"""

import secrets

from bs4 import BeautifulSoup

from .common import finding, mutated


def check(context, parameter):
    token = f"dreadcss{secrets.token_hex(4)}"
    # A payload that closes a selector/rule and starts our own — reflected into a
    # <style> block it becomes a real rule; reflected into text it's just the marker.
    payload = f"}}#{token}{{color:red}}"
    response = context.probe(mutated(context.params, parameter, payload), module="css-injection")
    if response is None or "text/html" not in response.headers.get("Content-Type", "").lower():
        return []
    if token in context.baseline.text:
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    for style in soup.find_all("style"):
        if token in (style.string or style.get_text() or ""):
            return [finding(
                "CSS Injection", "medium", context.endpoint, parameter, payload,
                f"Injected marker '{token}' was reflected inside a <style> block, so the "
                "parameter controls page CSS (data exfiltration / defacement risk).",
                response,
                evidence_payload="CSS rule breakout payload",
            )]
    return []
