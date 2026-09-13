"""
Prototype pollution (reflective, black-box).

Injects `__proto__` / `constructor.prototype` properties as request parameters and
looks for the injected marker coming back in the response — the tell that the app
merged attacker-controlled keys into an object (and, on vulnerable stacks, the
global prototype). Black-box detection is necessarily reflective, so this is
reported at medium severity with the evidence for a human to confirm.
"""

import secrets

from .common import finding


def check(context, parameter):
    token = f"qapp{secrets.token_hex(3)}"
    marker = f"polluted{secrets.token_hex(3)}"
    if marker in (context.baseline.text if context.baseline is not None else ""):
        return []

    # Pollution keys are added alongside the existing params (not a value mutation).
    variants = (
        f"__proto__[{token}]",
        f"constructor[prototype][{token}]",
    )
    for key in variants:
        params = {**context.params, key: marker}
        response = context.probe(params, module="proto-pollution")
        if response is None:
            continue
        # The injected property name AND its value coming back together indicate the
        # object absorbed our key — a strong reflective signal of pollution.
        if token in response.text and marker in response.text:
            return [finding(
                "Prototype pollution (reflective)", "medium", context.endpoint, parameter,
                f"{key}={marker}",
                f"Injected prototype property '{token}' was reflected in the response, "
                "indicating attacker-controlled keys are merged into server-side objects.",
                response,
                evidence_payload="prototype pollution key",
            )]
    return []
