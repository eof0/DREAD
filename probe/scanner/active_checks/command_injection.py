import secrets

from .common import finding, mutated


def _operands() -> tuple[int, int, str]:
    """Two operands whose product is not a substring of either, so plain reflection can't fake it."""
    while True:
        a = secrets.randbelow(9000) + 1000
        b = secrets.randbelow(9000) + 1000
        product = str(a * b)
        if str(a) not in product and str(b) not in product:
            return a, b, product


def check(context, parameter):
    a, b, product = _operands()
    # The response can only contain the product if the shell actually evaluated the
    # arithmetic; echoing our literal input back (reflection) reproduces a and b, never a*b.
    payload = f";echo $(({a}*{b}));"
    response = context.probe(mutated(context.params, parameter, payload), module="command")
    if response is None or product not in response.text or product in context.baseline.text:
        return []
    return [finding(
        "Command Injection", "critical", context.endpoint, parameter, payload,
        f"Shell arithmetic {a}*{b} was evaluated to {product} in the response", response,
        evidence_payload="shell arithmetic payload",
    )]
