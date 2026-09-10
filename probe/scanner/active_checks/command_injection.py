import secrets

from .common import finding, mutated


def check(context, parameter):
    token = f"dread-cmd-{secrets.token_hex(4)}"
    payload = f";echo {token};"
    response = context.probe(mutated(context.params, parameter, payload), module="command")
    if response is None or token not in response.text or token in context.baseline.text:
        return []
    return [finding(
        "Command Injection", "critical", context.endpoint, parameter, payload,
        "A command output marker was introduced in the response", response,
        evidence_payload="command marker payload",
    )]
