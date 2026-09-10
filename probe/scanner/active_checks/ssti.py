from .common import finding, mutated


PAYLOAD = "{{7*7}}"
MARKER = "49"


def check(context, parameter):
    response = context.probe(mutated(context.params, parameter, PAYLOAD), module="ssti")
    if response is None or MARKER not in response.text or MARKER in context.baseline.text:
        return []
    return [finding(
        "Server-Side Template Injection", "high", context.endpoint, parameter, PAYLOAD,
        "The template expression was evaluated in the response", response,
        evidence_payload="arithmetic template expression",
    )]
