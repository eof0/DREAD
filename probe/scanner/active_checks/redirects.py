import secrets

from .common import finding, mutated


def check(context, parameter):
    destination = f"https://example.com/dread-redirect-{secrets.token_hex(4)}"
    response = context.probe(mutated(context.params, parameter, destination), module="redirect")
    if (
        response is not None
        and 300 <= response.status_code < 400
        and response.headers.get("Location") == destination
    ):
        return [finding(
            "Open Redirect", "medium", context.endpoint, parameter, destination,
            f"Location header redirects to {destination}", response,
        )]
    return []
