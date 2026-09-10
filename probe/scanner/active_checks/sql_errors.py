from .common import SQL_ERRORS, finding, mutated, original_value


def check(context, parameter):
    payload = f"{original_value(context.params[parameter])}'"
    response = context.probe(mutated(context.params, parameter, payload), module="sql")
    if response is None:
        return []
    new_errors = [
        pattern.pattern
        for pattern in SQL_ERRORS
        if pattern.pattern not in context.baseline_sql and pattern.search(response.text)
    ]
    if not new_errors:
        return []
    return [finding(
        "SQL Injection Error", "high", context.endpoint, parameter, payload,
        f"New database error signature: {new_errors[0]}", response,
        evidence_payload="[original value] + single quote",
    )]
