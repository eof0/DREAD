"""Server-side template injection across common engine syntaxes."""

import secrets

from .common import finding, mutated

# Each syntax expresses a*b in a different template language. A page that merely
# reflects the payload echoes the literal braces; only an engine that evaluates it
# produces the product, so the product is the signal.
# "A"/"B" are placeholders replaced by the operands (kept literal so the braces
# stay exactly as each engine expects — str.format brace-escaping is error-prone here).
_SYNTAXES = (
    ("{{A*B}}", "Jinja2/Twig/Nunjucks ({{ }})"),
    ("${A*B}", "JSP EL / Thymeleaf (${ })"),
    ("#{A*B}", "Ruby/Freemarker (#{ })"),
    ("<%= A*B %>", "ERB/EJS (<%= %>)"),
    ("A*B", None),  # raw, catches naive eval-style templating
)


def _operands():
    while True:
        a = secrets.randbelow(900) + 100
        b = secrets.randbelow(900) + 100
        product = str(a * b)
        if str(a) not in product and str(b) not in product:
            return a, b, product


def check(context, parameter):
    for template, engine in _SYNTAXES:
        a, b, product = _operands()
        payload = template.replace("A", str(a)).replace("B", str(b))
        # The raw "a*b" form would also match a page that literally echoes it, so skip
        # it unless the braced forms are unavailable; keep it last and low-weight.
        response = context.probe(mutated(context.params, parameter, payload), module="ssti")
        if response is None:
            continue
        if product in response.text and product not in context.baseline.text:
            # For the raw form require the payload NOT be reflected verbatim (else it's
            # just reflection, not evaluation).
            if engine is None and payload in response.text:
                continue
            detail = f"Template expression {a}*{b} evaluated to {product}"
            if engine:
                detail += f" ({engine})"
            return [finding(
                "Server-Side Template Injection", "high", context.endpoint, parameter, payload,
                detail + " in the response", response,
                evidence_payload="arithmetic template expression",
            )]
    return []
