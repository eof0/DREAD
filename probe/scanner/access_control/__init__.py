"""Object-level authorization (IDOR / BOLA) checks."""

from scanner.access_control.identifiers import (
    IdLocation,
    classify_value,
    find_id_locations,
    mutation_values,
)
from scanner.access_control.comparison import ResponseFacts, idor_verdict, summarize
from scanner.access_control.engine import AccessControlContext, scan_url_for_idor

__all__ = [
    "IdLocation",
    "classify_value",
    "find_id_locations",
    "mutation_values",
    "ResponseFacts",
    "idor_verdict",
    "summarize",
    "AccessControlContext",
    "scan_url_for_idor",
]
