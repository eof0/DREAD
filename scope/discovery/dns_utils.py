"""Small DNS helpers shared across Scope's discovery modules."""

from __future__ import annotations

from typing import Optional


def resolve_cname(host: str) -> Optional[str]:
    """Best-effort CNAME lookup using dnspython if present, else None."""
    try:
        import dns.resolver  # type: ignore

        answers = dns.resolver.resolve(host, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except Exception:
        return None
    return None
