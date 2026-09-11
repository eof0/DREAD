"""
Authorization gate and audit log for Spear's active/offensive capabilities.

Spear's passive tools (discovery, service analysis, the poisoning *monitor*) run
freely. Anything that actively interferes with the network — answering name-
resolution queries, capturing authentication — must pass `require_authorization`
first: the operator has to both set an environment flag and explicitly affirm the
acknowledgment below, and everything the tool does is written to an audit log.

This is authorized-pentest / lab / research tooling. It is deliberately hard to
turn on by accident.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

ENV_FLAG = "SPEAR_AUTHORIZED"

# The operator must affirm this (typed consent or --i-am-authorized) before any
# active capability runs. It states the intended use, the per-engagement permission
# requirement, the early-stage status, and the liability disclaimer.
ACK_PHRASE = (
    "I confirm I am AUTHORIZED to test this network and that this tool is for "
    "TESTING, LABBING, and RESEARCH. It is early-stage and NOT DESIGNED FOR CLIENT "
    "ENGAGEMENTS. If I run it on a client engagement I do so ONLY with explicit "
    "written permission to run THIS SPECIFIC tool, entirely at my own risk. "
    "Dread Labs provides NO WARRANTY and is NOT RESPONSIBLE if the tool misbehaves "
    "in a way not intended."
)


class AuthorizationError(RuntimeError):
    """Raised when an active capability is invoked without proper authorization."""


def require_authorization(
    *,
    acknowledged: bool,
    operator: Optional[str] = None,
    target: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Enforce that an active capability is authorized. Both conditions are required:
      1. the environment flag SPEAR_AUTHORIZED=1, and
      2. an explicit acknowledgment from the operator (`acknowledged=True`).

    Returns an authorization context (operator/target/when) on success; raises
    AuthorizationError otherwise. Callers should record the context to the audit log.
    """
    import os

    environment = env if env is not None else os.environ
    if environment.get(ENV_FLAG) != "1":
        raise AuthorizationError(
            f"Active Spear capabilities are disabled. Set {ENV_FLAG}=1 and affirm the "
            "authorization acknowledgment to enable them (authorized testing/lab/research only)."
        )
    if not acknowledged:
        raise AuthorizationError(
            "Authorization not acknowledged. You must explicitly affirm:\n\n"
            f"{ACK_PHRASE}\n\n"
            "Pass --i-am-authorized (or type the consent when prompted) to proceed."
        )
    return {
        "operator": operator or "unknown",
        "target": target or "unspecified",
        "authorized_at": datetime.now(timezone.utc).isoformat(),
    }


class AuditLog:
    """Append-only, timestamped record of every active action Spear takes."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **fields: Any) -> None:
        stamp = datetime.now(timezone.utc).isoformat()
        parts = [stamp, event] + [f"{k}={v}" for k, v in fields.items()]
        line = "\t".join(str(p) for p in parts)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
