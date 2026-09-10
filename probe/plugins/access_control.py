"""
Object-level authorization (IDOR / BOLA) plugin.

Looks for identifier parameters / path segments on each crawled URL and checks
whether swapping the identifier lets a weaker principal reach another object.

Confirmed cross-principal access (a second identity or an anonymous client
reading the authorized baseline's object shape) is reported as a real
vulnerability. Single-identity id walking cannot be confirmed as a cross-user
issue, so it is reported as an informational observation only.
"""

from __future__ import annotations

from threading import Lock
from typing import Dict, List, Optional

from plugins.base_plugin import BasePlugin, Finding
from scanner.access_control.engine import AccessControlContext, scan_url_for_idor
from scanner.access_control.identifiers import harvest_identifiers
from scanner.auth import build_handler

_GLOBAL_BUDGET = 150


class AccessControlPlugin(BasePlugin):
    def __init__(self) -> None:
        self._lock = Lock()
        self._context: Optional[AccessControlContext] = None

    def get_name(self) -> str:
        return "access_control"

    def get_description(self) -> str:
        return "Object-level authorization (IDOR / BOLA) checks on identifier parameters"

    def _get_context(self, request_handler) -> AccessControlContext:
        """Build (once, lazily) the budget-shared context for this scan run."""
        with self._lock:
            if self._context is not None:
                return self._context

            secondary = getattr(request_handler, "secondary", None)
            authenticated = bool(getattr(request_handler, "authenticated", False))

            anonymous = None
            if authenticated and secondary is None:
                anonymous = build_handler(
                    getattr(request_handler, "rate_limit", 1.0) or 1.0,
                    getattr(request_handler, "verbose", False),
                )

            def wrap(handler):
                if handler is None:
                    return None
                return lambda url: handler.get(url, allow_redirects=False)

            self._context = AccessControlContext(
                primary_get=wrap(request_handler),
                primary_authenticated=authenticated,
                secondary_get=wrap(secondary),
                anonymous_get=wrap(anonymous),
                budget=_GLOBAL_BUDGET,
            )
            return self._context

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        """Run IDOR/BOLA checks for one crawled URL and return any findings."""
        url = url_info["url"]
        page = url_info.get("response")
        page_text = getattr(page, "text", "") or ""

        context = self._get_context(request_handler)
        results = scan_url_for_idor(
            context, url, params=None, harvested=harvest_identifiers(page_text)
        )
        return [self._to_finding(url, result) for result in results]

    def _to_finding(self, url: str, result: Dict) -> Finding:
        """Turn an engine verdict dict into a ``Finding`` (confirmed vs heuristic)."""
        principal = result["principal"]
        parameter = result["parameter"]
        original = result["original_value"]
        mutated = result["mutated_value"]

        if principal == "self":
            return Finding(
                plugin_name=self.get_name(),
                severity="low",
                title="Enumerable object identifier (unconfirmed IDOR)",
                description=(
                    f"Changing '{parameter}' from {original} to {mutated} returned a "
                    f"different {result['id_kind']} object (HTTP 200, same structure, no "
                    "authorization error). With only one identity this cannot be confirmed "
                    "as cross-user access — re-run with --auth / --auth-b to verify."
                ),
                url=url,
                evidence=self._evidence(result, confidence="low"),
                remediation=(
                    "Confirm server-side authorization is enforced for every object "
                    "reference, then treat unguessable IDs as defense in depth only."
                ),
                metadata={"classification": "warning", "category": "access-control"},
            )

        who = "An unauthenticated client" if principal == "anonymous" else "A different user"
        return Finding(
            plugin_name=self.get_name(),
            severity=result["severity"],
            title="IDOR / broken object-level authorization",
            description=(
                f"{who} retrieved the object referenced by '{parameter}'={mutated} "
                f"(authorized baseline used {original}). The response was HTTP 200 with the "
                "same structure as the authorized baseline and no access-control error, "
                "indicating the identifier alone grants access."
            ),
            url=url,
            evidence=self._evidence(result, confidence="high"),
            remediation=(
                "Enforce per-request authorization server-side: verify the authenticated "
                "principal owns or may access the referenced object, independent of any "
                "client-supplied identifier."
            ),
            attack_scenario=(
                "An attacker iterates identifier values and reads or modifies records "
                "belonging to other users or tenants."
            ),
            defense_strategy=(
                "Centralize object-level authorization checks; add automated tests that "
                "assert one user cannot fetch another user's objects by ID."
            ),
        )

    @staticmethod
    def _evidence(result: Dict, *, confidence: str) -> Dict:
        return {
            "parameter": result["parameter"],
            "location": result["location"],
            "original_value": result["original_value"],
            "mutated_value": result["mutated_value"],
            "id_kind": result["id_kind"],
            "tested_url": result["tested_url"],
            "principal": result["principal"],
            "mutated_status": result["mutated_status"],
            "confidence": confidence,
        }
