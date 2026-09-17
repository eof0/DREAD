"""Shared DNS helper used by both takeover detection and cloud-asset discovery."""

from __future__ import annotations

from scope.discovery.dns_utils import resolve_cname


def test_resolve_cname_returns_none_for_an_unresolvable_host():
    # No mocking of dns.resolver here: an NXDOMAIN, a missing dnspython, or a
    # sandboxed/offline test host must all degrade to None rather than raise --
    # exactly like the takeover detector's original private copy of this did.
    assert resolve_cname("this-host-should-not-resolve.invalid.example") is None
