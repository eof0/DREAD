"""
Session / authentication helpers.

Turns CLI-style auth inputs (bearer token, cookie string, basic creds, repeated
``-H`` headers, or a login form) into configured ``RequestHandler`` instances.
Used by the engine to build the primary identity and an optional secondary
identity for two-identity IDOR checks.
"""

from __future__ import annotations

from typing import Dict, Iterable, Optional
from urllib.parse import parse_qsl

from scanner.request_handler import RequestHandler


def parse_cookie_string(raw: str) -> Dict[str, str]:
    """``"a=1; b=2"`` -> ``{"a": "1", "b": "2"}``."""
    cookies: Dict[str, str] = {}
    for part in (raw or "").split(";"):
        if "=" in part:
            name, value = part.split("=", 1)
            name = name.strip()
            if name:
                cookies[name] = value.strip()
    return cookies


def parse_header_lines(lines: Optional[Iterable[str]]) -> Dict[str, str]:
    """``["X-A: 1", "X-B: 2"]`` -> ``{"X-A": "1", "X-B": "2"}``."""
    headers: Dict[str, str] = {}
    for line in lines or []:
        if ":" in line:
            name, value = line.split(":", 1)
            name = name.strip()
            if name:
                headers[name] = value.strip()
    return headers


def form_data(data) -> Dict[str, str]:
    """Accept a dict or an ``a=1&b=2`` string; return a dict."""
    if isinstance(data, dict):
        return {str(k): str(v) for k, v in data.items()}
    return dict(parse_qsl(str(data or ""), keep_blank_values=True))


def build_handler(
    rate_limit: float,
    verbose: bool = False,
    *,
    auth: Optional[Dict] = None,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    verify_ssl: bool = True,
) -> RequestHandler:
    """Build a ``RequestHandler`` and tag it with ``.authenticated`` / ``.secondary``."""
    handler = RequestHandler(
        rate_limit=rate_limit,
        verbose=verbose,
        auth=auth,
        cookies=cookies,
        headers=headers,
        verify_ssl=verify_ssl,
    )
    # Marked here so plugins can tell an authenticated session from an anonymous
    # one without inspecting the requests session internals. Only real
    # credentials or a session cookie count — arbitrary ``-H`` headers (tracing,
    # user-agent overrides, etc.) do not make a session authenticated.
    handler.authenticated = bool(auth or cookies)
    handler.secondary = None
    return handler


def login_via_form(
    handler: RequestHandler,
    login_url: str,
    data,
    *,
    success_indicator: str,
    method: str = "POST",
) -> bool:
    """
    Submit a login form on ``handler``'s session and report whether it worked.

    ``success_indicator`` is required: a bare HTTP 200 is not proof of login
    (a login page re-rendered with an error is also 200), and wrongly flagging
    the session as authenticated would pick the wrong principal in
    access-control checks. Pass a substring that only appears once logged in
    (a username, a "Sign out" link, a dashboard heading).

    Session cookies set by the response persist on the handler for the rest of
    the scan.
    """
    if not success_indicator:
        raise ValueError("login_via_form requires a non-empty success_indicator")
    payload = form_data(data)
    if method.upper() == "POST":
        response = handler.post(login_url, data=payload, allow_redirects=True)
    else:
        response = handler.get(login_url, params=payload, allow_redirects=True)
    if response is None:
        return False
    ok = success_indicator.lower() in (response.text or "").lower()
    if ok:
        handler.authenticated = True
    return ok
