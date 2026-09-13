"""Opt-in credential spray against discovered login forms (off by default, bounded list)."""

from __future__ import annotations

import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from scanner import password_spray as ps


class _Resp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


LOGIN_HTML = """
<form action="/session" method="post">
  <input name="username" type="text">
  <input name="password" type="password">
  <button>Sign in</button>
</form>
"""


def test_find_login_forms_detects_password_form():
    forms = ps.find_login_forms(LOGIN_HTML, "https://app.test/login")
    assert len(forms) == 1
    form = forms[0]
    assert form["action"] == "https://app.test/session"
    assert form["method"] == "POST"
    assert form["user_field"] == "username"
    assert form["pass_field"] == "password"


def test_no_login_form_when_no_password_input():
    assert ps.find_login_forms("<form><input name=q></form>", "https://app.test/") == []


def test_spray_reports_valid_credentials():
    form = {"action": "https://app.test/session", "method": "POST",
            "user_field": "username", "pass_field": "password", "page": "https://app.test/login"}

    class Handler:
        def post(self, url, data=None, **kwargs):
            # admin/admin "works": redirects and sets a session cookie.
            if data.get("password") == "admin" and data.get("username") == "admin":
                return _Resp(302, "", {"Set-Cookie": "session=abc", "Location": "/dashboard"})
            return _Resp(200, "Invalid username or password")

    valid = ps.spray_login(Handler(), form, [("admin", "admin"), ("root", "toor")])
    assert valid == [("admin", "admin")]


def test_spray_finds_nothing_when_all_rejected():
    form = {"action": "https://app.test/session", "method": "POST",
            "user_field": "username", "pass_field": "password", "page": "https://app.test/login"}

    class Handler:
        def post(self, url, data=None, **kwargs):
            return _Resp(200, "Invalid username or password")

    assert ps.spray_login(Handler(), form, [("admin", "admin")]) == []


def test_default_credentials_are_a_small_bounded_list():
    assert 0 < len(ps.DEFAULT_CREDENTIALS) <= 25      # bounded — not a dictionary attack
    assert ("admin", "admin") in ps.DEFAULT_CREDENTIALS
