import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

import requests
from requests.cookies import RequestsCookieJar
from requests.models import PreparedRequest

from scanner.request_handler import RequestHandler, _RedirectSafeSession


def _prepared(url: str, headers: dict) -> PreparedRequest:
    pr = PreparedRequest()
    pr.url = url
    pr.headers = requests.structures.CaseInsensitiveDict(headers)
    pr._cookies = RequestsCookieJar()
    pr._cookies.set("session", "secret")
    return pr


def _response(request_url: str) -> requests.Response:
    resp = requests.Response()
    resp.request = PreparedRequest()
    resp.request.url = request_url
    return resp


def _session() -> _RedirectSafeSession:
    session = _RedirectSafeSession(sensitive_headers=["X-Api-Key"])
    session.trust_env = False  # keep the test off ~/.netrc
    return session


SECRET_HEADERS = {
    "Cookie": "session=secret",
    "Authorization": "Bearer t0ken",
    "X-Api-Key": "operator-key",
    "User-Agent": "Probe",
}


def test_cross_host_redirect_strips_cookies_and_secret_headers():
    session = _session()
    prepared = _prepared("https://attacker.test/x", dict(SECRET_HEADERS))

    session.rebuild_auth(prepared, _response("https://target.test/start"))

    assert "Cookie" not in prepared.headers
    assert "Authorization" not in prepared.headers
    assert "X-Api-Key" not in prepared.headers
    assert prepared.headers.get("User-Agent") == "Probe"
    assert len(prepared._cookies) == 0


def test_same_host_redirect_keeps_credentials():
    session = _session()
    prepared = _prepared("https://target.test/next", dict(SECRET_HEADERS))

    session.rebuild_auth(prepared, _response("https://target.test/start"))

    assert prepared.headers.get("Cookie") == "session=secret"
    assert prepared.headers.get("Authorization") == "Bearer t0ken"
    assert prepared.headers.get("X-Api-Key") == "operator-key"


def test_request_handler_uses_redirect_safe_session():
    handler = RequestHandler(
        rate_limit=0,
        cookies={"session": "secret"},
        headers={"X-Api-Key": "operator-key"},
    )
    assert isinstance(handler.session, _RedirectSafeSession)
    assert "x-api-key" in handler.session._sensitive_headers
