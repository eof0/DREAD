"""Regression tests locking the code-review fixes (branch feature/spear-active-capture)."""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
for sub in ("probe", "spear"):
    p = str(_REPO / sub)
    if p not in sys.path:
        sys.path.insert(0, p)


class _Resp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {"Content-Type": "text/html"}
        self.url = ""


# --- #6 CORS: version-prefixed APIs only count at the path root -----------------------

def test_cors_looks_like_api_root_versioned_not_midpath():
    from plugins.cors_check import _looks_like_api

    assert _looks_like_api("https://x.test/api/users")
    assert _looks_like_api("https://x.test/v1/users")          # root-versioned API
    assert _looks_like_api("https://x.test/graphql")
    assert not _looks_like_api("https://x.test/guide/v1/intro")  # v1 mid-path = content
    assert not _looks_like_api("https://x.test/docs/v2/pricing")  # v2 mid-path = content
    assert not _looks_like_api("https://x.test/pricing")


# --- #5 Crawler: only queue statuses that confirm a route exists ----------------------

def test_crawler_route_discovery_excludes_server_errors():
    from scanner.crawler import Crawler

    class Handler:
        def get(self, url, **kwargs):
            if "qa-nope" in url:               # catch-all probe -> genuinely absent
                return _Resp(404)
            if url.endswith("/login"):
                return _Resp(500)              # server error: NOT a confirmed route
            if url.endswith("/redirect"):
                return _Resp(302)              # exists (redirects)
            if url.endswith("/admin"):
                return _Resp(403)              # exists but gated
            return _Resp(404)

    seeds = Crawler("https://site.test/", max_depth=2, max_urls=50).seed_urls(Handler())
    assert "https://site.test/redirect" in seeds        # 302 queued
    assert "https://site.test/admin" in seeds           # 403 queued
    assert "https://site.test/login" not in seeds       # 500 NOT queued (was phantom noise)


# --- #4 NTLM: Type-2 carries the 8-byte Version field it advertises -------------------

def test_ntlm_type2_targetname_offset_leaves_room_for_version():
    from ntlm import build_type2

    msg = build_type2(target_name="CORP")
    tn_len, _maxlen, tn_off = struct.unpack_from("<HHI", msg, 12)   # TargetNameFields
    assert tn_off == 56                                            # 48 header + 8 Version
    assert msg[tn_off:tn_off + tn_len].decode("utf-16-le") == "CORP"


# --- #1 Poisoner: the LLMNR listener joins the 224.0.0.252 multicast group -------------

class _FakeSock:
    def __init__(self):
        self.opts = []
        self.port = None

    def setsockopt(self, level, optname, value):
        self.opts.append((level, optname))

    def bind(self, addr):
        self.port = addr[1]

    def settimeout(self, _t):
        pass

    def close(self):
        pass


def test_llmnr_listener_joins_multicast_group(monkeypatch, tmp_path):
    monkeypatch.setenv("SPEAR_AUTHORIZED", "1")
    from poisoner import run_poisoner

    created = []
    monkeypatch.setattr(socket, "socket",
                        lambda *a, **k: created.append(_FakeSock()) or created[-1])

    run_poisoner("10.0.0.66", duration=0, acknowledged=True,
                 audit_path=tmp_path / "audit.log")

    llmnr = next(s for s in created if s.port == 5355)
    nbns = next(s for s in created if s.port == 137)
    join = (socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP)
    assert join in llmnr.opts        # LLMNR joins multicast -> actually receives queries
    assert join not in nbns.opts     # NBT-NS is broadcast, no join


# --- #3 Dedup: the shared session_auth helper shapes cookies + filters headers --------

def test_browser_session_auth_shapes_cookies_and_filters_headers():
    from scanner.browser_crawler import session_auth

    class _Cookie:
        def __init__(self, name, value, domain=None, path=None):
            self.name, self.value, self.domain, self.path = name, value, domain, path

    class _Session:
        cookies = [_Cookie("sid", "abc", None, None)]
        headers = {"Authorization": "Bearer t", "User-Agent": "x", "X-CSRF-Token": "c"}

    class _RH:
        session = _Session()

    cookies, headers = session_auth(_RH(), "app.test")
    assert cookies == [{"name": "sid", "value": "abc", "domain": "app.test", "path": "/"}]
    assert headers == {"Authorization": "Bearer t", "X-CSRF-Token": "c"}  # UA dropped
