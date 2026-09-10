import json
import sys
from pathlib import Path

_PROBE = Path(__file__).resolve().parents[1] / "probe"
if str(_PROBE) not in sys.path:
    sys.path.insert(0, str(_PROBE))

from plugins import wordpress_scan
from plugins.wordpress_scan import WordPressScanPlugin
from scanner.cms.wordpress import enumerate_wordpress, is_wordpress


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class FakeHandler:
    """Routes requests by first matching substring of the URL."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        for needle, resp in self.routes.items():
            if needle in url:
                return resp
        return FakeResp(404, "not found")


HOMEPAGE = (
    "<html><head>"
    '<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/'
    'includes/css/styles.css?ver=5.8.1">'
    '<link rel="stylesheet" href="/wp-content/plugins/really-simple-ssl/assets/css/main.css">'
    '<link rel="stylesheet" href="/wp-content/themes/twentytwentyone/style.css?ver=1.4">'
    "</head><body>hello wp-content</body></html>"
)


def test_is_wordpress_positive_and_negative():
    assert is_wordpress('<link href="/wp-includes/css/x.css">')
    assert is_wordpress("", {"X-Pingback": "https://x.test/xmlrpc.php"})
    assert not is_wordpress("<html>plain site</html>", {})


def test_is_wordpress_matches_lowercase_header_names():
    assert is_wordpress("", {"x-pingback": "https://x.test/xmlrpc.php"})
    assert is_wordpress("", {"link": "<https://x.test/wp-json/>; rel=\"https://api.w.org/\""})


def test_enumerate_preserves_subdirectory_base_path():
    handler = FakeHandler(
        {
            "/blog/readme.html": FakeResp(200, "<h1>WordPress<br /> Version 6.5</h1>"),
            "/blog/feed/": FakeResp(404),
        }
    )
    report = enumerate_wordpress(
        handler, "https://host.test/blog/", homepage_text=HOMEPAGE
    )

    assert report.core_version == "6.5"
    assert all(
        url.startswith("https://host.test/blog/")
        for url in handler.calls
        if "host.test" in url
    )


def test_core_version_from_readme_html_when_generator_stripped():
    handler = FakeHandler(
        {
            "readme.html": FakeResp(
                200, "<h1>WordPress<br /> Version 6.4.2</h1>"
            ),
            "feed/": FakeResp(404),
        }
    )
    report = enumerate_wordpress(handler, "https://blog.test/", homepage_text=HOMEPAGE)

    assert report.core_version == "6.4.2"
    assert report.core_version_source == "readme.html"
    assert report.homepage_has_generator is False


def test_plugin_version_from_asset_ver_query():
    handler = FakeHandler({})
    report = enumerate_wordpress(handler, "https://blog.test/", homepage_text=HOMEPAGE)

    assert report.plugins["contact-form-7"]["version"] == "5.8.1"
    assert report.themes["twentytwentyone"]["version"] == "1.4"


def test_plugin_version_falls_back_to_readme_stable_tag():
    handler = FakeHandler(
        {
            "really-simple-ssl/readme.txt": FakeResp(
                200, "=== Really Simple SSL ===\nStable tag: 7.1.2\n"
            )
        }
    )
    report = enumerate_wordpress(handler, "https://blog.test/", homepage_text=HOMEPAGE)

    assert report.plugins["really-simple-ssl"]["version"] == "7.1.2"
    assert report.plugins["really-simple-ssl"]["source"] == "readme.txt"


def test_user_enumeration_via_rest_route():
    handler = FakeHandler(
        {
            "wp-json/wp/v2/users": FakeResp(
                200,
                json.dumps([{"id": 1, "slug": "admin", "name": "Site Admin"}]),
            )
        }
    )
    report = enumerate_wordpress(handler, "https://blog.test/", homepage_text=HOMEPAGE)

    assert report.users == [
        {"id": 1, "slug": "admin", "name": "Site Admin", "source": "wp-json"}
    ]


def test_xmlrpc_exposure_detected():
    handler = FakeHandler(
        {
            "xmlrpc.php": FakeResp(
                405, "XML-RPC server accepts POST requests only."
            )
        }
    )
    report = enumerate_wordpress(handler, "https://blog.test/", homepage_text=HOMEPAGE)

    assert any(e["name"] == "xmlrpc.php enabled" for e in report.exposures)


def test_plugin_skips_non_wordpress_targets():
    plugin = WordPressScanPlugin()
    url_info = {
        "url": "https://plain.test/",
        "depth": 0,
        "response": FakeResp(200, "<html>nothing to see</html>"),
    }
    assert plugin.scan(url_info, FakeHandler({})) == []


def test_plugin_emits_inventory_findings(monkeypatch):
    monkeypatch.setattr(wordpress_scan, "sqlite_cve_db_available", lambda: False)
    plugin = WordPressScanPlugin()
    handler = FakeHandler({"readme.html": FakeResp(404)})
    url_info = {"url": "https://blog.test/", "depth": 0, "response": FakeResp(200, HOMEPAGE)}

    findings = plugin.scan(url_info, handler)
    titles = [f.title for f in findings]

    assert any("plugins detected" in t for t in titles)
    assert all(f.plugin_name == "wordpress_scan" for f in findings)


def test_plugin_cve_correlation_for_versioned_plugin(monkeypatch):
    monkeypatch.setattr(wordpress_scan, "sqlite_cve_db_available", lambda: True)
    monkeypatch.setattr(wordpress_scan, "calculate_severity", lambda cvss, cid="": "high")

    def fake_query(product, version=None):
        if product == "contact-form-7" and version == "5.8.1":
            return [
                {
                    "cve_id": "CVE-2020-35489",
                    "cvss_score": 8.8,
                    "description": "Unrestricted file upload in Contact Form 7",
                    "references": [],
                    "kev": False,
                }
            ]
        return []

    monkeypatch.setattr(wordpress_scan, "query_cves", fake_query)

    plugin = WordPressScanPlugin()
    handler = FakeHandler({"readme.html": FakeResp(404)})
    url_info = {"url": "https://blog.test/", "depth": 0, "response": FakeResp(200, HOMEPAGE)}

    findings = plugin.scan(url_info, handler)
    cve_titles = [f.title for f in findings if "CVE-" in f.title]

    assert cve_titles == ["CVE-2020-35489: WordPress plugin contact-form-7 5.8.1"]
