import pytest
from requests import Response

from plugins import cve_correlation
from plugins.cve_correlation import CVECorrelationPlugin
from scanner.fingerprints import fingerprint_technologies


def make_response(headers=None, body=b"", url="https://example.test"):
    response = Response()
    response.status_code = 200
    response.url = url
    response.headers = {"Content-Type": "text/html", **(headers or {})}
    response._content = body
    response.encoding = "utf-8"
    return response


def versioned_wordpress_response():
    return make_response(
        headers={"X-Powered-By": "PHP/8.5.5"},
        body=(
            b'<meta name="generator" content="WordPress 6.7.1">'
            b'<link href="/wp-content/site.css">'
        ),
    )


def test_fingerprinting_keeps_php_and_wordpress_versions():
    detected = fingerprint_technologies(versioned_wordpress_response())

    assert detected["framework_version"] == "6.7.1"
    assert detected["_detailed"]["languages"][0] == {
        "name": "PHP",
        "version": "8.5.5",
    }


def test_php_header_alone_does_not_claim_wordpress():
    response = versioned_wordpress_response()
    response._content = b"<html>PHP application</html>"

    detected = fingerprint_technologies(response)

    assert "framework" not in detected


def test_unversioned_php_header_still_detects_php():
    response = versioned_wordpress_response()
    response.headers["X-Powered-By"] = "PHP"
    response._content = b"<html>PHP application</html>"

    detected = fingerprint_technologies(response)

    assert detected["_detailed"]["languages"] == [{"name": "PHP"}]


@pytest.mark.parametrize(
    ("header", "name", "version"),
    [
        ("Apache/2.4.62", "Apache", "2.4.62"),
        ("nginx/1.27.4", "Nginx", "1.27.4"),
        ("Microsoft-IIS/10.0", "IIS", "10.0"),
    ],
)
def test_fingerprinting_keeps_server_versions(header, name, version):
    response = versioned_wordpress_response()
    response.headers = {"Content-Type": "text/html", "Server": header}

    detected = fingerprint_technologies(response)

    assert detected["_detailed"]["servers"] == [
        {"name": name, "version": version}
    ]


def test_os_detected_from_apache_distro_token():
    detected = fingerprint_technologies(
        make_response(headers={"Server": "Apache/2.4.52 (Ubuntu)"})
    )

    assert detected["os"]["name"] == "Ubuntu"
    assert detected["os"]["family"] == "Linux"
    assert detected["_detailed"]["servers"] == [{"name": "Apache", "version": "2.4.52"}]


def test_os_detected_from_nginx_centos_token():
    detected = fingerprint_technologies(
        make_response(headers={"Server": "nginx/1.24.0 (CentOS)"})
    )

    assert detected["os"]["name"] == "CentOS"
    assert detected["os"]["family"] == "Linux"


def test_iis_server_implies_windows_family():
    detected = fingerprint_technologies(
        make_response(headers={"Server": "Microsoft-IIS/10.0"})
    )

    assert detected["os"]["family"] == "Windows"


def test_no_os_claimed_from_cdn_server_banner():
    detected = fingerprint_technologies(
        make_response(headers={"Server": "cloudflare"})
    )

    assert detected.get("os") is None


def test_jquery_version_from_script_filename():
    detected = fingerprint_technologies(
        make_response(body=b'<script src="/assets/js/jquery-3.6.4.min.js"></script>')
    )

    libs = {item["name"]: item.get("version") for item in detected["_detailed"]["js_libraries"]}
    assert libs.get("jQuery") == "3.6.4"


def test_library_version_from_ver_query_string():
    detected = fingerprint_technologies(
        make_response(
            body=b'<link href="/wp-includes/css/bootstrap.min.css?ver=5.3.2" rel="stylesheet">'
        )
    )

    libs = {item["name"]: item.get("version") for item in detected["_detailed"]["js_libraries"]}
    assert libs.get("Bootstrap") == "5.3.2"


def test_scoped_npm_package_version_is_resolved():
    detected = fingerprint_technologies(
        make_response(
            body=(
                b'<script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/'
                b'dist/umd/popper.min.js"></script>'
            )
        )
    )

    libs = {item["name"]: item.get("version") for item in detected["_detailed"]["js_libraries"]}
    assert libs.get("Popper.js") == "2.11.8"


def test_library_version_from_cdn_at_version_path():
    detected = fingerprint_technologies(
        make_response(
            body=(
                b'<script src="https://cdn.jsdelivr.net/npm/vue@3.4.21/dist/vue.min.js">'
                b"</script>"
            )
        )
    )

    libs = {item["name"]: item.get("version") for item in detected["_detailed"]["js_libraries"]}
    assert libs.get("Vue") == "3.4.21"


def test_drupal_version_from_x_generator_header():
    detected = fingerprint_technologies(
        make_response(
            headers={"X-Generator": "Drupal 10 (https://www.drupal.org)"},
            body=b"<html></html>",
        )
    )

    assert {"name": "Drupal", "version": "10"} in detected["_detailed"]["frameworks"]


def test_structured_technologies_carry_confidence_and_source():
    detected = fingerprint_technologies(
        make_response(
            headers={"Server": "Apache/2.4.52 (Ubuntu)", "X-Powered-By": "PHP/8.1.2"},
            body=b'<script src="/js/jquery-3.6.4.min.js"></script>',
        )
    )

    techs = {item["name"]: item for item in detected["technologies"]}
    assert techs["PHP"]["version"] == "8.1.2"
    assert techs["PHP"]["source"] == "header"
    assert techs["jQuery"]["version"] == "3.6.4"
    assert techs["jQuery"]["source"] == "asset"
    assert techs["Apache"]["confidence"] == "high"


def test_clean_response_reports_no_os_and_no_phantom_libraries():
    detected = fingerprint_technologies(
        make_response(body=b"<html><body><h1>hello</h1></body></html>")
    )

    assert detected.get("os") is None
    assert detected["_detailed"]["js_libraries"] == []


def test_asset_derived_library_version_flows_to_cve_correlation(monkeypatch):
    response = make_response(
        body=b'<script src="/assets/jquery-3.6.4.min.js"></script>'
    )

    class Handler:
        def get(self, _url):
            return response

    seen = {}

    def query_cves(name, version=None):
        seen[name] = version
        return []

    monkeypatch.setattr(cve_correlation, "sqlite_cve_db_available", lambda: True)
    monkeypatch.setattr(cve_correlation, "query_cves", query_cves)

    CVECorrelationPlugin().scan({"url": response.url, "depth": 0}, Handler())

    assert seen.get("jQuery") == "3.6.4"


def test_cve_correlation_uses_the_fingerprinted_php_version(monkeypatch):
    response = versioned_wordpress_response()

    class Handler:
        def get(self, _url):
            return response

    def query_cves(_name, version=None):
        if version != "8.5.5":
            return []
        return [
            {
                "cve_id": "CVE-2026-17543",
                "cvss_score": 9.8,
                "confidence": "confirmed",
                "description": "PHP test advisory",
                "references": [],
                "kev": False,
                "kev_date_added": None,
                "epss_score": None,
                "epss_percentile": None,
            }
        ]

    monkeypatch.setattr(cve_correlation, "sqlite_cve_db_available", lambda: True)
    monkeypatch.setattr(cve_correlation, "query_cves", query_cves)

    findings = CVECorrelationPlugin().scan(
        {"url": response.url, "depth": 0},
        Handler(),
    )

    assert [finding.evidence["cve_id"] for finding in findings] == [
        "CVE-2026-17543"
    ]


def _correlate_php_cve(monkeypatch, cve_row):
    response = versioned_wordpress_response()

    class Handler:
        def get(self, _url):
            return response

    def query_cves(_name, version=None):
        return [cve_row] if version == "8.5.5" else []

    monkeypatch.setattr(cve_correlation, "sqlite_cve_db_available", lambda: True)
    monkeypatch.setattr(cve_correlation, "query_cves", query_cves)

    return CVECorrelationPlugin().scan(
        {"url": response.url, "depth": 0}, Handler()
    )


def test_high_epss_is_surfaced_in_remediation(monkeypatch):
    findings = _correlate_php_cve(
        monkeypatch,
        {
            "cve_id": "CVE-2026-17543",
            "cvss_score": 9.8,
            "confidence": "confirmed",
            "description": "PHP test advisory",
            "references": [],
            "kev": False,
            "kev_date_added": None,
            "epss_score": 0.94,
            "epss_percentile": 0.978,
        },
    )

    remediation = findings[0].remediation
    assert "EPSS" in remediation
    assert "0.94" in remediation
    assert "98th percentile" in remediation
    assert "high probability" in remediation.lower()


def test_absent_epss_adds_no_note(monkeypatch):
    findings = _correlate_php_cve(
        monkeypatch,
        {
            "cve_id": "CVE-2026-17543",
            "cvss_score": 9.8,
            "confidence": "confirmed",
            "description": "PHP test advisory",
            "references": [],
            "kev": False,
            "kev_date_added": None,
            "epss_score": None,
            "epss_percentile": None,
        },
    )

    assert "EPSS" not in findings[0].remediation
