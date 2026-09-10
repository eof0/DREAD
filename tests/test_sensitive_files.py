from requests import Response

from plugins.sensitive_files import SensitiveFilesPlugin


def make_response(body, status=200, content_type="text/html; charset=utf-8"):
    response = Response()
    response.status_code = status
    response._content = body.encode()
    response.headers["Content-Type"] = content_type
    return response


class Handler:
    verbose = False

    def __init__(self, responses):
        self.responses = responses

    def get(self, url, **_kwargs):
        return self.responses.get(url, make_response("not found", 404))


def test_html_admin_route_is_a_warning_not_a_vulnerability():
    root = "https://example.test/"
    responses = {
        root: make_response("home page " * 40),
        "https://example.test/admin": make_response("<html><title>Honeypot</title>admin</html>"),
        "https://example.test/admin/": make_response("<html><title>Honeypot</title>admin</html>"),
    }

    findings = SensitiveFilesPlugin().scan({"url": root, "depth": 0}, Handler(responses))

    warnings = [finding for finding in findings if finding.metadata.get("classification") == "warning"]
    assert {finding.title for finding in warnings} == {
        "Potential Sensitive Path: admin",
        "Potential Sensitive Path: admin/",
    }
    assert all(finding.severity == "info" for finding in warnings)


def test_env_with_secret_shape_remains_a_vulnerability():
    root = "https://example.test/"
    responses = {
        root: make_response("home page " * 40),
        "https://example.test/.env": make_response(
            "APP_KEY=redacted\nDB_PASSWORD=redacted\n", content_type="text/plain"
        ),
    }

    findings = SensitiveFilesPlugin().scan({"url": root, "depth": 0}, Handler(responses))

    env = next(finding for finding in findings if finding.title.endswith(".env"))
    assert env.severity == "high"
    assert env.metadata.get("classification") != "warning"
