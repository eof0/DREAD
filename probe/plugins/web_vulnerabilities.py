import ipaddress
import json
from typing import Dict, List
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup
from requests import Request
from requests.exceptions import RequestException

from plugins.base_plugin import BasePlugin, Finding
from scanner.active_checks import (
    css_injection,
    dom_xss,
    command_injection,
    file_inclusion,
    prototype_pollution,
    redirects,
    reflected_xss,
    sql_errors,
    sqli_boolean,
    ssti,
    traversal,
    xss_attribute,
)
from scanner.active_checks.context import ActiveScanContext, OriginState


MAX_PARAMETERS = 6
# Some checks send many probes per parameter (traversal tries ~13 encodings, blind
# SQLi 8, SSTI 5). Budget generously per parameter so every parameter is fully
# tested; the crawler's URL cap and the rate limiter bound total scan volume.
MAX_PROBES_PER_PARAMETER = 50
CHECKS = [
    reflected_xss.check,
    xss_attribute.check,
    css_injection.check,
    sql_errors.check,
    sqli_boolean.check,
    traversal.check,
    redirects.check,
    command_injection.check,
    ssti.check,
    file_inclusion.check,
    prototype_pollution.check,
]


def _add_value(values, name, value):
    current = values.get(name)
    if current is None:
        values[name] = value
    elif isinstance(current, list):
        current.append(value)
    else:
        values[name] = [current, value]


def _parameter_values(pairs):
    values = {}
    for name, value in pairs:
        _add_value(values, name, value)
    return values


def _control_disabled(control):
    if control.has_attr("disabled"):
        return True
    for fieldset in control.find_parents("fieldset"):
        if not fieldset.has_attr("disabled"):
            continue
        first_legend = fieldset.find("legend", recursive=False)
        if first_legend is None or first_legend not in control.parents:
            return True
    return False


def _form_values(form) -> Dict:
    values = {}
    for control in form.find_all(["input", "select", "textarea"]):
        name = control.get("name")
        if not name or _control_disabled(control):
            continue
        if control.name == "input":
            control_type = control.get("type", "text").lower()
            if control_type in {
                "submit",
                "button",
                "file",
                "password",
                "reset",
                "image",
            }:
                continue
            if control_type in {"checkbox", "radio"} and not control.has_attr("checked"):
                continue
            value = control.get("value", "")
        elif control.name == "textarea":
            value = control.get_text()
        else:
            options = control.find_all("option", selected=True)
            if not options and not control.has_attr("multiple"):
                option = control.find("option")
                options = [option] if option else []
            for option in options:
                optgroup = option.find_parent("optgroup")
                if option.has_attr("disabled") or (
                    optgroup is not None and optgroup.has_attr("disabled")
                ):
                    continue
                _add_value(values, name, option.get("value", option.get_text()))
            continue
        _add_value(values, name, value)
    return values


def _canonical_host(host):
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            return host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return host.lower()


def _origin(url):
    try:
        prepared_url = Request("GET", url).prepare().url
        parsed = urlparse(prepared_url)
        port = parsed.port
    except (RequestException, UnicodeError, ValueError):
        return None
    scheme = parsed.scheme.lower()
    host = _canonical_host(parsed.hostname or "")
    if not scheme or not host:
        return None
    default_port = {"http": 80, "https": 443}.get(scheme)
    return scheme, host, port if port is not None else default_port


def discover_json_targets(url: str, body: str) -> List[tuple[str, Dict]]:
    parsed = urlparse(url)
    query = _parameter_values(parse_qsl(parsed.query, keep_blank_values=True))
    if not query:
        return []
    try:
        payload = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    endpoint = urlunparse(parsed._replace(query="", fragment=""))
    return [(endpoint, query)]


def discover_get_targets(url: str, html: str) -> List[tuple[str, Dict]]:
    origin = _origin(url)
    if origin is None:
        return []
    parsed = urlparse(url)
    targets = []
    query = _parameter_values(parse_qsl(parsed.query, keep_blank_values=True))
    if query:
        endpoint = urlunparse(parsed._replace(query="", fragment=""))
        targets.append((endpoint, query))

    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        if form.get("method", "get").lower() != "get":
            continue
        try:
            action = urljoin(url, form.get("action") or url)
            action_parsed = urlparse(action)
        except ValueError:
            continue
        if _origin(action) != origin:
            continue
        values = _parameter_values(
            parse_qsl(action_parsed.query, keep_blank_values=True)
        )
        values.update(_form_values(form))
        if not values:
            continue
        endpoint = urlunparse(action_parsed._replace(query="", fragment=""))
        target = (endpoint, values)
        if target not in targets:
            targets.append(target)
    return targets


def _query_target(url: str) -> List[tuple[str, Dict]]:
    """The (endpoint, params) target for a URL's own query string, if any and same-origin."""
    if _origin(url) is None:
        return []
    parsed = urlparse(url)
    query = _parameter_values(parse_qsl(parsed.query, keep_blank_values=True))
    if not query:
        return []
    return [(urlunparse(parsed._replace(query="", fragment="")), query)]


def discover_post_targets(url: str, html: str) -> List[tuple[str, Dict]]:
    """Same-origin POST forms and their default field values, for body injection."""
    origin = _origin(url)
    if origin is None:
        return []
    targets: List[tuple[str, Dict]] = []
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        if form.get("method", "get").lower() != "post":
            continue
        try:
            action = urljoin(url, form.get("action") or url)
            action_parsed = urlparse(action)
        except ValueError:
            continue
        if _origin(action) != origin:
            continue
        values = _form_values(form)
        if not values:
            continue
        endpoint = urlunparse(action_parsed._replace(fragment=""))
        target = (endpoint, values)
        if target not in targets:
            targets.append(target)
    return targets


class WebVulnerabilitiesPlugin(BasePlugin):
    def get_name(self) -> str:
        return "web_vulnerabilities"

    def get_description(self) -> str:
        return "Safe active checks for common GET parameter vulnerabilities"

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        page_url = url_info["url"]
        page = url_info.get("response")
        if page is None:
            page = request_handler.get(page_url)
        if page is None:
            return []
        content_type = page.headers.get("Content-Type", "").lower()
        is_html = "text/html" in content_type
        is_json = "json" in content_type
        if not is_html and not is_json:
            return []

        response_url = getattr(page, "url", None) or page_url
        if _origin(response_url) != _origin(page_url):
            return []

        # One dispatcher so the active checks can drive GET or POST identically; the
        # context decides whether a mutated payload becomes a query string or a body.
        def _send(method="GET", **kwargs):
            fn = request_handler.post if method.upper() == "POST" else request_handler.get
            return fn(**kwargs)

        findings = dom_xss.scan_dom(response_url) if is_html else []
        self._tested = 0
        origin_states: Dict = {}

        if is_html:
            get_targets = discover_get_targets(response_url, page.text)
            # Recover the requested URL's own query parameters: a URL that itself
            # redirects (e.g. /go?next=..) loses them once we follow to the final page,
            # and with them the very endpoint we need to test. Forms still resolve
            # against the final URL only (handled above).
            for extra in _query_target(page_url):
                if extra not in get_targets:
                    get_targets.append(extra)
            post_targets = discover_post_targets(response_url, page.text)
        else:
            get_targets = discover_json_targets(response_url, page.text)
            post_targets = []

        for endpoint, params in get_targets:
            if not self._run_targets(endpoint, params, "GET", "query", _send,
                                     request_handler, origin_states, findings):
                return findings
        for endpoint, params in post_targets:
            if not self._run_targets(endpoint, params, "POST", "form", _send,
                                     request_handler, origin_states, findings):
                return findings
        return findings

    def _run_targets(self, endpoint, params, method, location, send,
                     request_handler, origin_states, findings) -> bool:
        """Inject into one endpoint's params. Returns False when the global budget is spent."""
        if method == "POST":
            baseline = request_handler.post(endpoint, data=params, allow_redirects=False)
        else:
            baseline = request_handler.get(endpoint, params=params, allow_redirects=False)
        if baseline is None:
            return True
        baseline_sql = {
            pattern.pattern
            for pattern in sql_errors.SQL_ERRORS
            if pattern.search(baseline.text)
        }
        endpoint_origin = _origin(endpoint)
        context = ActiveScanContext(
            endpoint,
            endpoint_origin,
            baseline,
            params,
            send,
            endpoint_budget=MAX_PARAMETERS * MAX_PROBES_PER_PARAMETER,
            baseline_sql=baseline_sql,
            origin_state=origin_states.setdefault(
                endpoint_origin, OriginState(MAX_PARAMETERS * MAX_PROBES_PER_PARAMETER * 2)),
            method=method,
            location=location,
        )
        for parameter in params:
            if self._tested >= MAX_PARAMETERS:
                return False
            self._tested += 1
            for check in CHECKS:
                findings.extend(check(context, parameter))
        return True
