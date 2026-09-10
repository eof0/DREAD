import ipaddress
import json
from typing import Dict, List
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup
from requests import Request
from requests.exceptions import RequestException

from plugins.base_plugin import BasePlugin, Finding
from scanner.active_checks import (
    dom_xss,
    command_injection,
    file_inclusion,
    redirects,
    reflected_xss,
    sql_errors,
    ssti,
    traversal,
)
from scanner.active_checks.context import ActiveScanContext, OriginState


MAX_PARAMETERS = 6
CHECKS = [
    reflected_xss.check,
    sql_errors.check,
    traversal.check,
    redirects.check,
    command_injection.check,
    ssti.check,
    file_inclusion.check,
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

        findings = dom_xss.scan_dom(response_url) if is_html else []
        tested = 0
        origin_states = {}
        targets = (
            discover_get_targets(response_url, page.text)
            if is_html
            else discover_json_targets(response_url, page.text)
        )
        for endpoint, params in targets:
            baseline = request_handler.get(endpoint, params=params, allow_redirects=False)
            if baseline is None:
                continue
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
                request_handler.get,
                endpoint_budget=MAX_PARAMETERS * (len(CHECKS) + 3),
                baseline_sql=baseline_sql,
                origin_state=origin_states.setdefault(endpoint_origin, OriginState(240)),
            )
            for parameter in params:
                if tested >= MAX_PARAMETERS:
                    return findings
                tested += 1
                for check in CHECKS:
                    findings.extend(check(context, parameter))
        return findings
