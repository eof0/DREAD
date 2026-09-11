"""
Common web misconfiguration checks.

Passive signals in a normal page fetch that point at hardening gaps:
  - directory listing (the server indexes a folder instead of serving a page),
  - verbose error output / stack traces (leaks framework, paths, versions),
  - file-upload forms (worth a manual check for unrestricted upload).

These run per crawled URL and lean toward "observation/warning" unless the leak
is clearly sensitive, to avoid drowning real vulnerabilities in noise.
"""

from __future__ import annotations

import re
from typing import Dict, List

from bs4 import BeautifulSoup

from plugins.base_plugin import BasePlugin, Finding

_DIR_LISTING = re.compile(r"(index of /|directory listing for )", re.I)

_STACK_TRACES = tuple(re.compile(p, re.I) for p in (
    r"traceback \(most recent call last\)",     # Python
    r"\bat [\w.$]+\([\w.]+\.java:\d+\)",         # Java
    r"\bjava\.lang\.\w+exception",               # Java
    r"php (fatal|parse|warning|notice)",          # PHP
    r"\bon line \d+ in\b",                        # PHP/others
    r"system\.\w+exception",                      # .NET
    r"\bat [\w.]+ in .+:line \d+",                # .NET
    r"stack trace:",                               # generic
    r"\bnodejs\b.*\berror\b|\bat .+\(.+:\d+:\d+\)",  # Node
))


def detect_directory_listing(body: str) -> bool:
    return bool(_DIR_LISTING.search(body or ""))


def detect_stack_trace(body: str) -> bool:
    text = body or ""
    return any(pattern.search(text) for pattern in _STACK_TRACES)


def _has_file_upload(html: str) -> bool:
    soup = BeautifulSoup(html or "", "html.parser")
    if soup.find("input", attrs={"type": "file"}):
        return True
    return any(
        (form.get("enctype") or "").lower() == "multipart/form-data"
        for form in soup.find_all("form")
    )


class MisconfigurationPlugin(BasePlugin):
    def get_name(self) -> str:
        return "misconfiguration"

    def get_description(self) -> str:
        return "Directory listing, verbose errors, and upload-form exposure checks"

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        url = url_info["url"]
        response = url_info.get("response") or request_handler.get(url)
        if response is None:
            return []
        body = getattr(response, "text", "") or ""
        ctype = response.headers.get("Content-Type", "").lower()
        findings: List[Finding] = []

        if "text/html" in ctype and detect_directory_listing(body):
            findings.append(Finding(
                plugin_name=self.get_name(), severity="medium",
                title="Directory listing enabled",
                description="The server returned an auto-generated index of a directory, "
                            "exposing file names that should not be enumerable.",
                url=url,
                remediation="Disable auto-indexing (e.g. 'Options -Indexes' / 'autoindex off') "
                            "and serve an explicit index page.",
                evidence={"signal": "directory index page"},
            ))

        if detect_stack_trace(body):
            findings.append(Finding(
                plugin_name=self.get_name(), severity="medium",
                title="Verbose error / stack trace exposed",
                description="A response leaked a stack trace or verbose error, disclosing "
                            "framework, file paths and versions useful to an attacker.",
                url=url,
                remediation="Disable debug mode in production and return generic error pages; "
                            "log details server-side only.",
                evidence={"signal": "stack trace in response"},
            ))

        if "text/html" in ctype and _has_file_upload(body):
            findings.append(Finding(
                plugin_name=self.get_name(), severity="info",
                title="File upload form present (review for unrestricted upload)",
                description="A file-upload form was found. Unrestricted upload can lead to "
                            "web-shell / RCE; verify type, size and storage-location controls.",
                url=url,
                remediation="Enforce an allowlist of extensions/MIME types, store uploads "
                            "outside the web root, and never execute uploaded files.",
                evidence={"signal": "multipart form or <input type=file>"},
                metadata={"classification": "warning"},
            ))

        return findings
