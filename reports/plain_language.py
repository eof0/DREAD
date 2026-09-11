"""
Plain-language explanations for the executive summary.

Every customer-facing sentence about a finding comes from explain(); that is the
seam where generated prose can replace these templates later without touching
the report layout. Templates are matched on plugin name + title, first match wins.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PlainExplanation:
    category: str
    headline: str
    what_it_means: str
    why_it_matters: str
    what_to_do: str


@dataclass(frozen=True)
class _Template:
    category: str
    plugins: frozenset[str]  # empty = any plugin
    title_pattern: re.Pattern[str]
    headline: str
    what_it_means: str
    why_it_matters: str
    what_to_do: str


def _t(category: str, plugins: str, pattern: str, *text: str) -> _Template:
    return _Template(
        category,
        frozenset(p for p in plugins.split() if p),
        re.compile(pattern, re.IGNORECASE),
        *text,
    )


_TEMPLATES: tuple[_Template, ...] = (
    _t(
        "known_vulnerable_software", "", r"CVE-\d",
        "Outdated {technology} with a publicly known security flaw",
        "Your site runs a version of {technology} that has a documented security flaw. "
        "Details of flaws like this are published, so attackers know exactly what to look for.",
        "Known flaws are among the most common ways sites get broken into, because attackers "
        "scan the internet for them automatically.",
        "Update {technology} to the latest supported version.",
    ),
    _t(
        "sql_injection", "web_vulnerabilities", r"SQL",
        "Your database can be tampered with through the website",
        "Part of your website passes what visitors type directly to its database. A visitor "
        "can type specially crafted text to read or change data they should never see.",
        "This can expose customer records, passwords, or business data, and is a common cause "
        "of data breaches.",
        "Your developers need to change how that page talks to the database.",
    ),
    _t(
        "cross_site_scripting", "web_vulnerabilities", r"XSS|Cross.Site Scripting",
        "Attackers can run their own code in your visitors' browsers",
        "A page on your site can be tricked into showing content an attacker supplies, "
        "including code that runs in the browser of anyone who opens a crafted link.",
        "An attacker could steal your users' logins, act on their behalf, or show them fake "
        "content that appears to come from you.",
        "Your developers need to make sure the site treats visitor input as plain text.",
    ),
    _t(
        "open_redirect", "web_vulnerabilities", r"Open Redirect",
        "Your site can be used to send visitors to malicious websites",
        "A link on your domain can be crafted to forward visitors to any other website.",
        "Scammers use links like this in phishing emails because the link looks like it "
        "belongs to you.",
        "Your developers should only allow redirects to your own pages.",
    ),
    _t(
        "command_injection", "web_vulnerabilities", r"Command Injection",
        "Attackers can run commands on your server",
        "Part of your website passes visitor input to the server's operating system, letting "
        "an outsider run commands on the machine.",
        "This can give an attacker full control of the server and everything stored on it.",
        "Treat this as an emergency: your developers need to fix that page immediately.",
    ),
    _t(
        "template_injection", "web_vulnerabilities", r"Template Injection",
        "Attackers can make your server run their code",
        "Your website builds pages in a way that lets a visitor's text be executed as code "
        "on the server.",
        "In most cases this gives an attacker control of the server.",
        "Your developers need to change how that page builds its content.",
    ),
    _t(
        "file_access", "web_vulnerabilities", r"Path Traversal|File Inclusion",
        "Attackers can read files on your server",
        "A page on your site can be tricked into returning files from the server that were "
        "never meant to be public.",
        "Those files can include passwords, configuration, or private data.",
        "Your developers need to restrict which files that page is allowed to open.",
    ),
    _t(
        "broken_access_control", "access_control", r"IDOR|authorization",
        "Users can see other users' data",
        "By changing a number or ID in a web address, one user can view or change records "
        "that belong to someone else.",
        "This is a direct privacy breach and a common source of reportable data incidents.",
        "Your developers need to check permissions on every request for a record.",
    ),
    _t(
        "wordpress_exposure", "wordpress_scan", r"WordPress",
        "Your WordPress site reveals information useful to attackers",
        "Your WordPress installation exposes details such as usernames or installed "
        "components that make targeted attacks easier.",
        "Knowing valid usernames makes password-guessing attacks much more effective.",
        "Have whoever manages your WordPress site hide these details and keep it updated.",
    ),
    _t(
        "exposed_sensitive_file", "sensitive_files", r"Sensitive",
        "Private files are publicly downloadable",
        "Files that should be private, such as configuration or backup files, can be "
        "downloaded by anyone on the internet.",
        "These files often contain passwords or keys that unlock other systems.",
        "Remove the files from the public site and change any passwords they contain.",
    ),
    _t(
        "origin_exposed", "", r"ORIGIN LEAKED|CDN Bypass",
        "Your server can be reached without its protection service",
        "Your site is protected by a security service, but the real server behind it can be "
        "reached directly, skipping that protection.",
        "Attackers can go around your firewall and attack protections entirely.",
        "Your IT team should block direct access so all traffic goes through the protection service.",
    ),
    _t(
        "exposed_service", "network_scanner infrastructure", r"EXPOSED|port",
        "A service is open to the internet that probably should not be",
        "A service on your server, such as a database or remote-access tool, accepts "
        "connections from anyone on the internet.",
        "Open services are routinely scanned for and attacked by automated tools.",
        "Your IT team should close it off or limit it to trusted locations.",
    ),
    _t(
        "weak_encryption", "tls_analysis", r"TLS|SSL|Certificate",
        "The encryption protecting your site could be stronger",
        "The settings that encrypt traffic between visitors and your site allow older or "
        "weaker options.",
        "Weak encryption can let someone on the same network read or alter traffic.",
        "Your IT team should update the encryption settings.",
    ),
    _t(
        "missing_browser_protections", "security_headers", r"",
        "Your site is missing some browser security settings",
        "Modern browsers can add extra protection for your visitors, but your site does not "
        "turn all of it on.",
        "Without these settings, other attacks are easier to carry out.",
        "Your IT team can add the missing settings to the web server configuration.",
    ),
    _t(
        "information_disclosure", "", r"Banner|Fingerprint|API|GraphQL|Documentation",
        "Your site reveals technical details about how it is built",
        "Your site discloses details such as software names, versions, or internal "
        "interfaces.",
        "This does not cause harm by itself, but it helps attackers plan an attack.",
        "Your IT team can hide version details and restrict internal interfaces.",
    ),
)

_GENERAL = _Template(
    "general", frozenset(), re.compile(""),
    "A security weakness was found",
    "Our testing found a weakness in one of your internet-facing systems.",
    "Weaknesses like this can give attackers a way into your systems or data.",
    "Your IT team has the technical details needed to fix it.",
)


def _technology(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence") or {}
    tech = evidence.get("technology")
    if tech:
        return str(tech)
    # "CVE-2023-1234: plugin contact-form-7 5.1" / "CVE-2020-11022: jquery vulnerability"
    tail = str(finding.get("title", "")).partition(":")[2].strip()
    return tail.removesuffix(" vulnerability").strip() or "software"


def explain(finding: dict[str, Any]) -> PlainExplanation:
    plugin = str(finding.get("plugin_name", ""))
    title = str(finding.get("title", ""))
    template = next(
        (
            t
            for t in _TEMPLATES
            if (not t.plugins or plugin in t.plugins) and t.title_pattern.search(title)
        ),
        _GENERAL,
    )
    fields = {"technology": _technology(finding)}
    why = template.why_it_matters
    if template.category == "known_vulnerable_software" and (finding.get("evidence") or {}).get("kev"):
        why = (
            "This flaw is being actively used by attackers right now, according to the U.S. "
            "government's list of known exploited vulnerabilities. " + why
        )
    return PlainExplanation(
        category=template.category,
        headline=template.headline.format(**fields),
        what_it_means=template.what_it_means.format(**fields),
        why_it_matters=why.format(**fields),
        what_to_do=template.what_to_do.format(**fields),
    )


_URGENCY = {
    "critical": "Fix immediately",
    "high": "Fix within 7 days",
    "medium": "Fix within 30 days",
    "low": "Fix when convenient",
}


def urgency(severity: str) -> str:
    return _URGENCY.get(severity.lower(), "Fix when convenient")


_RISK_LABEL = {"critical": "Critical", "high": "High", "medium": "Moderate"}


def risk_statement(overall_risk: str, vulnerability_count: int) -> tuple[str, str]:
    """(label, sentence) describing overall risk for a non-technical reader."""
    if vulnerability_count == 0:
        return (
            "Low",
            "No vulnerabilities were found. From an outside attacker's point of view, "
            "the systems we tested are in good shape.",
        )
    noun = "vulnerability" if vulnerability_count == 1 else "vulnerabilities"
    level = overall_risk.lower()
    label = _RISK_LABEL.get(level, "Low")
    tail = {
        "critical": "including at least one an attacker could use to cause serious harm "
        "right away. Treat this as urgent.",
        "high": "that give an attacker a realistic way in. They should be fixed within days, "
        "not weeks.",
        "medium": "that should be fixed within the next month.",
    }.get(level, "none of which are urgent.")
    return label, f"We found {vulnerability_count} {noun} {tail}"
