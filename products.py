"""
DREAD suite registry — one place for product names, entrypoints, and blurbs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Monorepo / CLI version (orchestrator + registry). Bump when releasing.
SUITE_VERSION = "0.1.0"


@dataclass(frozen=True)
class SuiteProduct:
    """Describes one deliverable in the DREAD suite."""

    cli_name: str
    script_relpath: str
    display_name: str
    summary: str
    status: str  # "implemented" | "scaffold"


REPO_ROOT = Path(__file__).resolve().parent

SUITE_PRODUCTS: tuple[SuiteProduct, ...] = (
    SuiteProduct(
        "probe",
        "probe/probe.py",
        "Probe",
        "Web application vulnerability scanner and crawl-based security testing.",
        "implemented",
    ),
    SuiteProduct(
        "scope",
        "scope/scope.py",
        "Scope",
        "External attack surface and asset discovery (DNS, CT, cloud hints, IP intel).",
        "implemented",
    ),
    SuiteProduct(
        "watch",
        "watch/watch.py",
        "Watch",
        "Continuous monitoring across web, internal network, and cloud environments.",
        "scaffold",
    ),
    SuiteProduct(
        "graph",
        "graph/graph.py",
        "Graph",
        "Attack path analysis — graph relationships between assets, exposures, and blast radius.",
        "scaffold",
    ),
    SuiteProduct(
        "intel",
        "intel/intel.py",
        "Intel",
        "Vulnerability intelligence: advisories, exploitability context, and enrichment pipelines.",
        "scaffold",
    ),
    SuiteProduct(
        "reports",
        "reports/reports.py",
        "Reports",
        "Unified suite reporting: master JSON + PDF + React dashboard (Probe & Scope MVP).",
        "implemented",
    ),
    SuiteProduct(
        "spear",
        "spear/spear.py",
        "Spear",
        "Internal network/host assessment and automated penetration agent "
        "(post-infiltration style, telemetry back to DREAD).",
        "scaffold",
    ),
    SuiteProduct(
        "cannon",
        "cannon/cannon.py",
        "Cannon",
        "Authorized stress testing and orchestration of installed external tools against a target.",
        "scaffold",
    ),
    SuiteProduct(
        "dreadai",
        "dreadai/dreadai.py",
        "DreadAI",
        "Report verification (Probe / unified suite JSON) plus suite overview; "
        "broader orchestration hooks remain roadmap.",
        "implemented",
    ),
)


def script_path(product: SuiteProduct) -> Path:
    return REPO_ROOT / product.script_relpath


def product_by_cli(name: str) -> SuiteProduct | None:
    n = name.lower().strip()
    for p in SUITE_PRODUCTS:
        if p.cli_name == n:
            return p
    return None


def format_suite_overview() -> str:
    lines = [
        "DREAD — product suite",
        "=" * 64,
        "",
    ]
    for p in SUITE_PRODUCTS:
        lines.append(f"  {p.display_name}  ({p.cli_name})  [{p.status}]")
        lines.append(f"    {p.summary}")
        lines.append("")
    lines.append("Entry:  python dread.py <product> ...")
    lines.append("        python dread.py products")
    lines.append("")
    lines.append(
        "Tip: Product-native --help (e.g. probe subcommands): "
        "python probe/probe.py --help"
    )
    return "\n".join(lines)
