"""
High-performance network scanner.

Tries to use Rust native scanner first, then Go, then pure-Python.

Usage:
    from scanner.engines.network import scan_target, quick_scan
    
    # Full scan with metadata
    result = scan_target("example.com", ports="top100")
    
    # Quick list of open ports
    open_ports = quick_scan("example.com")
"""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

RUST_BINARY = (
    Path(__file__).resolve().parents[3]  # probe/
    / "engines" / "rust" / "probe_engine"
    / "target" / "release" / "probe-engine"
)
GO_SOURCE = Path(__file__).parent / "scanner.go"
GO_BINARY = GO_SOURCE.parent / "network_scanner"


def _get_rust_binary() -> Optional[Path]:
    """Get the Rust binary when it can run on this host."""
    if not RUST_BINARY.is_file():
        return None
    try:
        result = subprocess.run(
            [str(RUST_BINARY), "--version"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return RUST_BINARY if result.returncode == 0 else None


def _get_go_binary() -> Optional[Path]:
    """Get path to compiled Go binary if it exists or can be built."""
    if GO_BINARY.exists():
        return GO_BINARY
    if shutil.which("go"):
        try:
            cmd = ["go", "build", "-o", str(GO_BINARY), str(GO_SOURCE)]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=GO_SOURCE.parent)
            if result.returncode == 0:
                return GO_BINARY
        except Exception:
            pass
    return None


def _get_binary_path() -> Optional[Path]:
    """Get path to best available scanner binary."""
    return _get_rust_binary() or _get_go_binary()


def scan_target_rust(
    target: str,
    ports: str = "top100",
    timeout_ms: int = 2000,
    concurrency: int = 0,
    grab_banners: bool = False,
) -> Dict:
    """Scan using Rust binary."""
    binary = RUST_BINARY
    if concurrency == 0:
        concurrency = 512

    cmd = [
        str(binary), "scan",
        "--input", target,
        "--ports", ports,
        "--timeout-ms", str(timeout_ms),
        "--concurrency", str(concurrency),
        "--json",
    ]

    if grab_banners:
        cmd.append("--banners")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return {
            "error": result.stderr,
            "target": target,
            "results": [],
        }

    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "error": f"failed to parse Rust engine output: {result.stdout[:500]}",
            "target": target,
            "results": [],
        }

    # Convert Rust findings schema → Python expected format
    results = []
    for f in raw.get("findings", []):
        asset = f.get("asset", {})
        port = asset.get("port")
        if port is None:
            continue
        banner = ""
        details = f.get("details", {})
        if details:
            banner = details.get("banner", "")
        results.append({
            "port": port,
            "protocol": asset.get("protocol", "tcp"),
            "state": "open",
            "service": asset.get("service", ""),
            "banner": banner,
            "response_time_ms": 0,
        })

    return {
        "target": raw.get("target", {}).get("input", target),
        "scan_type": "connect",
        "start_time": raw.get("timestamp", ""),
        "duration_ms": raw.get("duration_ms", 0),
        "total_ports_scanned": 0,
        "open_count": len(results),
        "results": results,
        "_engine": "rust",
    }


def scan_target_go(
    target: str,
    ports: str = "top100",
    scan_type: str = "connect",
    timeout_ms: int = 2000,
    concurrency: int = 0,
    grab_banners: bool = False,
) -> Dict:
    """Scan using Go binary."""
    binary = _get_go_binary()
    if not binary:
        return {"error": "Go binary not available", "target": target, "results": []}

    cmd = [
        str(binary),
        "-target", target,
        "-ports", ports,
        "-type", scan_type,
        "-timeout", str(timeout_ms),
        "-json",
    ]

    if concurrency > 0:
        cmd.extend(["-concurrency", str(concurrency)])

    if grab_banners:
        cmd.append("-banners")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return {
            "error": result.stderr,
            "target": target,
            "results": [],
        }

    return json.loads(result.stdout)


def scan_target_native(
    target: str,
    ports: str = "top100",
    timeout_ms: int = 2000,
    concurrency: int = 100,
    grab_banners: bool = False,
) -> Dict:
    """Scan using pure Python implementation."""
    from .native import scan_target as native_scan
    return native_scan(target, ports, timeout_ms, concurrency, grab_banners)


def scan_target(
    target: str,
    ports: str = "top100",
    scan_type: str = "connect",
    timeout_ms: int = 2000,
    concurrency: int = 0,
    grab_banners: bool = False,
) -> Dict:
    """
    Scan target using best available scanner.
    
    Priority: Rust → Go → Python-native.
    """
    rust_bin = _get_rust_binary()
    if rust_bin:
        return scan_target_rust(
            target, ports, timeout_ms, concurrency, grab_banners
        )

    go_bin = _get_go_binary()
    if go_bin:
        return scan_target_go(
            target, ports, scan_type, timeout_ms, concurrency, grab_banners
        )

    return scan_target_native(
        target, ports, timeout_ms, concurrency or 100, grab_banners
    )


def quick_scan(target: str, ports: str = "top100") -> List[Dict]:
    """Quick scan returning just open ports."""
    result = scan_target(target, ports=ports)
    return result.get("results", [])


class NetworkScanner:
    """Unified network scanner interface."""
    
    def __init__(
        self,
        ports: str = "top100",
        timeout_ms: int = 2000,
        concurrency: int = 0,
        grab_banners: bool = False,
    ):
        self.ports = ports
        self.timeout_ms = timeout_ms
        self.concurrency = concurrency
        self.grab_banners = grab_banners
        self._using_rust = _get_rust_binary() is not None
        self._using_go = not self._using_rust and _get_go_binary() is not None
    
    def scan(self, target: str) -> List[Dict]:
        """Scan a single target."""
        result = scan_target(
            target=target,
            ports=self.ports,
            timeout_ms=self.timeout_ms,
            concurrency=self.concurrency,
            grab_banners=self.grab_banners,
        )
        
        if "error" in result:
            raise RuntimeError(result["error"])
        
        return [
            {
                "port": r["port"],
                "protocol": r["protocol"],
                "state": r["state"],
                "service": r.get("service", ""),
                "banner": r.get("banner", ""),
                "response_time_ms": r.get("response_time_ms", 0),
            }
            for r in result.get("results") or []
            if r.get("state") == "open"
        ]
    
    def scan_many(self, targets: List[str]) -> Dict[str, List[Dict]]:
        """Scan multiple targets."""
        results = {}
        for target in targets:
            try:
                results[target] = self.scan(target)
            except Exception as e:
                results[target] = [{"error": str(e)}]
        return results
    
    @property
    def engine(self) -> str:
        """Return which engine is being used."""
        if self._using_rust:
            return "rust"
        if self._using_go:
            return "go"
        return "python-native"


__all__ = [
    "scan_target",
    "quick_scan",
    "NetworkScanner",
]
