"""
Output formatting for Scope results.
"""

import json
from typing import Any, Dict


class OutputFormatter:
    """Format Scope results for different outputs."""

    def to_json(self, data: Dict[str, Any]) -> str:
        """Format as JSON."""
        return json.dumps(data, indent=2, default=str)

    def to_yaml(self, data: Dict[str, Any]) -> str:
        """Format as YAML (requires PyYAML; install with `pip install pyyaml`)."""
        try:
            import yaml
        except ImportError:
            raise RuntimeError(
                "YAML output requires PyYAML. Install with: pip install pyyaml"
            ) from None
        return yaml.safe_dump(
            data,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
        )
    
    def to_table(self, data: Dict) -> str:
        """Format as human-readable table."""
        lines = []
        domain = data.get("domain", "unknown")
        
        lines.append("=" * 60)
        lines.append(f"Scope Attack Surface Report: {domain}")
        lines.append("=" * 60)
        lines.append("")
        
        discovery = data.get("discovery", {})
        
        # Subdomains
        subdomains = discovery.get("subdomains", {})
        all_unique = subdomains.get("all_unique", [])
        lines.append(f"[Subdomains] Found {len(all_unique)} unique subdomains")
        
        for source, items in subdomains.items():
            if source == "all_unique":
                continue
            if isinstance(items, list) and not any(str(i).startswith("Error") for i in items):
                lines.append(f"  - {source}: {len(items)} found")
        
        lines.append("")
        if all_unique:
            lines.append("  Top 10 subdomains:")
            for sub in all_unique[:10]:
                lines.append(f"    - {sub}")
            if len(all_unique) > 10:
                lines.append(f"    ... and {len(all_unique) - 10} more")
        lines.append("")
        
        # Cloud assets
        cloud = discovery.get("cloud_assets", {})
        total_cloud = sum(len(v) for v in cloud.values() if isinstance(v, list))
        lines.append(f"[Cloud Assets] Found {total_cloud} potential assets")
        
        for asset_type, assets in cloud.items():
            if assets:
                lines.append(f"  - {asset_type}: {len(assets)} found")
                for asset in assets[:3]:  # Show first 3
                    if isinstance(asset, dict):
                        name = asset.get("bucket") or asset.get("account") or "unknown"
                        lines.append(f"      {name}")
        lines.append("")
        
        # IP ranges
        ip_data = discovery.get("ip_ranges", {})
        resolutions = ip_data.get("resolutions", [])
        asn_info = ip_data.get("asn_info", [])
        
        lines.append(f"[IP Intelligence] {len(resolutions)} DNS resolutions")
        for res in resolutions:
            lines.append(f"  - {res['ip']} ({res['type']})")
        
        if asn_info:
            lines.append(f"\n  ASN Information:")
            for asn in asn_info:
                lines.append(f"    - {asn.get('asn', 'N/A')}: {asn.get('asn_name', 'Unknown')}")
        
        lines.append("")
        lines.append("=" * 60)
        lines.append("End of Report")
        lines.append("=" * 60)
        
        return "\n".join(lines)
