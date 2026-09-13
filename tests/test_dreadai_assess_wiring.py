"""assess_internal_network must wire the injected prober/connector into spear.assess."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_DREADAI = _REPO / "dreadai"
for p in (str(_REPO), str(_DREADAI)):
    if p not in sys.path:
        sys.path.insert(0, p)

import agent


def test_assess_internal_network_passes_required_probes(monkeypatch):
    sys.path.insert(0, str(_REPO / "spear"))
    import spear

    captured = {}

    def fake_assess(cidr, *, prober, connector, **kwargs):
        captured["prober"] = prober
        captured["connector"] = connector
        return {
            "target": cidr,
            "hosts_up": 2,
            "findings": [],
            "rollups": {"total_findings": 0, "findings_by_severity": {}},
        }

    monkeypatch.setattr(spear, "assess", fake_assess)

    out = agent.assess_internal_network.invoke({"cidr": "10.0.0.0/29"})

    assert out["hosts_up"] == 2
    assert callable(captured["prober"])
    assert callable(captured["connector"])
