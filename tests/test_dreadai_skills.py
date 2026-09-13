"""DreadAI security-skill catalog: discover + load Trail of Bits / secskills methodology."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_DREADAI = _REPO / "dreadai"
for p in (str(_REPO), str(_DREADAI)):
    if p not in sys.path:
        sys.path.insert(0, p)

import skills as dreadai_skills


def _make_skill(root: Path, plugin: str, version: str, name: str,
                description: str, body: str = "# Body\n", extra_files=None):
    d = root / plugin / version / "skills" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\n---\n\n{body}")
    for fname in (extra_files or []):
        (d / fname).write_text("supporting\n")
    return d


@pytest.fixture
def skill_root(tmp_path, monkeypatch):
    root = tmp_path / "cache"
    _make_skill(root, "trailofbits", "1.0.0", "differential-review",
                "Security-focused diff review.")
    _make_skill(root, "secskills-offense", "4.6.0", "attacking-jwt",
                "Attack JWTs: alg:none, key confusion.")
    monkeypatch.setenv("DREADAI_SKILL_ROOTS", str(root))
    return root


def test_discover_finds_skills_across_plugins(skill_root):
    catalog = dreadai_skills.discover_skills()
    assert "trailofbits:differential-review" in catalog
    assert "secskills-offense:attacking-jwt" in catalog
    assert "diff review" in catalog["trailofbits:differential-review"]["description"].lower()


def test_latest_version_wins(tmp_path, monkeypatch):
    root = tmp_path / "cache"
    _make_skill(root, "static-analysis", "1.4.3", "codeql", "OLD codeql.")
    _make_skill(root, "static-analysis", "4.6.0", "codeql", "NEW codeql.")
    monkeypatch.setenv("DREADAI_SKILL_ROOTS", str(root))

    catalog = dreadai_skills.discover_skills()
    assert catalog["static-analysis:codeql"]["description"] == "NEW codeql."


def test_load_skill_by_full_id_returns_content(skill_root):
    loaded = dreadai_skills.load_skill("secskills-offense:attacking-jwt")
    assert "# Body" in loaded["content"]
    assert loaded["id"] == "secskills-offense:attacking-jwt"


def test_load_skill_by_bare_name(skill_root):
    loaded = dreadai_skills.load_skill("attacking-jwt")
    assert loaded["id"] == "secskills-offense:attacking-jwt"


def test_load_skill_truncates_and_lists_supporting_files(tmp_path, monkeypatch):
    root = tmp_path / "cache"
    _make_skill(root, "trailofbits", "1.0.0", "big-skill", "Huge skill.",
                body="X" * 50_000, extra_files=["patterns.md", "methodology.md"])
    monkeypatch.setenv("DREADAI_SKILL_ROOTS", str(root))

    loaded = dreadai_skills.load_skill("big-skill", max_chars=1000)
    assert loaded["truncated"] is True
    assert len(loaded["content"]) < 2000           # truncated from 50k (+ a short notice)
    assert loaded["content"].rstrip().endswith("...]")
    assert set(loaded["supporting_files"]) == {"patterns.md", "methodology.md"}


def test_load_unknown_skill_reports_error_with_suggestions(skill_root):
    loaded = dreadai_skills.load_skill("attacking-jwtt")   # typo
    assert "error" in loaded
    assert any("attacking-jwt" in s for s in loaded.get("did_you_mean", []))


def test_missing_roots_are_graceful(tmp_path, monkeypatch):
    monkeypatch.setenv("DREADAI_SKILL_ROOTS", str(tmp_path / "does-not-exist"))
    assert dreadai_skills.discover_skills() == {}


def test_agent_registers_and_invokes_security_skill_tools(skill_root):
    import agent

    names = {t.name for t in agent.TOOLS}
    assert {"list_security_skills", "load_security_skill"} <= names

    listed = agent.list_security_skills.invoke({"query": "jwt"})
    assert any("attacking-jwt" in s["id"] for s in listed["skills"])

    loaded = agent.load_security_skill.invoke({"name": "attacking-jwt"})
    assert loaded["id"] == "secskills-offense:attacking-jwt"
    assert "# Body" in loaded["content"]
