"""Tests for framework-control coverage (enterprise/compliance.py).

Verifies the checklist packs + crosswalk load, that coverage rolls active
policy rules onto framework controls, that disabling the sole rule mapping a
control drops that control, and that every crosswalk control ID actually
exists in a shipped pack (no dangling references).

Run: python3 -m pytest tests/test_compliance.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime.enterprise import compliance


def test_frameworks_and_crosswalk_load():
    frameworks = compliance._load_frameworks()
    assert set(frameworks) >= {
        "owasp-llm-top10", "owasp-agentic-t10", "nist-ai-rmf", "eu-ai-act",
        "soc2", "iso-42001",
    }
    crosswalk = compliance._load_crosswalk()
    assert crosswalk and "destructive-command" in crosswalk


def test_default_policy_covers_all_controls(tmp_path):
    """The bundled default policy activates a rule for every mapped control."""
    cov = compliance.coverage(tmp_path)
    s = cov["summary"]
    assert s["frameworks"] == 6
    assert s["controls_total"] > 0
    assert s["controls_covered"] == s["controls_total"]


def test_soc2_and_iso42001_controls_are_covered(tmp_path):
    """The two frameworks added alongside NIST/EU AI Act are fully mapped
    under the default policy, same guarantee as the original four."""
    cov = compliance.coverage(tmp_path)
    soc2 = next(f for f in cov["frameworks"] if f["framework"] == "soc2")
    iso = next(f for f in cov["frameworks"] if f["framework"] == "iso-42001")
    assert soc2["covered"] == soc2["total"] and soc2["total"] >= 5
    assert iso["covered"] == iso["total"] and iso["total"] >= 3

    cc72 = next(c for c in soc2["controls"] if c["id"] == "CC7.2")
    assert cc72["covered"] and "subsystem:audit-trail" in cc72["by"]


def test_coverage_attributes_controls_to_real_rules(tmp_path):
    cov = compliance.coverage(tmp_path)
    llm = next(f for f in cov["frameworks"] if f["framework"] == "owasp-llm-top10")
    llm01 = next(c for c in llm["controls"] if c["id"] == "LLM01")
    assert llm01["covered"]
    assert "prompt-injection" in llm01["by"]


def test_subsystem_controls_are_always_active(tmp_path):
    """Audit-trail and step-up map controls that don't correspond to a policy
    rule; they must count as covered regardless of policy."""
    cov = compliance.coverage(tmp_path)
    eu = next(f for f in cov["frameworks"] if f["framework"] == "eu-ai-act")
    art12 = next(c for c in eu["controls"] if c["id"] == "ART12")
    assert art12["covered"] and "subsystem:audit-trail" in art12["by"]


def test_disabling_sole_mapper_drops_control(tmp_path):
    """model-manipulation is the only rule mapping OWASP LLM05; disable it and
    LLM05 becomes uncovered."""
    policy_dir = tmp_path / ".prismor"
    policy_dir.mkdir()
    (policy_dir / "policy.yaml").write_text(
        'version: "1.0"\n'
        "rules:\n"
        "  - id: model-manipulation\n"
        "    enabled: false\n",
        encoding="utf-8",
    )
    cov = compliance.coverage(tmp_path)
    llm = next(f for f in cov["frameworks"] if f["framework"] == "owasp-llm-top10")
    llm05 = next(c for c in llm["controls"] if c["id"] == "LLM05")
    assert not llm05["covered"] and llm05["by"] == []


def test_crosswalk_control_ids_exist_in_packs():
    """No crosswalk entry may point at a control ID that isn't in a pack."""
    frameworks = compliance._load_frameworks()
    valid = {
        f"{fid}:{c['id']}"
        for fid, pack in frameworks.items()
        for c in pack.get("controls", [])
    }
    dangling = []
    for rule_id, controls in compliance._load_crosswalk().items():
        for pair in controls or []:
            if pair not in valid:
                dangling.append(f"{rule_id} -> {pair}")
    assert not dangling, f"crosswalk points at unknown controls: {dangling}"


def test_crosswalk_rule_ids_are_real_or_subsystem():
    """Every crosswalk key is either a real default-policy rule ID or a
    declared subsystem pseudo-ID — catches typos that would silently never
    match."""
    from prismor.runtime.policy_engine import PolicyEngine
    engine = PolicyEngine()
    real_rules = {r.id for r in engine.rules}
    allowed = real_rules | set(compliance._ACTIVE_SUBSYSTEMS)
    unknown = [k for k in compliance._load_crosswalk() if k not in allowed]
    assert not unknown, f"crosswalk references unknown rule IDs: {unknown}"
