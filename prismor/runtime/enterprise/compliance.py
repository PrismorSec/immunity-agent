"""Framework-control coverage roll-up for attestation bundles.

Maps Prismor's active policy rules onto named compliance frameworks (OWASP LLM
Top 10, OWASP Agentic, NIST AI RMF, EU AI Act) so a bundle can report which
controls the current enforcement posture covers.

The data lives in ``prismor/runtime/checklists/``: one YAML pack per framework
(control IDs + titles) plus ``crosswalk.v1.yaml`` mapping Prismor rule IDs and
subsystem pseudo-IDs to ``framework:control`` pairs. Both are plain, forkable
YAML — a customer adds a rule mapping without touching Python.

A control is COVERED when at least one mapped rule is active in the effective
policy. Subsystem pseudo-IDs (``subsystem:audit-trail``,
``subsystem:step-up-approval``) are always active — the audit trail ships on,
and step-up is a built-in verdict. This is a statement about what Prismor
enforces, not a legal compliance opinion.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Set

_CHECKLIST_DIR = Path(__file__).resolve().parent.parent / "checklists"

# Subsystem capabilities that are always on, so their mapped controls always
# count. Keep in sync with the `subsystem:` keys in crosswalk.v1.yaml.
_ACTIVE_SUBSYSTEMS = ("subsystem:audit-trail", "subsystem:step-up-approval")


def _load_yaml(path: Path) -> Dict[str, Any]:
    try:
        import yaml
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _load_frameworks() -> Dict[str, Dict[str, Any]]:
    """Load every checklist pack, keyed by framework id."""
    frameworks: Dict[str, Dict[str, Any]] = {}
    if not _CHECKLIST_DIR.is_dir():
        return frameworks
    for f in sorted(_CHECKLIST_DIR.glob("*.yaml")):
        if f.name.startswith("crosswalk"):
            continue
        data = _load_yaml(f)
        fid = data.get("framework")
        if fid:
            frameworks[fid] = data
    return frameworks


def _load_crosswalk() -> Dict[str, List[str]]:
    data = _load_yaml(_CHECKLIST_DIR / "crosswalk.v1.yaml")
    mapping = data.get("map")
    return mapping if isinstance(mapping, dict) else {}


def active_rule_ids(workspace: Optional[Path]) -> Set[str]:
    """The rule IDs enabled in the effective policy for ``workspace``."""
    try:
        from prismor.runtime.policy_engine import PolicyEngine
        engine = PolicyEngine(workspace=workspace)
        return {r.id for r in getattr(engine, "rules", [])}
    except Exception:
        return set()


def coverage(workspace: Optional[Path] = None) -> Dict[str, Any]:
    """Roll active rules up into per-framework control coverage.

    Returns::

        {
          "frameworks": [
            {"framework", "title", "version",
             "covered": int, "total": int,
             "controls": [{"id", "title", "covered": bool,
                           "by": [rule_ids...]}]}
          ],
          "summary": {"controls_covered": int, "controls_total": int}
        }
    """
    frameworks = _load_frameworks()
    crosswalk = _load_crosswalk()
    active = active_rule_ids(workspace)
    active |= set(_ACTIVE_SUBSYSTEMS)

    # Invert the crosswalk: control -> [active rule/subsystem ids covering it].
    covered_by: Dict[str, List[str]] = {}
    for rule_id, controls in crosswalk.items():
        if rule_id not in active or not isinstance(controls, list):
            continue
        for control in controls:
            covered_by.setdefault(control, []).append(rule_id)

    out_frameworks: List[Dict[str, Any]] = []
    total_covered = total_controls = 0
    for fid, pack in frameworks.items():
        controls_out: List[Dict[str, Any]] = []
        f_covered = 0
        for ctrl in pack.get("controls", []) or []:
            cid = ctrl.get("id")
            key = f"{fid}:{cid}"
            by = sorted(covered_by.get(key, []))
            is_covered = bool(by)
            if is_covered:
                f_covered += 1
            controls_out.append({
                "id": cid,
                "title": ctrl.get("title"),
                "covered": is_covered,
                "by": by,
            })
        total_covered += f_covered
        total_controls += len(controls_out)
        out_frameworks.append({
            "framework": fid,
            "title": pack.get("title"),
            "version": pack.get("version"),
            "covered": f_covered,
            "total": len(controls_out),
            "controls": controls_out,
        })

    return {
        "frameworks": out_frameworks,
        "summary": {
            "controls_covered": total_covered,
            "controls_total": total_controls,
            "frameworks": len(out_frameworks),
        },
    }
