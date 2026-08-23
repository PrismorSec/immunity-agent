"""Tests for per-workspace scoping (managed vs personal).

Invariants:
  * Not enrolled → always local (nothing to report to).
  * Org claims a repo (pattern) → managed, and a developer CANNOT downgrade it.
  * No patterns set → manage everything (backward-compatible), but a dev can
    opt a personal repo out.
  * Patterns set → non-matching repos are personal by default; dev can opt in.
  * git remote detection from .git/config (https + ssh forms).
"""
from __future__ import annotations

import json
import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    yield


_counter = [0]


def _git_repo(tmp_path, url):
    _counter[0] += 1
    ws = tmp_path / f"repo{_counter[0]}"
    (ws / ".git").mkdir(parents=True)
    (ws / ".git" / "config").write_text(
        f'[remote "origin"]\n\turl = {url}\n\tfetch = +refs/heads/*\n', encoding="utf-8"
    )
    return ws


def _enroll():
    from prismor.runtime.enterprise import identity
    identity.save_identity({"device_id": "d", "org_id": "o", "user_id": "u",
                            "device_key": "prism_dev_x", "org_name": "Acme", "api_base": "http://x"})


def test_git_remote_detection(tmp_path):
    from prismor.runtime.enterprise import workspace_scope as ws
    assert ws.detect_git_remote(_git_repo(tmp_path, "https://github.com/acme/payments.git")) == "github.com/acme/payments"
    assert ws.detect_git_remote(_git_repo(tmp_path, "git@github.com:Acme/Payments.git")) == "github.com/acme/payments"
    assert ws.detect_git_remote(tmp_path / "not-a-repo") is None


def test_not_enrolled_is_local(tmp_path):
    from prismor.runtime.enterprise import workspace_scope as ws
    info = ws.resolve_scope(_git_repo(tmp_path, "https://github.com/acme/x"))
    assert info["scope"] == "local" and info["reason"] == "not_enrolled"


def test_revoked_device_falls_back_to_local(tmp_path, monkeypatch):
    from prismor.runtime.enterprise import workspace_scope as ws
    from prismor.runtime.enterprise import identity
    _enroll()
    identity.mark_revoked("device deleted by admin")
    monkeypatch.setattr(ws, "org_managed_patterns", lambda: ["github.com/acme/*"])
    info = ws.resolve_scope(_git_repo(tmp_path, "https://github.com/acme/payments"))
    assert info["scope"] == "local" and info["reason"] == "revoked"


def test_revoked_device_is_not_reported_as_enrolled():
    from prismor.runtime.enterprise import identity
    from prismor.runtime.store import get_enrollment
    _enroll()
    identity.mark_revoked("device deleted by admin")
    assert identity.is_enrolled() is False
    assert get_enrollment() is None


def test_no_patterns_manages_everything(tmp_path, monkeypatch):
    from prismor.runtime.enterprise import workspace_scope as ws
    _enroll()
    monkeypatch.setattr(ws, "org_managed_patterns", lambda: [])
    info = ws.resolve_scope(_git_repo(tmp_path, "https://github.com/someone/sideproject"))
    assert info["scope"] == "managed" and info["reason"] == "default_all"


def test_dev_can_opt_out_personal_when_no_patterns(tmp_path, monkeypatch):
    from prismor.runtime.enterprise import workspace_scope as ws
    _enroll()
    monkeypatch.setattr(ws, "org_managed_patterns", lambda: [])
    repo = _git_repo(tmp_path, "https://github.com/me/hobby")
    ws.set_override(repo, "personal")
    assert ws.is_managed(repo) is False


def test_org_claimed_repo_is_managed_and_cannot_downgrade(tmp_path, monkeypatch):
    from prismor.runtime.enterprise import workspace_scope as ws
    _enroll()
    monkeypatch.setattr(ws, "org_managed_patterns", lambda: ["github.com/acme/*"])
    repo = _git_repo(tmp_path, "https://github.com/acme/payments")
    # Even with a 'personal' override, a claimed company repo stays managed.
    ws.set_override(repo, "personal")
    info = ws.resolve_scope(repo)
    assert info["scope"] == "managed" and info["reason"] == "org_claimed"


def test_non_claimed_repo_is_personal_when_patterns_set(tmp_path, monkeypatch):
    from prismor.runtime.enterprise import workspace_scope as ws
    _enroll()
    monkeypatch.setattr(ws, "org_managed_patterns", lambda: ["github.com/acme/*"])
    info = ws.resolve_scope(_git_repo(tmp_path, "https://github.com/me/sideproject"))
    assert info["scope"] == "local" and info["reason"] == "personal"


def test_dev_opt_in_managed(tmp_path, monkeypatch):
    from prismor.runtime.enterprise import workspace_scope as ws
    _enroll()
    monkeypatch.setattr(ws, "org_managed_patterns", lambda: ["github.com/acme/*"])
    repo = _git_repo(tmp_path, "https://github.com/me/work-related")
    ws.set_override(repo, "managed")
    assert ws.is_managed(repo) is True


def test_hostless_pattern_matches(tmp_path, monkeypatch):
    from prismor.runtime.enterprise import workspace_scope as ws
    _enroll()
    monkeypatch.setattr(ws, "org_managed_patterns", lambda: ["acme/*"])
    assert ws.is_managed(_git_repo(tmp_path, "https://github.com/acme/svc")) is True


def test_policy_engine_skips_remote_for_personal(tmp_path, monkeypatch):
    """The org policy overlay (and its telemetry sink) must NOT be merged for a
    personal workspace."""
    from prismor.runtime.enterprise import workspace_scope as ws
    from prismor.runtime.policy_engine import PolicyEngine
    _enroll()
    monkeypatch.setattr(ws, "org_managed_patterns", lambda: ["github.com/acme/*"])
    personal = _git_repo(tmp_path, "https://github.com/me/hobby")
    engine = PolicyEngine(workspace=personal)
    assert engine.workspace_managed is False
    # No prismor telemetry sink should be present for a personal workspace.
    assert not any(str(o.get("type", "")).lower() == "prismor" for o in (engine.outputs or []))


def test_org_can_disable_personal_workspaces(tmp_path, monkeypatch):
    """allow_personal_workspaces=false → every workspace is managed: the
    personal override, the env opt-out, and the non-claimed default all lose.
    (Scope is keyed on the git remote, which a dev can rewrite — this is the
    org's only way to close that.)"""
    from prismor.runtime.enterprise import workspace_scope as ws
    _enroll()
    monkeypatch.setattr(ws, "_org_settings", lambda: {
        "managed_repo_patterns": ["github.com/acme/*"], "allow_personal_workspaces": False})
    repo = _git_repo(tmp_path, "https://github.com/me/remote-rewritten-to-dodge-acme")
    ws.set_override(repo, "personal")
    monkeypatch.setenv("PRISMOR_WORKSPACE_SCOPE", "personal")
    info = ws.resolve_scope(repo)
    assert info["scope"] == "managed" and info["reason"] == "org_no_personal"
    # An org-claimed repo still reports the more specific reason.
    assert ws.resolve_scope(_git_repo(tmp_path, "https://github.com/acme/x"))["reason"] == "org_claimed"
    # Default stays permissive when the key is absent.
    monkeypatch.setattr(ws, "_org_settings", lambda: {"managed_repo_patterns": ["github.com/acme/*"]})
    monkeypatch.delenv("PRISMOR_WORKSPACE_SCOPE")
    assert ws.resolve_scope(repo)["reason"] == "opt_out"
