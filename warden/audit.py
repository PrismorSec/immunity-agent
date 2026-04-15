"""Security posture audit for Prismor Warden.

Performs a single-shot check across all Warden subsystems:
  1. Hook integrations     — are hooks installed? which agents? what mode?
  2. Policy coverage       — disabled rules, missing block categories
  3. Cloaking status       — hooks installed? secrets registered?
  4. Secret permissions    — directory and file modes (0700 / 0600)
  5. Feed signature        — Ed25519 signature verification
  6. Egress allowlist      — is network lockdown configured?
  7. Network isolation     — are network rules enabled?

Each check returns findings with a severity, a human-readable message,
and an optional auto-fix function for ``warden audit --fix``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import stat
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from warden.policy_engine import PolicyEngine, _load_yaml


# ── Finding model ───────────────────────────────────────────────────────────

class AuditFinding:
    """A single audit finding."""

    __slots__ = ("severity", "category", "message", "fix_label", "fix_fn")

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "PASS": 5}

    def __init__(
        self,
        severity: str,
        category: str,
        message: str,
        fix_label: Optional[str] = None,
        fix_fn: Optional[Callable[[], str]] = None,
    ) -> None:
        self.severity = severity
        self.category = category
        self.message = message
        self.fix_label = fix_label
        self.fix_fn = fix_fn

    @property
    def fixable(self) -> bool:
        return self.fix_fn is not None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
        }
        if self.fix_label:
            d["fixable"] = True
            d["fix"] = self.fix_label
        return d


# ── Audit runner ────────────────────────────────────────────────────────────

def run_audit(
    workspace: Path,
    repo_root: Path,
) -> List[AuditFinding]:
    """Run all audit checks. Returns findings sorted by severity."""
    findings: List[AuditFinding] = []

    findings.extend(_check_hooks(workspace, repo_root))
    findings.extend(_check_policy(workspace))
    findings.extend(_check_cloaking(workspace))
    findings.extend(_check_secret_permissions())
    findings.extend(_check_feed_signature(repo_root))
    findings.extend(_check_egress_allowlist(workspace))
    findings.extend(_check_network_rules(workspace))

    findings.sort(key=lambda f: AuditFinding.SEVERITY_ORDER.get(f.severity, 99))
    return findings


def apply_fixes(findings: List[AuditFinding]) -> List[str]:
    """Run all available auto-fixes. Returns list of actions taken."""
    actions: List[str] = []
    for f in findings:
        if f.fix_fn is not None:
            result = f.fix_fn()
            if result:
                actions.append(result)
    return actions


# ── Individual checks ───────────────────────────────────────────────────────

def _check_hooks(workspace: Path, repo_root: Path) -> List[AuditFinding]:
    """Check hook installation across agents."""
    findings: List[AuditFinding] = []
    agents_config = {
        "claude": workspace / ".claude" / "settings.json",
        "cursor": workspace / ".cursor" / "hooks.json",
        "windsurf": workspace / ".windsurf" / "hooks.json",
        "openclaw": workspace / ".openclaw" / "plugins.json",
        "hermes": workspace / ".hermes" / "plugins.json",
    }

    installed_agents: List[str] = []
    mode_found: Optional[str] = None

    for agent, config_path in agents_config.items():
        if not config_path.exists():
            continue
        try:
            content = config_path.read_text(encoding="utf-8")
        except OSError:
            continue

        if "warden" in content.lower() or "prismor" in content.lower():
            installed_agents.append(agent)
            if mode_found is None:
                if "--mode enforce" in content:
                    mode_found = "enforce"
                elif "--mode observe" in content:
                    mode_found = "observe"

    if not installed_agents:
        def _fix_install_hooks() -> str:
            from warden.hooks import install_hooks
            from warden.store import register_workspace
            install_hooks(
                repo_root=repo_root,
                workspace=workspace,
                agent="all",
                scope="project",
                mode="enforce",
            )
            register_workspace(workspace)
            return "Installed Warden hooks for all agents in enforce mode"

        findings.append(AuditFinding(
            severity="CRITICAL",
            category="hooks",
            message="No Warden hooks installed — agent actions are not monitored",
            fix_label="Install hooks for all agents (enforce mode)",
            fix_fn=_fix_install_hooks,
        ))
    else:
        findings.append(AuditFinding(
            severity="PASS",
            category="hooks",
            message=f"Hooks installed: {', '.join(installed_agents)}",
        ))

        if mode_found == "observe":
            findings.append(AuditFinding(
                severity="MEDIUM",
                category="hooks",
                message="Hooks are in observe mode — dangerous actions are logged but not blocked",
            ))
        elif mode_found == "enforce":
            findings.append(AuditFinding(
                severity="PASS",
                category="hooks",
                message="Hooks running in enforce mode",
            ))

    return findings


def _check_policy(workspace: Path) -> List[AuditFinding]:
    """Check policy coverage — disabled rules, missing categories."""
    findings: List[AuditFinding] = []

    engine = PolicyEngine(workspace=workspace)
    default_path = Path(__file__).resolve().parent / "default_policy.yaml"
    default_data = _load_yaml(default_path)

    if default_data is None:
        findings.append(AuditFinding(
            severity="HIGH",
            category="policy",
            message="Cannot load default policy — rule engine may be broken",
        ))
        return findings

    total_rules = len(default_data.get("rules", []))
    active_rules = len(engine.rules)
    disabled = total_rules - active_rules

    if disabled > 0:
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="policy",
            message=f"{disabled} of {total_rules} default rules are disabled",
        ))
    else:
        findings.append(AuditFinding(
            severity="PASS",
            category="policy",
            message=f"All {total_rules} default rules are active",
        ))

    # Check for project-level policy
    project_policy = workspace / ".prismor-warden" / "policy.yaml"
    if project_policy.exists():
        findings.append(AuditFinding(
            severity="PASS",
            category="policy",
            message="Project-level policy overrides present",
        ))

    return findings


def _check_cloaking(workspace: Path) -> List[AuditFinding]:
    """Check cloaking hook installation and secret registration."""
    findings: List[AuditFinding] = []

    try:
        from warden.cloaking import status as cloak_status, list_secrets, secrets_dir
    except ImportError:
        findings.append(AuditFinding(
            severity="HIGH",
            category="cloaking",
            message="Cloaking module not available",
        ))
        return findings

    result = cloak_status(workspace=workspace, scope="project")

    if not result["installed"]:
        def _fix_install_cloak() -> str:
            from warden.cloaking import install as cloak_install
            cloak_install(workspace=workspace, scope="project")
            return "Installed cloaking hooks at project scope"

        findings.append(AuditFinding(
            severity="HIGH",
            category="cloaking",
            message="Cloaking hooks not installed — secrets are not protected at the tool boundary",
            fix_label="Install cloaking hooks (project scope)",
            fix_fn=_fix_install_cloak,
        ))
    else:
        events = result.get("events", [])
        findings.append(AuditFinding(
            severity="PASS",
            category="cloaking",
            message=f"Cloaking hooks installed ({len(events)} hook event(s))",
        ))

    secrets = list_secrets()
    if not secrets:
        findings.append(AuditFinding(
            severity="LOW",
            category="cloaking",
            message="No secrets registered — consider registering secrets with `warden cloak add`",
        ))
    else:
        findings.append(AuditFinding(
            severity="PASS",
            category="cloaking",
            message=f"{len(secrets)} secret(s) registered",
        ))

    return findings


def _check_secret_permissions() -> List[AuditFinding]:
    """Check filesystem permissions on secrets directory and files."""
    findings: List[AuditFinding] = []

    try:
        from warden.cloaking.secrets_store import secrets_dir, check_permissions
    except ImportError:
        return findings

    sdir = secrets_dir()
    if not sdir.exists():
        # No secrets dir yet — not an issue
        return findings

    warnings = check_permissions()
    if warnings:
        def _fix_permissions() -> str:
            fixed = 0
            sdir_inner = secrets_dir()
            try:
                sdir_inner.chmod(0o700)
                fixed += 1
            except PermissionError:
                pass
            for child in sdir_inner.iterdir():
                if child.is_file():
                    try:
                        child.chmod(0o600)
                        fixed += 1
                    except PermissionError:
                        pass
            return f"Fixed permissions on {fixed} path(s) in {sdir_inner}"

        for w in warnings:
            findings.append(AuditFinding(
                severity="HIGH",
                category="permissions",
                message=w,
                fix_label="Set directory to 0700 and files to 0600",
                fix_fn=_fix_permissions,
            ))
    else:
        findings.append(AuditFinding(
            severity="PASS",
            category="permissions",
            message="Secret file permissions are correct (0700/0600)",
        ))

    return findings


def _check_feed_signature(repo_root: Path) -> List[AuditFinding]:
    """Verify the advisory feed Ed25519 signature."""
    findings: List[AuditFinding] = []

    feed_path = repo_root / "advisories" / "immunity-feed.json"
    sig_path = repo_root / "advisories" / "immunity-feed.json.sig"
    pub_key = repo_root / "keys" / "public.pub"

    if not feed_path.exists():
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="feed",
            message="Advisory feed not found — threat intelligence not available",
        ))
        return findings

    if not sig_path.exists():
        findings.append(AuditFinding(
            severity="HIGH",
            category="feed",
            message="Feed signature file missing — cannot verify feed integrity",
        ))
        return findings

    if not pub_key.exists():
        findings.append(AuditFinding(
            severity="HIGH",
            category="feed",
            message="Public key not found — cannot verify feed signature",
        ))
        return findings

    # Check if openssl is available
    if not shutil.which("openssl"):
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="feed",
            message="openssl not found — cannot verify feed signature",
        ))
        return findings

    # Verify signature
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            sig_b64 = sig_path.read_bytes()
            import base64
            tmp.write(base64.b64decode(sig_b64))
            tmp_path = tmp.name

        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify",
                "-pubin", "-inkey", str(pub_key),
                "-rawin",
                "-in", str(feed_path),
                "-sigfile", tmp_path,
            ],
            capture_output=True,
            timeout=10,
        )
        os.unlink(tmp_path)

        if result.returncode == 0:
            # Also report advisory count
            try:
                feed_data = json.loads(feed_path.read_text(encoding="utf-8"))
                n_advisories = len(feed_data.get("advisories", []))
                findings.append(AuditFinding(
                    severity="PASS",
                    category="feed",
                    message=f"Feed signature valid — {n_advisories} advisories loaded",
                ))
            except Exception:
                findings.append(AuditFinding(
                    severity="PASS",
                    category="feed",
                    message="Feed signature valid",
                ))
        else:
            findings.append(AuditFinding(
                severity="CRITICAL",
                category="feed",
                message="Feed signature verification FAILED — feed may be tampered with",
            ))
    except Exception as exc:
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="feed",
            message=f"Feed signature check error: {exc}",
        ))

    return findings


def _check_egress_allowlist(workspace: Path) -> List[AuditFinding]:
    """Check if an egress allowlist is configured."""
    findings: List[AuditFinding] = []

    engine = PolicyEngine(workspace=workspace)

    if engine.egress_allowlist:
        findings.append(AuditFinding(
            severity="PASS",
            category="network",
            message=f"Egress allowlist configured with {len(engine.egress_allowlist)} domain(s)",
        ))
    else:
        findings.append(AuditFinding(
            severity="LOW",
            category="network",
            message="No egress allowlist configured — all outbound domains are permitted",
        ))

    return findings


def _check_network_rules(workspace: Path) -> List[AuditFinding]:
    """Check that network isolation rules are enabled."""
    findings: List[AuditFinding] = []

    engine = PolicyEngine(workspace=workspace)
    network_rule_ids = {
        "raw-ip-outbound", "bind-all-interfaces",
        "reverse-tunnel", "network-exfil-tool", "suspicious-network",
    }

    active_ids = {r.id for r in engine.rules}
    active_network = network_rule_ids & active_ids
    missing_network = network_rule_ids - active_ids

    if missing_network:
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="network",
            message=f"Network isolation rules disabled: {', '.join(sorted(missing_network))}",
        ))
    else:
        findings.append(AuditFinding(
            severity="PASS",
            category="network",
            message=f"All {len(network_rule_ids)} network isolation rules active",
        ))

    return findings
