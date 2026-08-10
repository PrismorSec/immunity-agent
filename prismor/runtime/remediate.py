"""Turn a shadow-AI finding into the action that governs it.

``prismor discover`` answers "what is running that Prismor does not govern".
This module answers the only follow-up that matters: make it governed.

There is exactly one way to govern an agent Prismor is not hooked into, and it
is not to constrain it — every enforcement surface in the runtime (egress
screening, the Docker sandbox, tool denies, kill switches) sits downstream of a
hook payload, so an unhooked agent produces no event and nothing to act on.
Governing shadow AI therefore means *eliminating the shadow*: install the hook,
move the MCP server behind the gateway, vault the key.

Three levers, one per surface:

    agent       hooks.install_hooks          — shadow agent becomes governed
    mcp         mcp_gateway.install_gateway  — servers move behind the gateway
    credential  cloaking.add_env_secrets     — the key becomes a placeholder

Everything this module cannot fix is reported as *skipped with a reason*, never
silently dropped. A remediation tool that quietly does less than it claims is
worse than one that does nothing, because the report is what the operator then
believes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

#: Filenames ``cloaking.parse_env_file`` can actually read. The credential
#: sweep also flags keys inside JSON/TOML agent configs, which are real
#: findings but not importable by the dotenv parser.
_DOTENV_NAMES = (".env", ".env.local", ".env.development", ".env.production")

FIXABLE_KINDS = ("agent", "mcp", "credential")


@dataclass
class Remediation:
    """One attempted (or declined) fix."""

    kind: str            # agent | mcp | credential
    target: str          # agent name, server name, or provider
    #: planned | fixed | skipped | failed
    status: str
    detail: str = ""
    #: the command a human would run to do this by hand
    command: str = ""
    #: machine-readable subject of the action — the agent id, or the path to
    #: the config/dotenv file. Kept separate from ``detail`` so applying a plan
    #: never has to parse a sentence written for a human.
    subject: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "fixed"


@dataclass
class RemediationPlan:
    """What ``--fix`` would do, before it does any of it."""

    actions: List[Remediation] = field(default_factory=list)

    @property
    def fixable(self) -> List[Remediation]:
        return [a for a in self.actions if a.status == "planned"]

    @property
    def skipped(self) -> List[Remediation]:
        return [a for a in self.actions if a.status == "skipped"]


def _is_dotenv(path: str) -> bool:
    name = Path(path).name
    return name in _DOTENV_NAMES or name.startswith(".env")


# ── planning ─────────────────────────────────────────────────────────────────


def plan(report: Dict[str, Any], *, kinds: Iterable[str] = FIXABLE_KINDS) -> RemediationPlan:
    """Decide what is fixable, without touching anything.

    Separated from ``apply`` so the CLI can show the operator exactly what is
    about to happen to their machine before it happens — this writes to agent
    config files, and a surprise there is expensive to unpick.
    """
    wanted = set(kinds)
    out = RemediationPlan()

    if "agent" in wanted:
        for agent in report.get("agents") or []:
            if agent.get("managed"):
                continue
            name = str(agent.get("name") or agent.get("id") or "")
            agent_id = str(agent.get("id") or "")
            if not agent.get("coverable", True):
                out.actions.append(Remediation(
                    kind="agent", target=name, status="skipped",
                    detail="Prismor has no hook for this agent — it cannot be governed here",
                ))
                continue
            out.actions.append(Remediation(
                kind="agent", target=name, status="planned",
                detail=f"install the global hook for {agent_id}",
                command=f"prismor install-hooks --agent {agent_id} --scope global",
                subject=agent_id,
            ))

    if "mcp" in wanted:
        for server in report.get("mcp") or []:
            if server.get("managed") or server.get("is_gateway"):
                continue
            name = str(server.get("name") or "")
            source = str(server.get("source") or "")
            # install_gateway only rewrites the workspace's own .mcp.json.
            # Servers declared by Claude Desktop, VS Code, Cursor, Zed and the
            # rest are found by discovery but cannot be migrated by it.
            if Path(source).name != ".mcp.json":
                out.actions.append(Remediation(
                    kind="mcp", target=name, status="skipped",
                    detail=f"declared in {source} — the gateway migration only rewrites "
                           f"a workspace .mcp.json; move this one by hand",
                ))
                continue
            out.actions.append(Remediation(
                kind="mcp", target=name, status="planned",
                detail="move behind the Prismor MCP gateway",
                command="prismor mcp-gateway install",
                subject=source,
            ))

    if "credential" in wanted:
        for cred in report.get("credentials") or []:
            if cred.get("managed"):
                continue
            provider = str(cred.get("provider") or "")
            location = str(cred.get("location") or "")
            if cred.get("location_kind") != "file":
                out.actions.append(Remediation(
                    kind="credential", target=provider, status="skipped",
                    detail=f"set in the environment as {location} — export it from a "
                           f"cloaked .env, or register it with `prismor cloak add`",
                ))
                continue
            if not _is_dotenv(location):
                out.actions.append(Remediation(
                    kind="credential", target=provider, status="skipped",
                    detail=f"embedded in {location}, which is not a dotenv file — "
                           f"move the value into .env or cloak it by hand",
                ))
                continue
            out.actions.append(Remediation(
                kind="credential", target=provider, status="planned",
                detail=f"import every key from {location} into Cloak",
                command=f"prismor cloak add --env-file {location}",
                subject=location,
            ))

    return out


# ── applying ─────────────────────────────────────────────────────────────────


def _agent_id_for(report: Dict[str, Any], display_name: str) -> str:
    for agent in report.get("agents") or []:
        if str(agent.get("name") or "") == display_name:
            return str(agent.get("id") or "")
    return display_name


def apply(
    report: Dict[str, Any],
    *,
    repo_root: Path,
    workspace: Path,
    mode: str = "observe",
    kinds: Iterable[str] = FIXABLE_KINDS,
    plan_obj: Optional[RemediationPlan] = None,
) -> List[Remediation]:
    """Carry out every fixable action. Returns one result per attempted action.

    Each lever is isolated: a failure on one agent must not abandon the rest,
    because a partial fix that reports honestly is more useful than an
    all-or-nothing run that leaves the operator guessing which half landed.
    """
    todo = (plan_obj or plan(report, kinds=kinds))
    results: List[Remediation] = list(todo.skipped)

    gateway_done = False
    dotenv_done: set = set()

    for action in todo.fixable:
        if action.kind == "agent":
            results.append(_fix_agent(report, action, repo_root=repo_root,
                                      workspace=workspace, mode=mode))
        elif action.kind == "mcp":
            # One install_gateway call migrates every server in the file, so
            # run it once and attribute the outcome to each server it covered.
            if gateway_done:
                results.append(Remediation(
                    kind="mcp", target=action.target, status="fixed",
                    detail="moved behind the gateway", command=action.command,
                    subject=action.subject))
                continue
            outcome = _fix_mcp(action, workspace=workspace)
            gateway_done = outcome.ok
            results.append(outcome)
        elif action.kind == "credential":
            path = action.subject
            if path in dotenv_done:
                results.append(Remediation(
                    kind="credential", target=action.target, status="fixed",
                    detail=f"imported from {path}", command=action.command,
                    subject=path))
                continue
            outcome = _fix_credential(action, path=path)
            if outcome.ok:
                dotenv_done.add(path)
            results.append(outcome)

    return results


def _fix_agent(report: Dict[str, Any], action: Remediation, *,
               repo_root: Path, workspace: Path, mode: str) -> Remediation:
    agent_id = action.subject or _agent_id_for(report, action.target)
    try:
        from prismor.runtime.hooks import install_hooks, HookConfigError
    except Exception as exc:  # pragma: no cover - import guard
        return Remediation(kind="agent", target=action.target, status="failed",
                           detail=f"could not load the hook installer: {exc}",
                           command=action.command)
    try:
        # Global scope: the point is to govern the agent wherever it runs, not
        # only in whichever directory `discover` happened to be invoked from.
        install_hooks(repo_root=repo_root, workspace=workspace,
                      agent=agent_id, scope="global", mode=mode)
    except HookConfigError as exc:
        return Remediation(kind="agent", target=action.target, status="failed",
                           detail=f"{exc} — fix the file, then re-run",
                           command=action.command)
    except Exception as exc:
        return Remediation(kind="agent", target=action.target, status="failed",
                           detail=str(exc), command=action.command)
    return Remediation(kind="agent", target=action.target, status="fixed",
                       detail=f"global hook installed ({mode} mode)",
                       command=action.command)


def _fix_mcp(action: Remediation, *, workspace: Path) -> Remediation:
    try:
        from prismor.runtime.mcp_gateway import install_gateway
    except Exception as exc:  # pragma: no cover - import guard
        return Remediation(kind="mcp", target=action.target, status="failed",
                           detail=f"could not load the gateway installer: {exc}",
                           command=action.command)
    try:
        summary = install_gateway(workspace)
    except Exception as exc:
        return Remediation(kind="mcp", target=action.target, status="failed",
                           detail=str(exc), command=action.command)
    return Remediation(kind="mcp", target=action.target, status="fixed",
                       detail=str(summary).strip().splitlines()[0] if summary
                       else "moved behind the gateway",
                       command=action.command)


def _fix_credential(action: Remediation, *, path: str) -> Remediation:
    try:
        from prismor.runtime.cloaking import add_env_secrets
    except Exception as exc:  # pragma: no cover - import guard
        return Remediation(kind="credential", target=action.target, status="failed",
                           detail=f"could not load Cloak: {exc}", command=action.command)
    try:
        created = add_env_secrets(Path(path))
    except Exception as exc:
        return Remediation(kind="credential", target=action.target, status="failed",
                           detail=str(exc), command=action.command)
    # Names only — a count and the placeholder names, never a value.
    return Remediation(
        kind="credential", target=action.target, status="fixed",
        detail=f"{len(created)} key(s) imported from {path}; reference them as "
               f"@@SECRET:<name>@@",
        command=action.command,
    )


def summarize(results: List[Remediation]) -> Dict[str, int]:
    out = {"fixed": 0, "skipped": 0, "failed": 0}
    for r in results:
        if r.status in out:
            out[r.status] += 1
    return out
