"""Docker-backed sandbox runner for Warden shell commands.

The sandbox is defense in depth: Warden policy still decides whether a command
is allowed, then this module constrains where the allowed command executes.
"""
from __future__ import annotations

import base64
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_SANDBOX_CONFIG: Dict[str, Any] = {
    "enabled": False,
    "backend": "docker",
    "mode": "observe",
    "image": "python:3.12-slim",
    "workdir": "/workspace",
    "network": "none",
    "workspace_mount": "rw",
    "read_only_root": True,
    "tmpfs": ["/tmp:noexec,nosuid,size=256m"],
    "env_allowlist": ["NO_COLOR", "TERM"],
    "resource_limits": {
        "cpus": "1.0",
        "memory": "1g",
        "pids_limit": 256,
        "timeout_seconds": 300,
    },
}

_VALID_NETWORKS = {"none", "bridge", "host", "allowlist"}
_VALID_MOUNTS = {"ro", "rw"}


def effective_config(raw: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return sandbox config with safe defaults applied."""
    cfg = _deep_merge(DEFAULT_SANDBOX_CONFIG, raw or {})
    cfg["backend"] = str(cfg.get("backend") or "docker").lower()
    cfg["mode"] = str(cfg.get("mode") or "observe").lower()
    cfg["network"] = str(cfg.get("network") or "none").lower()
    cfg["workspace_mount"] = str(cfg.get("workspace_mount") or "rw").lower()

    if cfg["backend"] != "docker":
        cfg["backend"] = "docker"
    if cfg["mode"] not in {"observe", "enforce"}:
        cfg["mode"] = "observe"
    if cfg["network"] not in _VALID_NETWORKS:
        cfg["network"] = "none"
    if cfg["workspace_mount"] not in _VALID_MOUNTS:
        cfg["workspace_mount"] = "rw"
    if not isinstance(cfg.get("tmpfs"), list):
        cfg["tmpfs"] = []
    if not isinstance(cfg.get("env_allowlist"), list):
        cfg["env_allowlist"] = []
    if not isinstance(cfg.get("resource_limits"), dict):
        cfg["resource_limits"] = {}
    return cfg


def is_enabled(raw: Optional[Dict[str, Any]]) -> bool:
    return bool(effective_config(raw).get("enabled"))


def docker_status() -> Dict[str, Any]:
    """Return Docker CLI/server availability without mutating state."""
    docker = shutil.which("docker")
    status: Dict[str, Any] = {
        "backend": "docker",
        "cli_found": bool(docker),
        "cli_path": docker,
        "server_reachable": False,
    }
    if not docker:
        status["error"] = "docker CLI not found"
        return status
    try:
        result = subprocess.run(
            [docker, "info", "--format", "{{json .ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        status["error"] = str(exc)
        return status
    status["server_reachable"] = result.returncode == 0
    if result.returncode == 0:
        status["server_version"] = result.stdout.strip().strip('"')
    else:
        status["error"] = (result.stderr or result.stdout).strip()
    return status


def encode_command(command: str) -> str:
    return base64.urlsafe_b64encode(command.encode("utf-8")).decode("ascii")


def decode_command(encoded: str) -> str:
    return base64.urlsafe_b64decode(encoded.encode("ascii")).decode("utf-8")


def hook_update_command(*, command: str, workspace: Path, mode: str) -> str:
    """Build the safe host command used in Claude's updated Bash input."""
    py = shlex.quote(sys.executable or "python3")
    ws = shlex.quote(str(workspace))
    encoded = shlex.quote(encode_command(command))
    mode_arg = shlex.quote(mode)
    return f"{py} -m warden.immunity_cli sandbox --workspace {ws} run --mode {mode_arg} --encoded {encoded}"


def claude_updated_input(payload: Dict[str, Any], *, workspace: Path, mode: str) -> Optional[Dict[str, Any]]:
    """Return Claude hook JSON that rewrites Bash input into sandbox execution."""
    if payload.get("tool_name") != "Bash":
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    command = str(tool_input.get("command") or "")
    if not command:
        return None
    new_input = dict(tool_input)
    new_input["command"] = hook_update_command(command=command, workspace=workspace, mode=mode)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": new_input,
        }
    }


def build_docker_argv(command: str, *, workspace: Path, config: Dict[str, Any]) -> List[str]:
    """Build a Docker argv list. The original command is never interpolated locally."""
    cfg = effective_config(config)
    docker = shutil.which("docker") or "docker"
    limits = cfg.get("resource_limits") or {}
    workspace = workspace.resolve()
    workdir = str(cfg.get("workdir") or "/workspace")
    image = str(cfg.get("image") or DEFAULT_SANDBOX_CONFIG["image"])
    network = cfg.get("network") or "none"
    if network == "allowlist":
        # Docker cannot enforce domain allowlists by itself. Fail closed by
        # using no network; hook-level egress findings still explain intent.
        network = "none"

    mount_spec = f"type=bind,src={workspace},dst={workdir}"
    if cfg["workspace_mount"] == "ro":
        mount_spec += ",readonly"

    argv = [
        docker,
        "run",
        "--rm",
        "--network",
        str(network),
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--workdir",
        workdir,
        "--mount",
        mount_spec,
    ]

    if cfg.get("read_only_root", True):
        argv.append("--read-only")
    for entry in cfg.get("tmpfs") or []:
        if entry:
            argv.extend(["--tmpfs", str(entry)])

    if hasattr(os, "getuid") and hasattr(os, "getgid"):
        argv.extend(["--user", f"{os.getuid()}:{os.getgid()}"])

    if limits.get("cpus"):
        argv.extend(["--cpus", str(limits["cpus"])])
    if limits.get("memory"):
        argv.extend(["--memory", str(limits["memory"])])
    if limits.get("pids_limit"):
        argv.extend(["--pids-limit", str(limits["pids_limit"])])

    for name in cfg.get("env_allowlist") or []:
        name = str(name)
        if name in os.environ:
            argv.extend(["--env", f"{name}={os.environ[name]}"])

    argv.extend([image, "/bin/sh", "-lc", command])
    return argv


def run(command: str, *, workspace: Path, config: Dict[str, Any]) -> int:
    """Run command inside the configured Docker sandbox."""
    cfg = effective_config(config)
    status = docker_status()
    if not status.get("cli_found") or not status.get("server_reachable"):
        sys.stderr.write(f"Prismor sandbox unavailable: {status.get('error') or 'Docker is not reachable'}\n")
        return 127

    argv = build_docker_argv(command, workspace=workspace, config=cfg)
    timeout = cfg.get("resource_limits", {}).get("timeout_seconds", 300)
    try:
        proc = subprocess.run(argv, timeout=float(timeout) if timeout else None)
        return int(proc.returncode)
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"Prismor sandbox timed out after {timeout} second(s)\n")
        return 124
    except OSError as exc:
        sys.stderr.write(f"Prismor sandbox failed: {exc}\n")
        return 127


def status_report(config: Dict[str, Any]) -> Dict[str, Any]:
    cfg = effective_config(config)
    return {
        "enabled": bool(cfg.get("enabled")),
        "mode": cfg.get("mode"),
        "backend": cfg.get("backend"),
        "image": cfg.get("image"),
        "network": cfg.get("network"),
        "workspace_mount": cfg.get("workspace_mount"),
        "read_only_root": bool(cfg.get("read_only_root")),
        "docker": docker_status(),
    }


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in base.items():
        if isinstance(value, dict):
            result[key] = _deep_merge(value, {})
        elif isinstance(value, list):
            result[key] = list(value)
        else:
            result[key] = value
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
