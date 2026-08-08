"""Codex CLI transcript adapter.

Codex writes rollout files under ``$CODEX_HOME/sessions/YYYY/MM/DD/
rollout-<timestamp>-<uuid>.jsonl``. Every line shares one envelope —
``{"timestamp": ..., "type": ..., "payload": {...}}`` — and the payload's own
``type`` discriminates further. The records that carry agent actions are:

``response_item/function_call``
    ``{name, arguments, call_id}``. ``arguments`` is *usually* a JSON string.

``response_item/custom_tool_call``
    ``{name, input, call_id}``. ``input`` is frequently **not** JSON — the
    ``exec`` tool carries raw JavaScript and ``apply_patch`` carries raw patch
    text — so argument decoding is best-effort by design.

``event_msg/user_message``
    ``{message}`` — genuine user input.

Codex's native tool names (``exec_command``, ``apply_patch``, …) are mapped onto
the canonical names `hooks._normalize_codex` dispatches on (``Bash``, ``Read``,
``Write``, ``apply_patch``), so replayed events land in the same event types as
live ones.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from prismor.runtime.transcripts.base import (
    DiscoveredSession,
    JsonlAdapter,
    env_root,
    home,
)

#: `rollout-2026-07-16T17-08-47-019f6d67-7fcc-7941-b318-852c68e3e9ab.jsonl`
_ROLLOUT_RE = re.compile(
    r"rollout-.*?-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.IGNORECASE,
)

#: `*** Update File: /path/to/file`
_PATCH_PATH_RE = re.compile(
    r"^\*\*\*\s+(?:Update|Add|Delete)\s+File:\s*(.+?)\s*$", re.MULTILINE
)

#: Codex tool name -> the canonical name `_normalize_codex` understands.
_TOOL_ALIASES = {
    "exec_command": "Bash",
    "local_shell_call": "Bash",
    "shell": "Bash",
    # `exec` runs a JavaScript program that drives the other tools. It is code
    # execution, so it maps to Bash: the point is that its source text reaches
    # the content rules, not that the language is sh.
    "exec": "Bash",
    "read_file": "Read",
    "write_file": "Write",
    "apply_patch": "apply_patch",
}

#: Control-plane tools that perform no action worth screening.
_IGNORED_TOOLS = {"wait", "kill", "update_plan", "view_image"}


def _decode_arguments(raw: Any) -> Tuple[Dict[str, Any], str]:
    """Best-effort decode of a Codex tool's arguments.

    Returns ``(parsed_mapping, raw_text)``. Several Codex tools carry a raw
    payload that is not JSON at all, so the raw text is always preserved — it
    is the only thing content rules can scan for those tools.
    """
    if isinstance(raw, dict):
        return raw, json.dumps(raw)
    if not isinstance(raw, str):
        return {}, "" if raw is None else str(raw)
    text = raw
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}, text
    if isinstance(parsed, dict):
        return parsed, text
    return {}, text


class CodexAdapter(JsonlAdapter):
    agent = "codex"
    label = "Codex"
    pattern = "**/rollout-*.jsonl"

    def roots(self) -> List[Path]:
        base = env_root("CODEX_HOME", home() / ".codex")
        return [base / "sessions", base / "archived_sessions"]

    def session_id_for(self, path: Path) -> str:
        """Session uuid from the rollout filename.

        The authoritative id also appears in the file's ``session_meta``
        record, but the filename embeds the same uuid and reading it here keeps
        discovery cheap — `--since` can drop a file without opening it.
        """
        match = _ROLLOUT_RE.match(path.stem)
        return match.group(1) if match else path.stem

    def record_to_payloads(
        self, record: Dict[str, Any], session: DiscoveredSession
    ) -> Iterator[Dict[str, Any]]:
        payload = record.get("payload")
        if not isinstance(payload, dict):
            return
        kind = payload.get("type")
        base: Dict[str, Any] = {
            "session_id": session.session_id,
            "timestamp": record.get("timestamp"),
        }

        if kind == "user_message":
            message = payload.get("message")
            if isinstance(message, str) and message.strip():
                yield {**base, "hook_event_name": "UserPromptSubmit", "prompt": message}
            return

        if kind not in ("function_call", "custom_tool_call"):
            return

        native = str(payload.get("name") or "")
        if native in _IGNORED_TOOLS:
            return
        args, raw_text = _decode_arguments(
            payload.get("arguments") if "arguments" in payload else payload.get("input")
        )
        tool_name = _TOOL_ALIASES.get(native, native)

        cwd = args.get("workdir") or args.get("cwd")
        if cwd:
            base["cwd"] = cwd
        elif session.workspace:
            base["cwd"] = str(session.workspace)

        tool_input = self._tool_input(native, tool_name, args, raw_text)
        if tool_input is None:
            return
        yield {
            **base,
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
        }

    @staticmethod
    def _tool_input(
        native: str, tool_name: str, args: Dict[str, Any], raw_text: str
    ) -> Optional[Dict[str, Any]]:
        if tool_name == "Bash":
            # `cmd` is exec_command's; raw_text covers `exec`, whose body is a
            # JavaScript program rather than a JSON object.
            command = args.get("cmd") or args.get("command") or raw_text
            if isinstance(command, list):
                command = " ".join(str(part) for part in command)
            return {"command": command or ""}

        if tool_name == "apply_patch":
            patch = args.get("input") or args.get("patch") or raw_text
            match = _PATCH_PATH_RE.search(patch or "")
            return {"file_path": match.group(1) if match else "", "content": patch or ""}

        if tool_name == "Read":
            return {"file_path": args.get("path") or args.get("file_path") or ""}

        if tool_name == "Write":
            return {
                "file_path": args.get("path") or args.get("file_path") or "",
                "content": args.get("content") or raw_text or "",
            }

        # Unrecognized tool: still replay it so MCP and tool-identity rules can
        # see the call, carrying the raw argument text as the scannable body.
        if not raw_text and not args:
            return None
        return dict(args) if args else {"command": raw_text}
