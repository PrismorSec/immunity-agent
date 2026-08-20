"""Shape an MCP JSON-RPC frame into a canonical policy event.

The MCP gateway builds its events from a resolved ``_Route`` — it owns the
upstream connections, so it already knows which server a tool belongs to. A
proxy delegating authorization to Prismor has no such thing: it has a URL, some
headers, and a request body it did not parse. This module is the shaping for
that case, and it is deliberately transport-independent — the same function
serves an external-authorization callout, a webhook, or a test.

What it does NOT do is decide anything. It produces an event; the verdict comes
from ``evaluate_tool_call`` like every other surface.

Naming
------
Tool names are namespaced ``mcp__<server>__<tool>``, matching the gateway, so a
tool deny, an allow entry, a tag rule, or a console filter written for one
surface matches on the other. The server name comes from the caller (a route
name or hostname); when it is unknown the frame is still screened, just under a
less specific tag.

Untrusted input
---------------
Every field here arrives from the network. Server and tool names are sanitized
before they reach a policy finding, sizes are capped, and a frame that does not
parse is reported as unparseable rather than guessed at — a proxy must not be
able to smuggle arbitrary strings into an audit record, and an unreadable body
must never quietly evaluate as "nothing to see".
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

#: Methods worth screening. `initialize` and `tools/list` matter because they
#: talk to the server before any tool call has been evaluated — discovery runs
#: with the proxy's network position, so registration alone must not be an
#: unscreened execution path (same reasoning as the gateway's connect guard).
SCREENED_METHODS = ("tools/call", "tools/list", "initialize", "prompts/get", "resources/read")

#: Cap on the serialized argument text handed to the rules. Long past this a
#: payload is data, not an instruction, and the regex engine should not be made
#: to walk megabytes on the request path.
MAX_ARGS_CHARS = 64_000

_NAME_RE = re.compile(r"[^a-zA-Z0-9_.\-]")


def sanitize_name(name: str, *, fallback: str = "unknown") -> str:
    """Reduce an untrusted server/tool name to the tag charset."""
    cleaned = _NAME_RE.sub("_", str(name or "")).strip("_")
    return cleaned[:64] or fallback


def parse_frame(body: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Parse a JSON-RPC frame from bytes/str/dict.

    Returns ``(frame, error)``. A caller that gets an error must fail closed:
    an unreadable body is not an empty one.
    """
    if isinstance(body, dict):
        return body, None
    if isinstance(body, (bytes, bytearray)):
        try:
            body = body.decode("utf-8", errors="replace")
        except Exception as exc:
            return None, f"undecodable body: {exc}"
    if not isinstance(body, str):
        return None, f"unsupported body type {type(body).__name__}"
    text = body.strip()
    if not text:
        return None, "empty body"
    try:
        frame = json.loads(text)
    except Exception as exc:
        return None, f"body is not JSON-RPC: {exc}"
    if not isinstance(frame, dict):
        return None, "JSON-RPC frame must be an object"
    return frame, None


def describe(frame: Dict[str, Any]) -> Dict[str, Any]:
    """Summarize what a frame is asking for, without judging it."""
    method = str(frame.get("method") or "")
    params = frame.get("params")
    params = params if isinstance(params, dict) else {}
    tool = ""
    arguments: Any = None
    if method == "tools/call":
        tool = str(params.get("name") or "")
        arguments = params.get("arguments")
    elif method == "prompts/get":
        tool = str(params.get("name") or "")
        arguments = params.get("arguments")
    elif method == "resources/read":
        tool = str(params.get("uri") or "")
    return {
        "method": method,
        "tool": tool,
        "arguments": arguments,
        "is_notification": "id" not in frame,
        "screened": method in SCREENED_METHODS,
    }


def _args_text(arguments: Any) -> str:
    if arguments is None:
        return ""
    if isinstance(arguments, str):
        text = arguments
    else:
        try:
            text = json.dumps(arguments, default=str)
        except Exception:
            text = str(arguments)
    return text[:MAX_ARGS_CHARS]


def shape_request_event(
    *,
    body: Any,
    url: str = "",
    server: str = "",
    session_id: str = "",
    agent: str = "mcp-proxy",
    surface_id: str = "ext-authz",
    metadata: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Shape an inbound MCP request frame into a canonical event.

    Returns ``(event, error)``. ``event`` is ``None`` when the frame could not
    be parsed (fail closed) or when it is a method not worth screening (in
    which case ``error`` is also ``None`` — nothing to decide, allow).

    A remote MCP server is screened as a ``network`` event carrying the
    outbound arguments, so the egress allowlist, secret-in-arguments and taint
    rules all apply — the same classification the gateway gives a remote
    upstream, so one policy covers both.
    """
    frame, err = parse_frame(body)
    if err:
        return None, err
    assert frame is not None

    info = describe(frame)
    if not info["screened"]:
        return None, None

    srv = sanitize_name(server, fallback="proxy")
    tool = sanitize_name(info["tool"], fallback=info["method"].replace("/", "_"))
    tool_name = f"mcp__{srv}__{tool}"

    meta: Dict[str, Any] = dict(metadata or {})
    meta.update({
        "tool_name": tool_name,
        "surface": surface_id,
        "mcp_method": info["method"],
    })

    event: Dict[str, Any] = {
        "session_id": session_id,
        "agent": agent,
        "agent_event": "PreToolUse",
        "type": "network",
        "url": url,
        "outbound_payload": _args_text(info["arguments"]),
        "mcp_server": srv,
        "mcp_tool": tool,
        "metadata": meta,
    }
    return event, None


def shape_response_event(
    *,
    body: Any,
    url: str = "",
    server: str = "",
    tool: str = "",
    session_id: str = "",
    agent: str = "mcp-proxy",
    surface_id: str = "ext-authz",
    metadata: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Shape an MCP tool RESULT into a ``tool_result`` event.

    This is the path that catches a poisoned response — content that is
    dangerous because of what it makes the model do next. Only surfaces that
    carry the response can produce it at all.
    """
    frame, err = parse_frame(body)
    if err:
        return None, err
    assert frame is not None

    srv = sanitize_name(server, fallback="proxy")
    tl = sanitize_name(tool, fallback="result")
    meta: Dict[str, Any] = dict(metadata or {})
    meta.update({"tool_name": f"mcp__{srv}__{tl}", "surface": surface_id})

    event = {
        "session_id": session_id,
        "agent": agent,
        "agent_event": "PostToolUse",
        "type": "tool_result",
        "response": extract_result_text(frame)[:MAX_ARGS_CHARS],
        "mcp_server": srv,
        "mcp_tool": tl,
        "metadata": meta,
    }
    if url:
        event["url"] = url
    return event, None


def extract_result_text(frame: Dict[str, Any]) -> str:
    """Flatten the text an MCP result would put in front of the model."""
    result = frame.get("result")
    if result is None:
        # An error frame still reaches the model as text.
        err = frame.get("error")
        return json.dumps(err, default=str) if err is not None else ""
    if isinstance(result, str):
        return result
    parts: List[str] = []
    content = result.get("content") if isinstance(result, dict) else None
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
    if parts:
        return "\n".join(parts)
    try:
        return json.dumps(result, default=str)
    except Exception:
        return str(result)
