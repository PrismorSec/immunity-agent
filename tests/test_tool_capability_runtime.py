from __future__ import annotations

from prismor.runtime import agents
from prismor.runtime.enterprise import identity
from prismor.runtime.runtime import evaluate_tool_call
from prismor.runtime.scoped_agent import save_scoped_rules


class _SyncThread:
    def __init__(self, target=None, args=(), daemon=None):
        self.target, self.args = target, args

    def start(self):
        self.target(*self.args)


def test_coding_agent_call_registers_scope_and_mcp_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor-home"))
    identity.save_identity({
        "device_id": "dev1", "org_id": "org1", "user_id": "user1",
        "device_key": "test-device-key", "api_base": "http://127.0.0.1:1",
    })
    monkeypatch.setattr("prismor.runtime.enterprise.workspace_scope.is_managed", lambda ws: True)
    monkeypatch.setattr(agents.threading, "Thread", _SyncThread)
    posts = []
    monkeypatch.setattr(agents, "_post_registration", lambda ident, payload: posts.append(payload))
    agents._SEEN_THIS_PROCESS.clear()
    agents._TOOLS_SEEN_THIS_PROCESS.clear()
    agents._CONFIG_CACHE.clear()

    session_id = "claude-session"
    mcp_tools = [
        "mcp__prismor-demo__read_note",
        "mcp__prismor-demo__list_projects",
        "mcp__prismor-demo__lookup_customer",
        "mcp__prismor-demo__create_draft",
        "mcp__prismor-demo__send_report",
    ]
    save_scoped_rules(tmp_path, session_id, {
        "allowed_tools": ["Read", "Write", *mcp_tools],
        "allowed_paths": ["**"], "deny_tools": [], "deny_network": True,
    })
    decision = evaluate_tool_call(
        event={
            "type": "tool", "agent_event": "PreToolUse",
            "metadata": {"tool_name": "mcp__prismor-demo__create_draft"},
        },
        workspace=tmp_path, agent="claude", session_id=session_id,
        mode="observe", persist=False,
    )
    assert decision.allow is True
    sent = posts[0]["agents"][0]
    assert sent["sessionId"] == session_id
    assert {t["name"] for t in sent["tools"]} == {
        "Read", "Write", *mcp_tools,
    }
