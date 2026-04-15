"""Extended tests for hooks: uninstall, normalize, install/uninstall roundtrip."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from warden.hooks import (
    _is_pre_action,
    _strip_claude,
    _strip_cursor,
    _strip_windsurf,
    install_hooks,
    normalize_payload,
    uninstall_hooks,
)


class TestStripClaude(unittest.TestCase):
    """Test _strip_claude removes Prismor entries and leaves others."""

    def test_removes_prismor_hooks(self):
        marker = "/repo/warden/cli.py"
        config = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash|Read",
                        "hooks": [
                            {"type": "command", "command": f'python3 "{marker}" hook-dispatch --agent claude'},
                            {"type": "command", "command": "other-tool --check"},
                        ],
                    }
                ]
            },
            "env": {"PRISMOR_WARDEN_WORKSPACE": "/some/path", "OTHER_VAR": "keep"},
        }
        result, removed = _strip_claude(config, marker)
        self.assertTrue(removed)
        # Other hook command preserved
        self.assertEqual(len(result["hooks"]["PreToolUse"]), 1)
        self.assertEqual(len(result["hooks"]["PreToolUse"][0]["hooks"]), 1)
        self.assertEqual(result["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "other-tool --check")
        # PRISMOR env removed, OTHER_VAR kept
        self.assertNotIn("PRISMOR_WARDEN_WORKSPACE", result["env"])
        self.assertEqual(result["env"]["OTHER_VAR"], "keep")

    def test_removes_entire_entry_when_only_prismor(self):
        marker = "/repo/warden/cli.py"
        config = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": f'python3 "{marker}" hook-dispatch'}],
                    }
                ]
            },
            "env": {},
        }
        result, removed = _strip_claude(config, marker)
        self.assertTrue(removed)
        self.assertEqual(result["hooks"]["PreToolUse"], [])

    def test_no_change_returns_false(self):
        config = {
            "hooks": {
                "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "unrelated"}]}]
            },
            "env": {},
        }
        result, removed = _strip_claude(config, "/repo/warden/cli.py")
        self.assertFalse(removed)

    def test_empty_config(self):
        result, removed = _strip_claude({}, "/repo/warden/cli.py")
        self.assertFalse(removed)


class TestStripCursor(unittest.TestCase):
    """Test _strip_cursor removes Prismor entries."""

    def test_removes_prismor_entries(self):
        marker = "/repo/warden/cli.py"
        config = {
            "hooks": {
                "beforeShellCommand": [
                    {"command": f'python3 "{marker}" hook-dispatch --agent cursor'},
                    {"command": "other-linter --check"},
                ]
            }
        }
        result, removed = _strip_cursor(config, marker)
        self.assertTrue(removed)
        self.assertEqual(len(result["hooks"]["beforeShellCommand"]), 1)
        self.assertEqual(result["hooks"]["beforeShellCommand"][0]["command"], "other-linter --check")

    def test_no_change(self):
        config = {"hooks": {"beforeShellCommand": [{"command": "unrelated"}]}}
        result, removed = _strip_cursor(config, "/repo/warden/cli.py")
        self.assertFalse(removed)


class TestStripWindsurf(unittest.TestCase):
    """Test _strip_windsurf removes Prismor entries."""

    def test_removes_prismor_entries(self):
        marker = "/repo/warden/cli.py"
        config = {
            "hooks": {
                "pre_run_command": [
                    {"command": f'python3 "{marker}" hook-dispatch --agent windsurf', "show_output": False},
                    {"command": "other-tool", "show_output": True},
                ]
            }
        }
        result, removed = _strip_windsurf(config, marker)
        self.assertTrue(removed)
        self.assertEqual(len(result["hooks"]["pre_run_command"]), 1)
        self.assertEqual(result["hooks"]["pre_run_command"][0]["command"], "other-tool")

    def test_no_change(self):
        config = {"hooks": {"pre_run_command": [{"command": "other"}]}}
        result, removed = _strip_windsurf(config, "/repo/warden/cli.py")
        self.assertFalse(removed)


class TestInstallUninstallRoundtrip(unittest.TestCase):
    """Test that install → uninstall leaves a clean config."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.workspace = Path(self.tmpdir) / "project"
        self.workspace.mkdir()
        self.repo_root = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _roundtrip(self, agent):
        install_hooks(
            repo_root=self.repo_root,
            workspace=self.workspace,
            agent=agent,
            scope="project",
            mode="observe",
        )
        # Verify hooks were written
        if agent == "claude":
            config_path = self.workspace / ".claude" / "settings.json"
        elif agent == "cursor":
            config_path = self.workspace / ".cursor" / "hooks.json"
        else:
            config_path = self.workspace / ".windsurf" / "hooks.json"
        self.assertTrue(config_path.exists())
        config = json.loads(config_path.read_text())
        self.assertTrue(any(
            isinstance(v, list) and len(v) > 0
            for v in config.get("hooks", {}).values()
        ))

        # Now uninstall
        results = uninstall_hooks(
            repo_root=self.repo_root,
            workspace=self.workspace,
            agent=agent,
            scope="project",
        )
        self.assertTrue(results[0]["removed"])

        # Verify hooks are empty
        config = json.loads(config_path.read_text())
        for entries in config.get("hooks", {}).values():
            if isinstance(entries, list):
                self.assertEqual(entries, [])

    def test_claude_roundtrip(self):
        self._roundtrip("claude")

    def test_cursor_roundtrip(self):
        self._roundtrip("cursor")

    def test_windsurf_roundtrip(self):
        self._roundtrip("windsurf")

    def test_uninstall_nonexistent_config(self):
        results = uninstall_hooks(
            repo_root=self.repo_root,
            workspace=self.workspace,
            agent="claude",
            scope="project",
        )
        self.assertFalse(results[0]["removed"])

    def test_uninstall_all(self):
        install_hooks(
            repo_root=self.repo_root,
            workspace=self.workspace,
            agent="all",
            scope="project",
            mode="enforce",
        )
        results = uninstall_hooks(
            repo_root=self.repo_root,
            workspace=self.workspace,
            agent="all",
            scope="project",
        )
        from warden.hooks import _SUPPORTED_AGENTS
        self.assertEqual(len(results), len(_SUPPORTED_AGENTS))
        for r in results:
            self.assertTrue(r["removed"])


class TestNormalizePayloadClaude(unittest.TestCase):
    """Test Claude payload normalization."""

    def test_user_prompt(self):
        payload = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "sess-1",
            "prompt": "Help me fix this bug",
            "timestamp": "2026-01-01T00:00:00Z",
        }
        result = normalize_payload(agent="claude", payload=payload, workspace=Path("/tmp"))
        self.assertEqual(result["sessionId"], "sess-1")
        event = result["event"]
        self.assertEqual(event["type"], "prompt")
        self.assertEqual(event["prompt"], "Help me fix this bug")
        self.assertEqual(event["agent"], "claude")
        self.assertEqual(event["agent_event"], "UserPromptSubmit")

    def test_bash_tool(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        }
        result = normalize_payload(agent="claude", payload=payload, workspace=Path("/tmp"))
        event = result["event"]
        self.assertEqual(event["type"], "shell")
        self.assertEqual(event["command"], "ls -la")

    def test_read_tool(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess-1",
            "tool_name": "Read",
            "tool_input": {"file_path": "/src/app.py"},
        }
        result = normalize_payload(agent="claude", payload=payload, workspace=Path("/tmp"))
        event = result["event"]
        self.assertEqual(event["type"], "file_read")
        self.assertEqual(event["path"], "/src/app.py")

    def test_write_tool(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess-1",
            "tool_name": "Write",
            "tool_input": {"file_path": "/src/app.py", "content": "print('hello')"},
        }
        result = normalize_payload(agent="claude", payload=payload, workspace=Path("/tmp"))
        event = result["event"]
        self.assertEqual(event["type"], "file_write")
        self.assertEqual(event["path"], "/src/app.py")

    def test_web_fetch(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess-1",
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://example.com"},
        }
        result = normalize_payload(agent="claude", payload=payload, workspace=Path("/tmp"))
        event = result["event"]
        self.assertEqual(event["type"], "network")
        self.assertEqual(event["url"], "https://example.com")

    def test_unknown_tool_becomes_tool_result(self):
        payload = {
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Agent",
            "tool_input": {},
        }
        result = normalize_payload(agent="claude", payload=payload, workspace=Path("/tmp"))
        event = result["event"]
        self.assertEqual(event["type"], "tool_result")

    def test_ephemeral_session_id_when_missing(self):
        payload = {"hook_event_name": "Stop"}
        result = normalize_payload(agent="claude", payload=payload, workspace=Path("/tmp"))
        self.assertTrue(result["sessionId"].startswith("claude-"))


class TestNormalizePayloadCursor(unittest.TestCase):
    """Test Cursor payload normalization."""

    def test_before_shell_command(self):
        payload = {
            "hook_event_name": "beforeShellCommand",
            "session_id": "cur-1",
            "command": "npm test",
        }
        result = normalize_payload(agent="cursor", payload=payload, workspace=Path("/tmp"))
        event = result["event"]
        self.assertEqual(event["type"], "shell")
        self.assertEqual(event["command"], "npm test")
        self.assertEqual(event["agent"], "cursor")

    def test_before_submit_prompt(self):
        payload = {
            "hookEventName": "beforeSubmitPrompt",
            "sessionId": "cur-2",
            "prompt": "Fix the test",
        }
        result = normalize_payload(agent="cursor", payload=payload, workspace=Path("/tmp"))
        event = result["event"]
        self.assertEqual(event["type"], "prompt")
        self.assertEqual(event["prompt"], "Fix the test")

    def test_before_file_write(self):
        payload = {
            "event_name": "beforeFileWrite",
            "session_id": "cur-3",
            "path": "/src/index.ts",
            "content": "export {}",
        }
        result = normalize_payload(agent="cursor", payload=payload, workspace=Path("/tmp"))
        event = result["event"]
        self.assertEqual(event["type"], "file_write")
        self.assertEqual(event["path"], "/src/index.ts")

    def test_alternate_key_names(self):
        payload = {
            "eventName": "beforeShellCommand",
            "session_id": "cur-4",
            "commandLine": "git status",
        }
        result = normalize_payload(agent="cursor", payload=payload, workspace=Path("/tmp"))
        event = result["event"]
        self.assertEqual(event["command"], "git status")


class TestNormalizePayloadWindsurf(unittest.TestCase):
    """Test Windsurf payload normalization."""

    def test_pre_run_command(self):
        payload = {
            "agent_action_name": "pre_run_command",
            "execution_id": "ws-1",
            "tool_info": {"command": "python3 main.py"},
        }
        result = normalize_payload(agent="windsurf", payload=payload, workspace=Path("/tmp"))
        self.assertEqual(result["sessionId"], "ws-1")
        event = result["event"]
        self.assertEqual(event["type"], "shell")
        self.assertEqual(event["command"], "python3 main.py")
        self.assertEqual(event["agent"], "windsurf")

    def test_pre_user_prompt(self):
        payload = {
            "agent_action_name": "pre_user_prompt",
            "execution_id": "ws-2",
            "tool_info": {"prompt": "Explain this code"},
        }
        result = normalize_payload(agent="windsurf", payload=payload, workspace=Path("/tmp"))
        event = result["event"]
        self.assertEqual(event["type"], "prompt")
        self.assertEqual(event["prompt"], "Explain this code")

    def test_pre_write_code(self):
        payload = {
            "agent_action_name": "pre_write_code",
            "execution_id": "ws-3",
            "tool_info": {"file_path": "/app/main.py", "edits": [{"new_string": "pass"}]},
        }
        result = normalize_payload(agent="windsurf", payload=payload, workspace=Path("/tmp"))
        event = result["event"]
        self.assertEqual(event["type"], "file_write")
        self.assertEqual(event["path"], "/app/main.py")

    def test_pre_read_code(self):
        payload = {
            "agent_action_name": "pre_read_code",
            "execution_id": "ws-4",
            "tool_info": {"file_path": "/app/config.py"},
        }
        result = normalize_payload(agent="windsurf", payload=payload, workspace=Path("/tmp"))
        event = result["event"]
        self.assertEqual(event["type"], "file_read")
        self.assertEqual(event["path"], "/app/config.py")


class TestIsPreActionExtended(unittest.TestCase):
    """Additional pre-action tests for coverage gaps."""

    def test_windsurf_pre_mcp_tool_use(self):
        self.assertTrue(_is_pre_action("pre_mcp_tool_use"))

    def test_windsurf_post_mcp_tool_use(self):
        self.assertFalse(_is_pre_action("post_mcp_tool_use"))

    def test_windsurf_pre_read_code(self):
        self.assertTrue(_is_pre_action("pre_read_code"))

    def test_windsurf_post_cascade_response(self):
        self.assertFalse(_is_pre_action("post_cascade_response"))

    def test_cursor_before_submit_prompt(self):
        self.assertTrue(_is_pre_action("beforeSubmitPrompt"))


if __name__ == "__main__":
    unittest.main()
