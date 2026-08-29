"""The generated hook command must be runnable by cmd.exe, not just by sh.

Every agent config format stores the dispatcher as a *shell string*, and the
shell that runs it is cmd.exe on Windows. A `PYTHONPATH=... python ...` prefix
is a variable assignment only in a POSIX shell; cmd.exe reads it as a request
to execute a program named `PYTHONPATH=...`, the hook fails, hook failure is
non-blocking, and Prismor reports installed while screening nothing. These
tests run on any platform — they check the *shape* of what is written, plus
that the shim works with the environment stripped.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prismor.runtime.hooks import _SHIM_NAME, install_hooks  # noqa: E402
from prismor.runtime.mirror_cli import _shim_pythonpath  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


class _IsolatedInstall(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name) / "prismor-home"
        self.workspace = Path(self._tmp.name) / "ws"
        self.workspace.mkdir(parents=True)
        self._prev_home = os.environ.get("PRISMOR_HOME")
        os.environ["PRISMOR_HOME"] = str(self.home)
        results = install_hooks(
            repo_root=REPO_ROOT, workspace=self.workspace,
            agent="claude", scope="project", mode="enforce",
        )
        config = json.loads(Path(results[0]["configPath"]).read_text(encoding="utf-8"))
        self.command = config["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.shim = self.home / _SHIM_NAME

    def tearDown(self):
        if self._prev_home is None:
            os.environ.pop("PRISMOR_HOME", None)
        else:
            os.environ["PRISMOR_HOME"] = self._prev_home
        self._tmp.cleanup()


class TestCommandShape(_IsolatedInstall):
    def test_no_env_assignment_prefix(self):
        """cmd.exe has no `VAR=value command` syntax — the command must not use it."""
        first = self.command.split()[0]
        self.assertFalse(
            "=" in first,
            f"hook command leads with an env assignment, unrunnable on cmd.exe: {self.command}",
        )
        self.assertNotIn("PYTHONPATH=", self.command)

    def test_starts_with_quoted_interpreter(self):
        self.assertTrue(self.command.startswith(f'"{sys.executable}"'), self.command)

    def test_keeps_the_hook_dispatch_marker(self):
        # hook_installed() and _strip_for_agent() both detect Prismor's hook by
        # this substring; losing it would orphan every previously written hook.
        self.assertIn("hook-dispatch", self.command)

    def test_shim_written_with_repo_root(self):
        # The shim writes a repr, so on Windows the path arrives
        # backslash-escaped — compare the parsed value, not the raw text.
        # This is also the parser `prismor mirror` uses to spot version skew
        # between the hook's prismor and the gateway's.
        self.assertTrue(self.shim.is_file())
        self.assertEqual(_shim_pythonpath(self.command), str(REPO_ROOT))


class TestShimRunsWithoutEnv(_IsolatedInstall):
    def test_dispatch_blocks_with_pythonpath_stripped(self):
        """The shim, not the environment, is what makes prismor importable.

        Runs the dispatcher as an argv list (no shell involved, so this is the
        same call cmd.exe would end up making) with PYTHONPATH removed and user
        site-packages disabled — the environment Claude Code hands its hooks.
        """
        (self.workspace / ".prismor").mkdir(exist_ok=True)
        (self.workspace / ".prismor" / "policy.yaml").write_text(
            'version: "1.0"\n'
            "settings:\n"
            "  tool_tags:\n"
            "    enabled: true\n"
            "    mode: enforce\n"
            "    tags:\n"
            "      mcp__Gmail__read_email: [untrusted_content]\n"
            "      mcp__Gmail__send_email: [critical_action]\n"
            "    incompatible:\n"
            "      - [untrusted_content, critical_action]\n",
            encoding="utf-8",
        )
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["PYTHONNOUSERSITE"] = "1"
        argv = [sys.executable, str(self.shim), "hook-dispatch", "--agent", "claude",
                "--workspace", str(self.workspace), "--mode", "enforce"]

        def dispatch(tool, tool_input):
            payload = json.dumps({
                "hook_event_name": "PreToolUse", "tool_name": tool,
                "tool_input": tool_input, "session_id": "windows-shim-test",
                "cwd": str(self.workspace),
            })
            return subprocess.run(argv, input=payload, capture_output=True, text=True, env=env)

        allowed = dispatch("mcp__Gmail__read_email", {"query": "is:unread"})
        self.assertEqual(allowed.returncode, 0, allowed.stderr)

        blocked = dispatch("mcp__Gmail__send_email", {"to": "x@example.com"})
        self.assertEqual(blocked.returncode, 2, blocked.stdout + blocked.stderr)
        self.assertIn("Prismor blocked this action", blocked.stdout + blocked.stderr)


if __name__ == "__main__":
    unittest.main()


class TestWindowsPortability(unittest.TestCase):
    """Guards for the three ways prismor used to be broken on Windows.

    All three are invisible on macOS/Linux, so only a static check keeps them
    from creeping back in between Windows CI runs.
    """

    def _runtime_files(self):
        for path in sorted((REPO_ROOT / "prismor").rglob("*.py")):
            if "__pycache__" not in path.parts:
                yield path

    def test_text_io_declares_an_encoding(self):
        """Without encoding=, Windows uses the locale codec (cp1252), not UTF-8.

        `prismor setup` died reading its own default_policy.yaml this way:
        UnicodeDecodeError on an em dash.
        """
        offenders = []
        for path in self._runtime_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else None
                if name not in ("read_text", "write_text"):
                    continue
                if any(k.arg == "encoding" for k in node.keywords):
                    continue
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno} {name}()")
        self.assertEqual(offenders, [], "text I/O without encoding=\"utf-8\":\n" + "\n".join(offenders))

    def test_fcntl_is_never_imported_unguarded(self):
        """fcntl is Unix-only. A bare import raised ImportError on every
        Windows tool call: `audit trail error: No module named 'fcntl'`.

        store.py owns the one guarded import and exposes file_lock(); everyone
        else goes through that.
        """
        allowed = {REPO_ROOT / "prismor" / "runtime" / "store.py"}
        offenders = []
        for path in self._runtime_files():
            if path in allowed:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import) and any(a.name == "fcntl" for a in node.names):
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
        self.assertEqual(
            offenders, [],
            "bare `import fcntl` outside store.py — use store.file_lock():\n" + "\n".join(offenders),
        )

    def test_cli_forces_utf8_streams(self):
        """A cp1252 console cannot encode the spinner/check glyphs prismor
        prints; setup died mid-write on the first tick."""
        from prismor.runtime.immunity_cli import _force_utf8_streams
        _force_utf8_streams()  # must be a no-op, never raise, under pytest capture
