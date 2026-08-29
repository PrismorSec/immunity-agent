"""Run the hook command string through the platform's own shell, verbatim.

The unit tests in tests/test_hooks_windows.py check the *shape* of the string
and invoke the shim as an argv list. This runs the string exactly as an agent
would: handed to a shell, which is cmd.exe on Windows. That is where a
`PYTHONPATH=... python ...` prefix stops being a variable assignment and starts
being a missing executable — and because hook failure is non-blocking, that
failure is silent in production. Here it is loud.

Runs on any platform (sh on POSIX, cmd.exe on Windows). Exit 0 = the hook
installed, ran under the real shell, and blocked what it was supposed to block.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from prismor.runtime.hooks import install_hooks  # noqa: E402

POLICY = """version: "1.0"
settings:
  tool_tags:
    enabled: true
    mode: enforce
    tags:
      mcp__Gmail__read_email: [untrusted_content]
      mcp__Gmail__send_email: [critical_action]
    incompatible:
      - [untrusted_content, critical_action]
"""


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        # A directory with a space in it, because %USERPROFILE% often has one
        # and that is exactly where naive quoting falls over.
        workspace = Path(tmp) / "work space"
        (workspace / ".prismor").mkdir(parents=True)
        (workspace / ".prismor" / "policy.yaml").write_text(POLICY, encoding="utf-8")
        os.environ["PRISMOR_HOME"] = str(Path(tmp) / "prismor home")

        results = install_hooks(
            repo_root=REPO_ROOT, workspace=workspace,
            agent="claude", scope="project", mode="enforce",
        )
        config = json.loads(Path(results[0]["configPath"]).read_text(encoding="utf-8"))
        command = config["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        print(f"shell: {'cmd.exe' if os.name == 'nt' else 'sh'}")
        print(f"command: {command}")

        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["PYTHONNOUSERSITE"] = "1"

        def dispatch(tool: str, tool_input: dict) -> subprocess.CompletedProcess:
            payload = json.dumps({
                "hook_event_name": "PreToolUse", "tool_name": tool,
                "tool_input": tool_input, "session_id": "windows-hook-smoke",
                "cwd": str(workspace),
            })
            return subprocess.run(
                command, shell=True, input=payload,
                capture_output=True, text=True, env=env,
            )

        allowed = dispatch("mcp__Gmail__read_email", {"query": "is:unread"})
        if allowed.returncode != 0:
            print(f"FAIL: benign call did not pass (exit {allowed.returncode})")
            print(allowed.stdout, allowed.stderr, sep="\n")
            return 1
        print("ok: benign call allowed")

        blocked = dispatch("mcp__Gmail__send_email", {"to": "x@example.com"})
        if blocked.returncode != 2:
            print(f"FAIL: crossover call was NOT blocked (exit {blocked.returncode})")
            print(blocked.stdout, blocked.stderr, sep="\n")
            return 1
        print("ok: crossover call blocked with exit 2")
    return 0


if __name__ == "__main__":
    sys.exit(main())
