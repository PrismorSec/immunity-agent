"""Tests for Docker-backed Warden sandbox support."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from warden import sandbox
from warden.cli import build_parser
from warden.policy_engine import PolicyEngine, validate_policy


class TestSandboxConfig(unittest.TestCase):
    def test_default_config_is_disabled_and_safe(self):
        cfg = sandbox.effective_config({})
        self.assertFalse(cfg["enabled"])
        self.assertEqual(cfg["backend"], "docker")
        self.assertEqual(cfg["network"], "none")
        self.assertTrue(cfg["read_only_root"])

    def test_policy_engine_loads_sandbox_config(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "policy.yaml"
            p.write_text(
                'version: "1.0"\n'
                "settings:\n"
                "  sandbox:\n"
                "    enabled: true\n"
                "    mode: enforce\n"
                "    network: none\n"
                "rules: []\n",
                encoding="utf-8",
            )
            engine = PolicyEngine(policy_path=p)
            cfg = sandbox.effective_config(engine.sandbox_config)
            self.assertTrue(cfg["enabled"])
            self.assertEqual(cfg["mode"], "enforce")

    def test_schema_accepts_sandbox_settings(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(
                'version: "1.0"\n'
                "settings:\n"
                "  sandbox:\n"
                "    enabled: true\n"
                "    backend: docker\n"
                "    mode: enforce\n"
                "    network: none\n"
                "rules: []\n"
            )
            path = Path(f.name)
        try:
            self.assertEqual(validate_policy(path), [])
        finally:
            path.unlink(missing_ok=True)


class TestSandboxCommandHandling(unittest.TestCase):
    def test_command_round_trip_encoding(self):
        command = "printf '%s\\n' hello && echo done"
        encoded = sandbox.encode_command(command)
        self.assertEqual(sandbox.decode_command(encoded), command)

    def test_docker_argv_keeps_original_command_as_single_container_arg(self):
        cfg = sandbox.effective_config({
            "image": "example/sandbox:latest",
            "network": "allowlist",
            "resource_limits": {
                "cpus": "2.0",
                "memory": "2g",
                "pids_limit": 128,
                "timeout_seconds": 60,
            },
        })
        command = "echo safe; touch /tmp/proof"
        argv = sandbox.build_docker_argv(command, workspace=Path("/tmp/work"), config=cfg)
        self.assertIn("--network", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertIn("--cap-drop", argv)
        self.assertIn("no-new-privileges", argv)
        mount = argv[argv.index("--mount") + 1]
        self.assertEqual(mount, f"type=bind,src={Path('/tmp/work').resolve()},dst=/workspace")
        self.assertEqual(argv[-3:], ["/bin/sh", "-lc", command])

    def test_docker_argv_uses_readonly_for_ro_workspace_mount(self):
        cfg = sandbox.effective_config({"workspace_mount": "ro"})
        argv = sandbox.build_docker_argv("echo ok", workspace=Path("/tmp/work"), config=cfg)
        mount = argv[argv.index("--mount") + 1]
        self.assertEqual(mount, f"type=bind,src={Path('/tmp/work').resolve()},dst=/workspace,readonly")

    def test_claude_updated_input_uses_encoded_runner(self):
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello", "description": "test"},
        }
        update = sandbox.claude_updated_input(
            payload,
            workspace=Path("/tmp/work"),
            mode="enforce",
        )
        self.assertIsNotNone(update)
        updated = update["hookSpecificOutput"]["updatedInput"]
        self.assertEqual(updated["description"], "test")
        self.assertIn("sandbox --workspace /tmp/work run", updated["command"])
        self.assertIn("--encoded", updated["command"])
        self.assertNotIn("echo hello", updated["command"])

    def test_sandbox_run_parser_does_not_clobber_top_level_command(self):
        args = build_parser().parse_args(["sandbox", "run", "--encoded", "abc"])
        self.assertEqual(args.command, "sandbox")
        self.assertEqual(args.sandbox_command, "run")
        self.assertEqual(args.encoded, "abc")


if __name__ == "__main__":
    unittest.main()
