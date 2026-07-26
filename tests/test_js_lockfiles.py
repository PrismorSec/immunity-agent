"""Tests for pnpm/yarn lockfile parsing in the transitive supply-chain scan.

The post-install transitive CVE scan originally read package-lock.json only, so
a pnpm or yarn workspace got no transitive coverage at all. npm, pnpm and yarn
all resolve from the same registry and OSV treats them as one `npm` ecosystem,
so the fix is parser coverage rather than new scanning logic.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.deps import (
    read_js_lockfiles_full,
    read_pnpm_lockfile_full,
    read_yarn_lockfile_full,
)
from prismor.runtime.policy_engine import _is_completed_npm_install


def _ws(**files) -> Path:
    d = Path(tempfile.mkdtemp())
    for name, content in files.items():
        (d / name.replace("__", "-").replace("_yaml", ".yaml")
           .replace("_json", ".json").replace("_lock", ".lock")).write_text(content)
    return d


def _write(name: str, content: str) -> Path:
    d = Path(tempfile.mkdtemp())
    (d / name).write_text(content)
    return d


class TestPnpm(unittest.TestCase):
    def test_v9_flat_keys(self):
        ws = _write("pnpm-lock.yaml",
                    "lockfileVersion: '9.0'\n"
                    "packages:\n"
                    "  lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n"
                    "  '@babel/code-frame@7.24.7':\n    resolution: {integrity: sha512-y}\n")
        self.assertEqual(read_pnpm_lockfile_full(ws),
                         {"lodash": "4.17.21", "@babel/code-frame": "7.24.7"})

    def test_v6_slash_prefixed_keys(self):
        ws = _write("pnpm-lock.yaml",
                    "lockfileVersion: '6.0'\n"
                    "packages:\n"
                    "  /lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n"
                    "  /@babel/code-frame@7.24.7:\n    resolution: {integrity: sha512-y}\n")
        self.assertEqual(read_pnpm_lockfile_full(ws),
                         {"lodash": "4.17.21", "@babel/code-frame": "7.24.7"})

    def test_peer_suffix_is_stripped_from_the_version(self):
        ws = _write("pnpm-lock.yaml",
                    "packages:\n"
                    "  /debug@4.3.4(supports-color@8.1.1):\n    resolution: {integrity: sha512-w}\n")
        self.assertEqual(read_pnpm_lockfile_full(ws), {"debug": "4.3.4"})

    def test_malformed_yaml_yields_nothing_and_does_not_raise(self):
        self.assertEqual(read_pnpm_lockfile_full(_write("pnpm-lock.yaml", "{{{ not yaml")), {})


class TestYarn(unittest.TestCase):
    V1 = ('# yarn lockfile v1\n\n'
          'lodash@^4.17.0, lodash@^4.17.21:\n'
          '  version "4.17.21"\n'
          '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"\n\n'
          '"@babel/code-frame@^7.0.0":\n'
          '  version "7.24.7"\n\n'
          'minimist@~1.2.5:\n'
          '  version "1.2.8"\n')

    BERRY = ('__metadata:\n  version: 8\n  cacheKey: 10c0\n\n'
             '"lodash@npm:^4.17.21":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n\n'
             '"@babel/code-frame@npm:^7.24.7":\n  version: 7.24.7\n')

    def test_classic_v1(self):
        self.assertEqual(
            read_yarn_lockfile_full(_write("yarn.lock", self.V1)),
            {"lodash": "4.17.21", "@babel/code-frame": "7.24.7", "minimist": "1.2.8"})

    def test_berry_yaml(self):
        self.assertEqual(
            read_yarn_lockfile_full(_write("yarn.lock", self.BERRY)),
            {"lodash": "4.17.21", "@babel/code-frame": "7.24.7"})

    def test_multi_spec_header_resolves_one_name(self):
        pins = read_yarn_lockfile_full(_write("yarn.lock", self.V1))
        self.assertEqual(pins["lodash"], "4.17.21")

    def test_garbage_does_not_raise(self):
        self.assertEqual(read_yarn_lockfile_full(_write("yarn.lock", "\x00\x01garbage")), {})


class TestUnion(unittest.TestCase):
    def test_merges_every_lockfile_flavour(self):
        d = Path(tempfile.mkdtemp())
        (d / "package-lock.json").write_text(
            '{"packages":{"node_modules/express":{"version":"4.18.2"},'
            '"node_modules/express/node_modules/ms":{"version":"2.0.0"}}}')
        (d / "pnpm-lock.yaml").write_text("packages:\n  lodash@4.17.21:\n    resolution: {}\n")
        pins = read_js_lockfiles_full(d)
        # npm transitive (nested node_modules) and pnpm both present.
        self.assertEqual(pins["express"], "4.18.2")
        self.assertEqual(pins["ms"], "2.0.0")
        self.assertEqual(pins["lodash"], "4.17.21")

    def test_vendored_lockfiles_are_skipped(self):
        d = Path(tempfile.mkdtemp())
        (d / "node_modules").mkdir()
        (d / "node_modules" / "yarn.lock").write_text('vendored@^1:\n  version "9.9.9"\n')
        self.assertNotIn("vendored", read_js_lockfiles_full(d))

    def test_empty_workspace(self):
        self.assertEqual(read_js_lockfiles_full(Path(tempfile.mkdtemp())), {})


class TestInstallCommandDetection(unittest.TestCase):
    def test_all_three_clients_trigger_the_scan(self):
        for cmd in ("npm install", "npm install lodash", "npm ci",
                    "pnpm install", "pnpm add lodash",
                    "yarn install", "yarn add lodash"):
            self.assertTrue(_is_completed_npm_install(cmd), cmd)

    def test_bun_is_excluded(self):
        # Bun's lockfile is binary; nothing here can parse it.
        self.assertFalse(_is_completed_npm_install("bun install"))

    def test_unrelated_commands_do_not_trigger(self):
        for cmd in ("ls -la", "echo npm installer docs", "git status"):
            self.assertFalse(_is_completed_npm_install(cmd), cmd)


if __name__ == "__main__":
    unittest.main()
