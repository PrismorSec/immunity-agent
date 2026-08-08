#!/usr/bin/env python3
"""prismor — unified CLI for the Prismor security toolkit.

Every command in the toolkit is reachable as ``prismor <command> [args...]``.
Run ``prismor --help`` for the full map. The umbrella dispatches to the
existing engines:

  - prismor.runtime.cli:main         runtime / session security, hooks, policy, sweep,
                            cloak, iam, canary, scope, learn, setup, audit ...
  - supplychain.cli:run_supply  package-install interception + project hardening
"""
from __future__ import annotations

import os
import sys
from functools import lru_cache
from typing import List, Optional, Set

from prismor.runtime import __version__

# ANSI helpers (mirrors prismor/runtime/cli.py palette so output is visually consistent)
_BOLD = "\033[1m"
_DIM = "\033[37m"
_RESET = "\033[0m"


def _c(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return f"{code}{text}{_RESET}"
    return text


# ── Routing ───────────────────────────────────────────────────────────────────
#
# Routing is fully introspection-driven: `main()` forwards ANY real prismor
# command (see `_prismor_commands()`), and `_print_usage()` builds the help from
# the live parser (see `_command_table()`), so neither can drift out of sync.
_SUPPLY_DOMAIN = "supplychain"


@lru_cache(maxsize=1)
def _prismor_commands() -> Set[str]:
    """Authoritative set of top-level commands ``prismor.runtime.cli`` accepts.

    Introspected from prismor.runtime.cli's argparse parser so the umbrella stays a true
    superset automatically — every prismor subcommand is reachable as
    ``prismor <command>`` with no hand-maintained list to drift out of sync.
    """
    import argparse
    try:
        from prismor.runtime.cli import build_parser
        parser = build_parser()
    except Exception:
        return set()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices.keys())
    return set()


def _deprecation_notice() -> None:
    """Nudge users off the old `immunity` command and the `immunity-agent`
    package name. Fires once per invocation, only when the binary was called as
    `immunity`. Suppressable with PRISMOR_NO_DEPRECATION=1 for scripts/CI."""
    if os.environ.get("PRISMOR_NO_DEPRECATION"):
        return
    if os.path.basename(sys.argv[0] or "") != "immunity":
        return
    sys.stderr.write(
        "\033[33mnote:\033[0m the 'immunity' command is now 'prismor'. "
        "'immunity' still works for now but will be removed.\n"
        "      Switch with: pip install -U prismor   (then use 'prismor ...')\n"
    )


def _update_notice() -> None:
    """Passive nag when a newer prismor is on PyPI. The actual PyPI check is
    debounced (see version_check.latest_known_version — at most once/day), so
    this adds no network latency to most invocations. Never called for
    `hook-dispatch`, which fires on every tool call and cannot afford stderr
    noise or a network hit on that path. Suppressable with
    PRISMOR_NO_UPDATE_CHECK=1 for scripts/CI."""
    if os.environ.get("PRISMOR_NO_UPDATE_CHECK"):
        return
    try:
        from prismor.runtime.version_check import latest_known_version
        latest = latest_known_version()
    except Exception:
        return
    if not latest or latest == __version__:
        return
    sys.stderr.write(
        f"\033[33mnote:\033[0m prismor {latest} is available (you're on {__version__}). "
        "Run `prismor update` to upgrade.\n"
    )


def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    _deprecation_notice()
    if argv and argv[0] != "hook-dispatch":
        _update_notice()

    if not argv or argv[0] in ("-h", "--help", "help"):
        _print_usage()
        return

    if argv[0] in ("-V", "--version"):
        print(f"prismor {__version__}")
        return

    cmd, rest = argv[0], argv[1:]

    # `prismor supplychain ...` — supply-chain enforcement engine.
    if cmd == _SUPPLY_DOMAIN:
        from supplychain.cli import run_supply
        run_supply(rest)
        return

    # Any genuine prismor top-level command (domains, shortcuts, and any future
    # prismor subcommand) forwards straight through: `prismor <cmd> ...`.
    if cmd in _prismor_commands():
        from prismor.runtime.cli import main as prismor_main
        prismor_main([cmd, *rest])
        return

    sys.stderr.write(
        f"prismor: unknown command '{cmd}'.\n"
        f"  Run 'prismor --help' to see all commands.\n"
    )
    sys.exit(2)


# Ordered grouping for `prismor help`. Every group lists the commands it
# owns; any introspected command NOT named here lands in the "More" catch-all,
# so a new prismor.runtime.cli subcommand can never silently vanish from help.
_HELP_GROUPS = [
    ("Quick start",          ["setup", "discover", "status", "dashboard", "audit", "update", "pause", "pause-hard", "resume"]),
    ("Runtime protection",   ["check", "semantic-check", "scan", "deps", "sandbox", "policy"]),
    ("Sessions & forensics", ["analyze", "ingest", "sessions", "session"]),
    ("Hooks",                ["install-hooks", "uninstall-hooks", "mcp-gateway"]),
    ("Secret prevention",    ["cloak", "sweep", "canary"]),
    ("Identity & scoping",   ["iam", "scope", "learn"]),
    ("Enterprise / org",     ["enroll", "enroll-status", "workspace", "exempt", "logout"]),
    ("Supply chain",         ["supplychain"]),
]

# Commands handled elsewhere in the help (deprecated section) or never shown.
_HELP_HIDDEN = {"hook-dispatch", "info", "serve"}

# supplychain is dispatched by this umbrella, not a prismor.runtime.cli subcommand, so it
# is injected manually with its own help + sub-actions.
_SUPPLY_HELP = ("Supply-chain install gating + project hardening", "supplychain")
_SUPPLY_ACTIONS = ["npm", "pip", "pnpm", "yarn", "uv", "cargo", "go", "harden"]


def _command_table():
    """Introspect build_parser() → {name: (help, sub_actions, mode_flags)}.

    Generated from the live parser so help can never drift from the real CLI.
    """
    import argparse
    table = {}
    try:
        from prismor.runtime.cli import build_parser
        parser = build_parser()
    except Exception:
        return table
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        helps = {ca.dest: (ca.help or "") for ca in action._get_subactions()}
        for name, sub in action.choices.items():
            nested, flags = [], []
            for sa in sub._actions:
                if isinstance(sa, argparse._SubParsersAction):
                    nested = list(sa.choices.keys())
                elif isinstance(sa, argparse._StoreTrueAction):
                    flags += [o for o in sa.option_strings if o.startswith("--")]
            table[name] = (helps.get(name, ""), nested, flags)
        break
    # supplychain isn't in prismor.runtime.cli — add it so help is complete.
    table["supplychain"] = (_SUPPLY_HELP[0], _SUPPLY_ACTIONS, [])
    return table


def _print_usage() -> None:
    def b(t: str) -> str: return _c(t, _BOLD)
    def d(t: str) -> str: return _c(t, _DIM)

    table = _command_table()
    pad = 16

    def _emit(name: str) -> None:
        if name not in table:
            return
        help_text, nested, flags = table[name]
        full_cmd = f"prismor {name}"
        col = pad + 9
        print(f"    {full_cmd.ljust(col)}{d(help_text)}")
        if nested:
            sub = " · ".join(f"prismor {name} {s}" for s in nested)
            print(f"    {' ' * col}{d('· ' + sub)}")
        elif flags:
            print(f"    {' ' * col}{d('modes:  ' + '  '.join(flags))}")

    print()
    print(f"  {b('prismor')} — runtime security for AI coding agents")
    print()
    print(f"  Usage: {b('prismor')} <command> [options...]")
    print(f"         {b('prismor')} <command> --help   {d('flags + sub-actions for one command')}")

    grouped = set(_HELP_HIDDEN)
    for title, names in _HELP_GROUPS:
        present = [n for n in names if n in table]
        if not present:
            continue
        print()
        print(f"  {b(title)}")
        for n in present:
            _emit(n)
            grouped.add(n)

    # Catch-all: any real command not placed in a group above.
    leftover = [n for n in table if n not in grouped]
    if leftover:
        print()
        print(f"  {b('More')}")
        for n in sorted(leftover):
            _emit(n)

    col = pad + 9
    print()
    print(f"  {b('Help & version')}")
    print(f"    {'prismor --help'.ljust(col)}{d('This message')}")
    print(f"    {'prismor <cmd> --help'.ljust(col)}{d('Flags + sub-actions for one command')}")
    print(f"    {'prismor --version'.ljust(col)}{d('Show version')}")
    print()
    print(f"  {b('Deprecated')}  {d('(kept working; will be removed in a future release)')}")
    print(f"    {'prismor info'.ljust(col)}{d('use `prismor status`')}")
    print(f"    {'prismor serve'.ljust(col)}{d('use `prismor dashboard --no-open`')}")
    print()


if __name__ == "__main__":
    main()
