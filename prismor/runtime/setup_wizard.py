"""Prismor — interactive setup wizard, usable from both pip install and git clone.

This module contains the full 4-step TUI wizard and the non-interactive install path.
It is the backing implementation for ``prismor setup``.

The original wizard in ``scripts/setup.py`` continues to work for git-clone users
running ``bash ~/.prismor/scripts/init.sh``; this module is its pip-installable twin.
"""

from __future__ import annotations

import atexit
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional

# ── Constants ────────────────────────────────────────────────────────────────

try:
    from prismor.runtime import __version__ as _PKG_VERSION
except Exception:
    _PKG_VERSION = "0.0.0"
_VERSION = f"v{_PKG_VERSION}"
_BACK = object()  # sentinel for "go back"

# repo_root for passing to install_hooks — parent of the prismor/runtime/ package
_PKG_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _PKG_DIR.parent

# ── ANSI ─────────────────────────────────────────────────────────────────────

RST  = "\033[0m"
BOLD = "\033[1m"
DIM  = "\033[37m"
CYAN = "\033[36m"
GRN  = "\033[32m"
YEL  = "\033[33m"
RED  = "\033[31m"
BLU  = "\033[34m"
WHT  = "\033[97m"

HIDE    = "\033[?25l"
SHOW    = "\033[?25h"
ALT_ON  = "\033[?1049h"
ALT_OFF = "\033[?1049l"


def _s(*codes: str) -> str:
    return "".join(codes)


def _w(text: str, *codes: str) -> str:
    if not codes or codes == ("",):
        return str(text)
    return "".join(codes) + str(text) + RST


def _visible_len(text: str) -> int:
    return len(re.sub(r"\033\[[0-9;]*m", "", str(text)))


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _visible_len(text))


# ── Screen buffer ────────────────────────────────────────────────────────────

def _term_width() -> int:
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80


def _term_height() -> int:
    try:
        return os.get_terminal_size().lines
    except Exception:
        return 24


def _render(lines: List[str]) -> None:
    buf = "\033[H\033[J" + HIDE
    for line in lines:
        buf += line + "\n"
    sys.stdout.write(buf)
    sys.stdout.flush()


# ── Terminal input ───────────────────────────────────────────────────────────

try:
    import tty
    import termios
    _HAS_TTY = True
except ImportError:
    _HAS_TTY = False

_saved_attrs = None


def _raw_on() -> None:
    global _saved_attrs
    if not _HAS_TTY:
        return
    fd = sys.stdin.fileno()
    _saved_attrs = termios.tcgetattr(fd)
    tty.setcbreak(fd)


def _raw_off() -> None:
    if not _HAS_TTY or _saved_attrs is None:
        return
    try:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, _saved_attrs)
    except Exception:
        pass


def _cleanup() -> None:
    _raw_off()
    sys.stdout.write(ALT_OFF + SHOW)
    sys.stdout.flush()


atexit.register(_cleanup)
signal.signal(signal.SIGINT,  lambda *_: (_cleanup(), sys.exit(0)))
signal.signal(signal.SIGTERM, lambda *_: (_cleanup(), sys.exit(0)))


def _read_key() -> str:
    ch = sys.stdin.read(1)
    if ch == "\x1b":
        ch2 = sys.stdin.read(1)
        if ch2 == "[":
            ch3 = sys.stdin.read(1)
            return "ESC[" + ch3
        return ch
    return ch


_UP    = "ESC[A"
_DOWN  = "ESC[B"
_RIGHT = "ESC[C"
_LEFT  = "ESC[D"
_ENTER = "\r"
_SPACE = " "


# ── Rule loading ─────────────────────────────────────────────────────────────

def _load_rules() -> List[dict]:
    policy = _PKG_DIR / "default_policy.yaml"
    if policy.exists():
        try:
            import yaml
            with policy.open() as f:
                data = yaml.safe_load(f)
            return [
                {
                    "id":       r["id"],
                    "severity": r["severity"],
                    "title":    r.get("title", r["id"]),
                    "on":       True,
                }
                for r in data.get("rules", [])
            ]
        except ImportError:
            return _parse_policy_manual(policy)
    return _default_rules()


def _parse_policy_manual(policy: Path) -> List[dict]:
    rules: List[dict] = []
    cur: dict = {}
    inside = False
    with policy.open() as f:
        for line in f:
            s = line.strip()
            if s == "rules:":
                inside = True
                continue
            if not inside:
                continue
            if s.startswith("allowlists:") or s.startswith("settings:"):
                break
            m = re.match(r"^\s*-\s*id:\s*(.+)$", line)
            if m:
                if cur:
                    rules.append(cur)
                cur = {"id": m.group(1).strip(), "severity": "MEDIUM",
                       "title": m.group(1).strip(), "on": True}
            m2 = re.match(r"^\s*severity:\s*(\w+)", line)
            if m2 and cur:
                cur["severity"] = m2.group(1)
            m3 = re.match(r"^\s*title:\s*(.+)$", line)
            if m3 and cur:
                cur["title"] = m3.group(1).strip()
    if cur:
        rules.append(cur)
    return rules or _default_rules()


def _default_rules() -> List[dict]:
    D = [
        ("destructive-command",     "CRITICAL", "Blocks rm -rf /, mkfs, dd to disk, shutdown, reboot"),
        ("secret-exfiltration",     "CRITICAL", "Blocks cat .env | curl, piping secrets to external hosts"),
        ("dos-resource-exhaustion", "CRITICAL", "Blocks fork bombs, while-true loops, /dev/urandom abuse"),
        ("rce-canary",              "CRITICAL", "Blocks reverse shells, bash -i /dev/tcp, crontab injection"),
        ("privilege-escalation",    "CRITICAL", "Blocks chmod +s, sudoers edits, useradd, setcap"),
        ("prompt-injection",        "HIGH",     "Detects 'ignore instructions', 'reveal system prompt' in agent I/O"),
        ("remote-execution",        "HIGH",     "Blocks curl | bash, wget | sh fetch-and-execute chains"),
        ("secret-access",           "HIGH",     "Flags reads/writes to .env, .ssh/id_rsa, .aws/credentials"),
        ("suspicious-network",      "HIGH",     "Flags calls to webhook.site, ngrok, pastebin, Discord webhooks"),
        ("db-modification",         "HIGH",     "Flags DROP TABLE, DELETE FROM, TRUNCATE in shell commands"),
        ("risky-write",             "MEDIUM",   "Flags writes to Dockerfile, CI workflows, package.json"),
    ]
    return [{"id": i, "severity": s, "title": t, "on": True} for i, s, t in D]


# ── Agent detection ──────────────────────────────────────────────────────────

def _detect_agents(target: Path) -> dict:
    home = Path.home()
    return {
        "claude":   shutil.which("claude") is not None or (target / ".claude").exists() or (home / ".claude").exists(),
        "cursor":   (target / ".cursor").exists() or (home / ".cursor").exists(),
        "windsurf": (target / ".windsurf").exists() or (home / ".codeium").exists(),
        "openclaw": shutil.which("openclaw") is not None or (target / ".openclaw").exists(),
        "hermes":   shutil.which("hermes") is not None or (target / ".hermes").exists(),
        "codex":    shutil.which("codex") is not None or (target / ".codex").exists() or (home / ".codex").exists(),
        "grok":     shutil.which("grok") is not None or (target / ".grok").exists() or (home / ".grok").exists(),
    }


# ── Severity colors ──────────────────────────────────────────────────────────

def _sev_color(s: str) -> str:
    s = s.upper()
    if s == "CRITICAL": return RED
    if s == "HIGH":     return YEL
    if s == "MEDIUM":   return BLU
    return DIM


# ── Shared UI pieces ─────────────────────────────────────────────────────────

def _header_lines(step: Optional[int] = None, total: Optional[int] = None, label: Optional[str] = None) -> List[str]:
    tw = _term_width()
    out = [
        "",
        f"  {_w('PRISMOR', BOLD, CYAN)}  {_w('· ' + _VERSION, DIM)}",
    ]
    if step and label:
        out.append(f"  {_w(f'Step {step}/{total}', DIM)}  {_w(label, BOLD)}")
    out.append(_w("  " + "─" * min(tw - 4, 64), DIM))
    out.append("")
    return out


def _control_line(items: List[tuple]) -> str:
    parts = [_w(k, BOLD, CYAN) + _w(f" {d}", DIM) for k, d in items]
    return "  " + _w(" · ", DIM).join(parts)


# ── Step 1: Enforcement Mode ─────────────────────────────────────────────────

def _step_mode(current: str = "enforce") -> str:
    opts = [
        ("observe", "Log and warn, never block"),
        ("enforce", "Block dangerous actions in real time"),
    ]
    sel = 0 if current == "observe" else 1

    while True:
        lines = _header_lines(1, 4, "ENFORCEMENT MODE")
        for i, (name, desc) in enumerate(opts):
            arrow = _w("▸ ", CYAN) if i == sel else "  "
            dot   = _w("●", GRN) if i == sel else _w("○", DIM)
            nm    = _pad(_w(name, BOLD) if i == sel else _w(name, DIM), 16)
            lines.append(f"  {arrow}{dot}  {nm}{_w(desc, DIM)}")
        lines.append("")
        lines.append(_control_line([("↑↓", "select"), ("enter", "next"), ("q", "quit")]))
        _render(lines)

        key = _read_key()
        if key == _UP:               sel = (sel - 1) % len(opts)
        elif key == _DOWN:           sel = (sel + 1) % len(opts)
        elif key in (_ENTER, "\n"):  return opts[sel][0]
        elif key in ("q", "Q", "\x03"): _cleanup(); sys.exit(0)


# ── Step 2: Agent Selection ──────────────────────────────────────────────────

def _step_agents(target: Path) -> list:
    detected = _detect_agents(target)
    agents = [
        {"name": "claude",   "label": "Claude Code", "on": detected.get("claude", False)},
        {"name": "cursor",   "label": "Cursor",      "on": detected.get("cursor", False)},
        {"name": "windsurf", "label": "Windsurf",    "on": detected.get("windsurf", False)},
        {"name": "openclaw", "label": "OpenClaw",    "on": detected.get("openclaw", False)},
        {"name": "hermes",   "label": "Hermes",      "on": detected.get("hermes", False)},
        {"name": "codex",    "label": "Codex",       "on": detected.get("codex", False)},
        {"name": "grok",     "label": "Grok Build",  "on": detected.get("grok", False)},
    ]
    if not any(a["on"] for a in agents):
        agents[0]["on"] = True
    sel = 0

    while True:
        lines = _header_lines(2, 4, "AGENTS")
        lines.append(f"  {_w('Select agents to install Prismor hooks for:', DIM)}")
        lines.append("")
        for i, ag in enumerate(agents):
            arrow = _w("▸ ", CYAN) if i == sel else "  "
            dot   = _w("●", GRN) if ag["on"] else _w("○", DIM)
            name  = _pad(_w(ag["label"], BOLD) if i == sel else ag["label"], 18)
            tag   = _w("detected", GRN) if detected[ag["name"]] else _w("not found", DIM)
            lines.append(f"  {arrow}{dot}  {name} {tag}")
        lines.append("")
        lines.append(_control_line([
            ("↑↓", "move"), ("space", "toggle"),
            ("←", "back"), ("enter", "next"),
        ]))
        _render(lines)

        key = _read_key()
        if key == _UP:               sel = (sel - 1) % len(agents)
        elif key == _DOWN:           sel = (sel + 1) % len(agents)
        elif key == _SPACE:          agents[sel]["on"] = not agents[sel]["on"]
        elif key in (_LEFT, "b", "B"): return _BACK  # type: ignore[return-value]
        elif key in (_ENTER, "\n"):
            chosen = [a["name"] for a in agents if a["on"]]
            return chosen if chosen else ["claude"]
        elif key in ("q", "Q", "\x03"): _cleanup(); sys.exit(0)


# ── Step 3: Secret Cloaking ──────────────────────────────────────────────────

def _step_cloak(current: bool = True) -> bool:
    opts = [
        ("yes", "Install cloaking hooks  (recommended — prevents secret leaks to the LLM provider)"),
        ("no",  "Skip — only runtime policy hooks will be installed"),
    ]
    sel = 0 if current else 1

    while True:
        lines = _header_lines(3, 4, "SECRET CLOAKING")
        lines.append(f"  {_w('Prevents real secrets from reaching model context, JSONL transcripts,', DIM)}")
        lines.append(f"  {_w('or upstream API requests. See prismor/runtime/cloaking/README.md.', DIM)}")
        lines.append("")
        for i, (name, desc) in enumerate(opts):
            arrow = _w("▸ ", CYAN) if i == sel else "  "
            dot   = _w("●", GRN) if i == sel else _w("○", DIM)
            tw = _term_width()
            max_desc = max(tw - 24, 30)
            nm = _pad(_w(name, BOLD) if i == sel else _w(name, DIM), 8)
            lines.append(f"  {arrow}{dot}  {nm}{_w(desc[:max_desc], DIM)}")
        lines.append("")
        lines.append(_control_line([
            ("↑↓", "select"), ("←", "back"), ("enter", "next"), ("q", "quit"),
        ]))
        _render(lines)

        key = _read_key()
        if key == _UP:                  sel = (sel - 1) % len(opts)
        elif key == _DOWN:              sel = (sel + 1) % len(opts)
        elif key in (_LEFT, "b", "B"):  return _BACK  # type: ignore[return-value]
        elif key in (_ENTER, "\n"):     return opts[sel][0] == "yes"
        elif key in ("q", "Q", "\x03"): _cleanup(); sys.exit(0)


# ── Step 4: Install Scope ────────────────────────────────────────────────────

def _step_scope(current: str = "project") -> str:
    opts = [
        ("project", "This workspace only",    "Hooks written to .claude/settings.json in the current project"),
        ("global",  "Global (all projects)",  "Hooks written to ~/.claude/settings.json — covers every workspace"),
    ]
    sel = 0 if current == "project" else 1

    while True:
        lines = _header_lines(4, 4, "INSTALL SCOPE")
        lines.append(f"  {_w('Where should Immunity hooks be installed?', DIM)}")
        lines.append("")
        tw = _term_width()
        for i, (key, label, desc) in enumerate(opts):
            arrow = _w("▸ ", CYAN) if i == sel else "  "
            dot   = _w("●", GRN) if i == sel else _w("○", DIM)
            nm    = _pad(_w(label, BOLD) if i == sel else _w(label, DIM), 26)
            lines.append(f"  {arrow}{dot}  {nm}{_w(desc[:max(tw - 36, 20)], DIM)}")
        lines.append("")
        lines.append(_control_line([
            ("↑↓", "select"), ("←", "back"), ("enter", "next"), ("q", "quit"),
        ]))
        _render(lines)

        key = _read_key()
        if key == _UP:                  sel = (sel - 1) % len(opts)
        elif key == _DOWN:              sel = (sel + 1) % len(opts)
        elif key in (_LEFT, "b", "B"):  return _BACK  # type: ignore[return-value]
        elif key in (_ENTER, "\n"):     return opts[sel][0]
        elif key in ("q", "Q", "\x03"): _cleanup(); sys.exit(0)


# ── Confirm ──────────────────────────────────────────────────────────────────

def _step_confirm(target: Path, mode: str, rules: List[dict], agents: List[str], cloak: bool = False, scope: str = "project") -> bool:
    home = str(Path.home())
    disp = str(target).replace(home, "~")
    n_on = sum(1 for r in rules if r["on"])
    ags  = ", ".join(agents)
    W = 48

    def bdr(l, fill, r):
        return _w(f"  {l}{fill * W}{r}", DIM)

    def row(content: str = "") -> str:
        vl = _visible_len(content)
        p = " " * max(0, W - vl - 2)
        return _w("  │", DIM) + " " + content + p + " " + _w("│", DIM)

    def kv(k: str, v: str, vc: str = WHT) -> str:
        return f"{_pad(_w(k, DIM), 14)}{_w(v, vc)}"

    while True:
        lines = _header_lines()
        lines.append(bdr("╭", "─", "╮"))
        lines.append(row(_w("READY TO INSTALL", BOLD)))
        lines.append(row())
        lines.append(row(kv("Project", disp[:30])))
        lines.append(row(kv("Mode", mode, GRN if mode == "enforce" else YEL)))
        lines.append(row(kv("Rules", f"{n_on}/{len(rules)} enabled")))
        lines.append(row(kv("Agents", ags)))
        lines.append(row(kv("Cloak", "yes  (secret prevention)" if cloak else "no",
                            GRN if cloak else DIM)))
        lines.append(row(kv("Scope", "global (all projects)" if scope == "global" else "workspace only",
                            YEL if scope == "global" else GRN)))
        lines.append(row())
        lines.append(bdr("╰", "─", "╯"))
        lines.append("")
        lines.append(_control_line([("enter", "install"), ("←", "back"), ("q", "quit")]))
        _render(lines)

        key = _read_key()
        if key in (_ENTER, "\n"):       return True
        elif key in (_LEFT, "b", "B"):  return _BACK  # type: ignore[return-value]
        elif key in ("q", "Q", "\x03"): _cleanup(); sys.exit(0)


# ── Spinner ───────────────────────────────────────────────────────────────────

_SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def _spinner_run(label: str, fn) -> None:
    stop = threading.Event()

    def spin() -> None:
        i = 0
        while not stop.is_set():
            f = _SPIN[i % len(_SPIN)]
            sys.stdout.write(f"\r  {_w(f, CYAN)}  {label}   ")
            sys.stdout.flush()
            i += 1
            time.sleep(0.08)

    t = threading.Thread(target=spin, daemon=True)
    t.start()
    try:
        ok, msg = fn()
    except Exception as e:
        ok, msg = False, str(e)[:60]
    stop.set()
    t.join(timeout=0.3)
    icon = _w("✓", GRN) if ok else _w("✗", RED)
    suffix = f"  {_w(msg, DIM)}" if msg else ""
    sys.stdout.write(f"\r  {icon}  {label}{suffix}            \n")
    sys.stdout.flush()



_AGENT_CONTEXT_BLOCK = (
    "\n## Security (Prismor)\n\n"
    "This workspace is protected by Prismor. "
    "Run `prismor status` at the start of every session.\n\n"
    "Key commands:\n\n"
    "| Action | Command |\n"
    "|---|---|\n"
    "| Check protection state | `prismor status` |\n"
    "| Install packages safely | `prismor supplychain <pm> install <pkg>` |\n"
    "| Pre-check a risky command | `prismor check \"<cmd>\"` |\n"
    "| Scan for dep vulnerabilities | `prismor deps` |\n"
    "| Harden package config | `prismor supplychain harden` |\n\n"
    "Full decision tree: `.claude/skills/immunity-agent/SKILL.md`\n"
)

_AGENTS_MD_AGENTS = {"codex", "openclaw", "hermes", "copilot"}


def _write_agent_context(target: Path, agents: List[str]) -> None:
    """Write the immunity-agent command reference into agent-specific context files."""
    agent_files = {
        "cursor": target / ".cursorrules",
        "windsurf": target / ".windsurfrules",
    }
    for agent, path in agent_files.items():
        if agent not in agents:
            continue
        content = path.read_text(encoding="utf-8") if path.exists() else ""
        if "Prismor" not in content:
            path.write_text(content + _AGENT_CONTEXT_BLOCK, encoding="utf-8")

    if any(a in agents for a in _AGENTS_MD_AGENTS):
        path = target / "AGENTS.md"
        content = path.read_text(encoding="utf-8") if path.exists() else ""
        if "Prismor" not in content:
            path.write_text(content + _AGENT_CONTEXT_BLOCK, encoding="utf-8")


# ── Install ───────────────────────────────────────────────────────────────────

def _install_skill(target: Path):
    """Copy the bundled immunity-agent Claude skill into the workspace.

    Installs to ``<target>/.claude/skills/immunity-agent/`` (SKILL.md plus its
    docs/). Idempotent: if a SKILL.md is already present it's left untouched so
    user edits survive re-runs. Returns ``(ok, detail)`` for the spinner.
    """
    try:
        from prismor.runtime.paths import skill_manifest_path, skill_docs_dir
        skill_md = skill_manifest_path()
        docs_src = skill_docs_dir()
    except Exception as e:
        return False, str(e)[:40]
    if not skill_md.exists():
        return True, "skipped (skill not bundled)"

    dest = target / ".claude" / "skills" / "immunity-agent"
    if (dest / "SKILL.md").exists():
        return True, "already present"
    try:
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(skill_md, dest / "SKILL.md")
        if docs_src.exists() and docs_src.is_dir():
            docs_dest = dest / "docs"
            docs_dest.mkdir(exist_ok=True)
            for md in docs_src.glob("*.md"):
                shutil.copy2(md, docs_dest / md.name)
        return True, "installed"
    except OSError as e:
        return False, str(e)[:40]


def _do_install(target: Path, mode: str, rules: List[dict], agents: List[str], cloak: bool = False, scope: str = "project") -> None:
    sys.stdout.write(ALT_OFF)
    sys.stdout.write("\033[H\033[J" + HIDE)
    sys.stdout.flush()
    print(_w("  Installing Prismor...\n", BOLD, CYAN))

    target = target.resolve()

    # 0. Register workspace
    def _register():
        try:
            from prismor.runtime.store import register_workspace
            register_workspace(target)
            return True, ""
        except Exception as e:
            return False, str(e)[:40]
    _spinner_run("Registering workspace", _register)

    # 1. Update Prismor — only for git-clone installs
    prismor_home = os.environ.get("PRISMOR_HOME")
    git_root: Optional[Path] = None
    if prismor_home:
        p = Path(prismor_home).expanduser()
        if (p / ".git").exists():
            git_root = p
    elif (_REPO_ROOT / ".git").exists():
        git_root = _REPO_ROOT

    if git_root is not None:
        def _update():
            r = subprocess.run(
                ["git", "-C", str(git_root), "pull", "--quiet"],
                capture_output=True, timeout=15,
            )
            return r.returncode == 0, "up to date" if r.returncode == 0 else "offline"
        _spinner_run("Updating Prismor", _update)
    else:
        def _pip_note():
            return True, "run `pip install --upgrade prismor` to update"
        _spinner_run("Prismor (pip install)", _pip_note)

    # 2. Policy overrides for disabled rules
    disabled = [r["id"] for r in rules if not r["on"]]
    if disabled:
        def _write_policy():
            d = target / ".prismor"
            d.mkdir(exist_ok=True)
            txt = 'version: "1.0"\nrules:\n'
            for rid in disabled:
                txt += f"  - id: {rid}\n    enabled: false\n"
            (d / "policy.yaml").write_text(txt)
            return True, f"{len(disabled)} disabled"
        _spinner_run("Writing policy overrides", _write_policy)

    # 3. Install hooks directly via prismor.runtime.hooks
    from prismor.runtime.hooks import install_hooks
    for agent in agents:
        def _install_hook(a: str = agent):
            try:
                install_hooks(
                    repo_root=_REPO_ROOT,
                    workspace=target,
                    agent=a,
                    scope=scope,
                    mode=mode,
                )
                return True, ""
            except Exception as e:
                return False, str(e)[:50]
        _spinner_run(f"Installing {agent} hooks", _install_hook)

    # 3b. Cloaking hooks (opt-in — Claude Code only for now)
    if cloak and "claude" in agents:
        def _install_cloak():
            if not shutil.which("jq"):
                return False, "jq not found (brew install jq)"
            # Route through prismor/runtime/cli.py directly with the current interpreter.
            # Don't shell out to a `prismor` binary on PATH — that entry point is
            # a deprecation shim and prints a "'prismor' is deprecated" warning.
            r = subprocess.run(
                [sys.executable, str(_PKG_DIR / "cli.py"), "cloak", "install",
                 "--workspace", str(target), "--scope", scope],
                capture_output=True, timeout=30,
            )
            return r.returncode == 0, "enabled" if r.returncode == 0 else r.stderr.decode()[:40]
        _spinner_run("Installing cloaking hooks", _install_cloak)

    # 4. CLAUDE.md
    def _update_claude():
        md = target / "CLAUDE.md"
        block = (
            "\n## Security (Prismor)\n\n"
            "This workspace is protected by Prismor — runtime "
            "security hooks that monitor tool calls in real time (destructive "
            "commands, secret leaks, supply-chain risk, prompt injection).\n\n"
            "Run `prismor status` at the start of a session to check protection "
            "state. The full decision tree lives in "
            "`.claude/skills/immunity-agent/SKILL.md`.\n\n"
            "For more info: https://github.com/PrismorSec/prismor\n"
        )
        if md.exists():
            content = md.read_text()
            if "Prismor" in content:
                return True, "already present"
            md.write_text(content + block)
            return True, "appended"
        md.write_text(block.lstrip())
        return True, "created"
    _spinner_run("Updating CLAUDE.md", _update_claude)

    # 4b. Install SKILL.md for all workspaces — any agent can read it.
    _spinner_run("Installing immunity-agent skill", lambda: _install_skill(target))

    # 4c. Agent-specific context files (cursorrules, windsurfrules, AGENTS.md).
    def _write_context():
        try:
            _write_agent_context(target, agents)
            return True, ""
        except OSError as e:
            return False, str(e)[:50]
    _spinner_run("Writing agent context", _write_context)

    # 5. Feed signature verification (use prismor.runtime.paths resolver, skip shell script)
    def _verify_feed():
        try:
            from prismor.runtime.paths import feed_path, public_key_path, feed_sig_path
            fp  = feed_path()
            sig = feed_sig_path()
            pub = public_key_path()
        except ImportError:
            return True, "skipped (paths unavailable)"
        if not all(p.exists() for p in (fp, sig, pub)):
            return True, "skipped (feed not bundled)"
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".sig.raw") as tf:
            sig_raw = tf.name
        try:
            # .sig file is base64-encoded; decode to raw binary first
            import base64
            sig_bytes = base64.b64decode(sig.read_bytes())
            Path(sig_raw).write_bytes(sig_bytes)
            r = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-rawin",
                 "-inkey", str(pub), "-sigfile", sig_raw, "-in", str(fp)],
                capture_output=True, timeout=15,
            )
            return r.returncode == 0, "verified" if r.returncode == 0 else "signature mismatch"
        finally:
            try:
                Path(sig_raw).unlink()
            except Exception:
                pass
    _spinner_run("Verifying feed signature", _verify_feed)

    # Done — success banner
    home = str(Path.home())
    print()
    print(_w("  ╭───────────────────────────────────────────╮", DIM))
    print(_w("  │", DIM) + _w("  Prismor installed successfully!    ", GRN, BOLD) + _w("│", DIM))
    print(_w("  ╰───────────────────────────────────────────╯", DIM))
    print()

    def _info(k: str, v: str) -> None:
        print(f"  {_w(k + ':', GRN)}  {_w(v, DIM)}")

    _info("Hooks",      f"installed  (mode: {mode})")
    if "claude" in agents:
        _info("Skill",  str(target / ".claude" / "skills" / "immunity-agent").replace(home, "~"))
    _info("Docs",       "https://github.com/PrismorSec/prismor")
    _info("Config",     str(target / "CLAUDE.md").replace(home, "~"))
    _info("Command",    "prismor status  ·  prismor sessions  ·  prismor check \"<cmd>\"")
    print()
    print(_w("  Quick commands:", GRN))
    print(f"    prismor status                       {_w('this workspace health check', DIM)}")
    print(f"    prismor status --all                 {_w('overview across all workspaces', DIM)}")
    print(f"    prismor sessions --findings-only     {_w('all flagged sessions by risk', DIM)}")
    print(f"    prismor check \"rm -rf /\"              {_w('pre-check a command', DIM)}")
    print(f"    prismor sweep                        {_w('scan AI tool configs for leaked secrets', DIM)}")
    print()
    sys.stdout.write(SHOW)
    sys.stdout.flush()


# ── Public API ────────────────────────────────────────────────────────────────

def run_non_interactive(
    target: Path,
    *,
    mode: str = "observe",
    agents: Optional[List[str]] = None,
    cloak: bool = False,
    scope: str = "project",
) -> None:
    """Run install without TUI. Args take precedence over env vars (resolution done by caller)."""
    rules = _load_rules()
    if agents is None:
        det = _detect_agents(target)
        agents = [n for n, ok in det.items() if ok] or ["claude"]
    cloak_tag = ", cloak=yes" if cloak else ""
    scope_tag = f", scope={scope}" if scope != "project" else ""
    print(f"[prismor] Non-interactive setup  (mode={mode}, agents={','.join(agents)}{cloak_tag}{scope_tag})")
    _do_install(target, mode, rules, agents, cloak=cloak, scope=scope)


def run_wizard(target: Path) -> None:
    """Run the full 4-step interactive TUI wizard."""
    sys.stdout.write(ALT_ON + HIDE)
    sys.stdout.flush()
    _raw_on()

    # All detection rules ship enabled by default — there is no per-rule toggle
    # step. Rules are loaded only so the confirm screen can show the count and
    # _do_install can write policy overrides if any are ever disabled.
    rules = _load_rules()
    mode = "enforce"
    agents = None
    cloak = True
    scope = "project"
    step = 1

    try:
        while True:
            if step == 1:
                mode = _step_mode(mode)
                step = 2
            elif step == 2:
                result = _step_agents(target)
                if result is _BACK:
                    step = 1
                    continue
                agents = result
                step = 3
            elif step == 3:
                result = _step_cloak(cloak)
                if result is _BACK:
                    step = 2
                    continue
                cloak = result
                step = 4
            elif step == 4:
                result = _step_scope(scope)
                if result is _BACK:
                    step = 3
                    continue
                scope = result
                step = 5
            elif step == 5:
                result = _step_confirm(target, mode, rules, agents, cloak=cloak, scope=scope)
                if result is _BACK:
                    step = 4
                    continue
                break
    except Exception:
        rules = _load_rules()
        mode = "enforce"
        agents = ["claude"]
        cloak = False
        scope = "project"

    _raw_off()
    _do_install(target, mode, rules, agents, cloak=cloak, scope=scope)
