#!/usr/bin/env python3
"""
Prismor — Interactive Setup Wizard
Usage: python3 setup.py [TARGET_DIR] [--non-interactive]

Environment variables (non-interactive mode):
    PRISMOR_MODE      observe | enforce    (default: observe)
    PRISMOR_CLOAK     1 | true | yes       (default: off — opts into the
                                            secret-cloaking prevention
                                            layer; requires jq on PATH)
"""

import os
import sys
import tty
import termios
import signal
import atexit
import time
import threading
import subprocess
import shutil
import re
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

def _pkg_version() -> str:
    # Prefer the installed package; fall back to parsing prismor/runtime/__init__.py
    # next to this script (git-clone path where prismor may not be importable).
    try:
        from prismor.runtime import __version__ as v
        return v
    except Exception:
        pass
    try:
        init = Path(__file__).resolve().parent.parent / "prismor" / "__init__.py"
        m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init.read_text())
        if m:
            return m.group(1)
    except Exception:
        pass
    return "0.0.0"

VERSION = f"v{_pkg_version()}"
BACK = object()  # sentinel for "go back"

# ── Hook catalogue ────────────────────────────────────────────────────────────

HOOK_DEFS = [
    {
        "id":      "runtime",
        "label":   "Runtime monitor",
        "default": True,
        "desc":    "Intercepts all tool calls — blocks/logs dangerous Bash, file ops, and prompt injections",
    },
    {
        "id":      "cloak-core",
        "label":   "Secret cloak",
        "default": True,
        "desc":    "Decloak @@SECRET:name@@ in Bash inputs; recloak real secrets from MCP tool output",
    },
    {
        "id":      "cloak-guard",
        "label":   "Secret guard",
        "default": True,
        "desc":    "Detects and denies tool calls where the model passes raw secret values directly",
    },
    {
        "id":      "cloak-prompt",
        "label":   "Prompt guard",
        "default": True,
        "desc":    "Soft-blocks if you paste a raw secret value directly into the chat prompt",
    },
    {
        "id":      "cloak-sweep",
        "label":   "Session sweep",
        "default": False,
        "desc":    "Scans session transcripts for secret residue at session end (verbose — off by default)",
    },
]

def _default_hooks():
    return {d["id"]: d["default"] for d in HOOK_DEFS}

# ── ANSI ─────────────────────────────────────────────────────────────────────

RST  = "\033[0m"
BOLD = "\033[1m"
DIM  = "\033[37m"  # light gray — visible on dark themes (not \033[2m which vanishes)
CYAN = "\033[36m"
GRN  = "\033[32m"
YEL  = "\033[33m"
RED  = "\033[31m"
BLU  = "\033[34m"
WHT  = "\033[97m"

HIDE = "\033[?25l"
SHOW = "\033[?25h"
ALT_ON  = "\033[?1049h"  # switch to alternate screen buffer
ALT_OFF = "\033[?1049l"  # switch back to normal buffer

def s(*codes):
    """Start style."""
    return "".join(codes)

def w(text, *codes):
    """Wrap text in style codes."""
    if not codes or codes == ("",):
        return str(text)
    return "".join(codes) + str(text) + RST

def visible_len(text):
    """Length of text without ANSI escapes."""
    return len(re.sub(r'\033\[[0-9;]*m', '', str(text)))

def pad(text, width):
    """Right-pad text to width, accounting for ANSI codes."""
    vl = visible_len(text)
    return text + " " * max(0, width - vl)

# ── Screen buffer ────────────────────────────────────────────────────────────
# Build frame as list of lines, then flush all at once to reduce flicker.

def term_width():
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80

def term_height():
    try:
        return os.get_terminal_size().lines
    except Exception:
        return 24

def render(lines):
    """Clear screen and draw all lines at once."""
    buf = "\033[H\033[J" + HIDE  # cursor home, clear to end, hide cursor
    for line in lines:
        buf += line + "\n"
    sys.stdout.write(buf)
    sys.stdout.flush()

# ── Terminal input ───────────────────────────────────────────────────────────

_saved = None

def raw_on():
    global _saved
    fd = sys.stdin.fileno()
    _saved = termios.tcgetattr(fd)
    tty.setcbreak(fd)

def raw_off():
    if _saved is not None:
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, _saved)
        except Exception:
            pass

def cleanup():
    raw_off()
    sys.stdout.write(ALT_OFF + SHOW)
    sys.stdout.flush()

atexit.register(cleanup)
signal.signal(signal.SIGINT,  lambda *_: (cleanup(), sys.exit(0)))
signal.signal(signal.SIGTERM, lambda *_: (cleanup(), sys.exit(0)))

def read_key():
    ch = sys.stdin.read(1)
    if ch == '\x1b':
        ch2 = sys.stdin.read(1)
        if ch2 == '[':
            ch3 = sys.stdin.read(1)
            return 'ESC[' + ch3
        return ch
    return ch

UP    = 'ESC[A'
DOWN  = 'ESC[B'
RIGHT = 'ESC[C'
LEFT  = 'ESC[D'
ENTER = '\r'
SPACE = ' '

# ── Rule loading ─────────────────────────────────────────────────────────────

SCRIPT_DIR  = Path(__file__).resolve().parent
PRISMOR_DIR = Path(os.environ.get("PRISMOR_HOME", Path.home() / ".prismor"))
if not PRISMOR_DIR.exists():
    PRISMOR_DIR = SCRIPT_DIR.parent

DEFAULT_POLICY = PRISMOR_DIR / "prismor" / "default_policy.yaml"

def load_rules():
    if DEFAULT_POLICY.exists():
        try:
            import yaml
            with open(DEFAULT_POLICY) as f:
                data = yaml.safe_load(f)
            return [{"id": r["id"], "severity": r["severity"],
                     "title": r.get("title", r["id"]), "on": True}
                    for r in data.get("rules", [])]
        except ImportError:
            pass
        return _parse_manual()
    return _defaults()

def _parse_manual():
    rules, cur, inside = [], {}, False
    with open(DEFAULT_POLICY) as f:
        for line in f:
            s = line.strip()
            if s == "rules:":
                inside = True; continue
            if not inside:
                continue
            if s.startswith("allowlists:") or s.startswith("settings:"):
                break
            m = re.match(r'^\s*-\s*id:\s*(.+)$', line)
            if m:
                if cur: rules.append(cur)
                cur = {"id": m.group(1).strip(), "severity": "MEDIUM",
                       "title": m.group(1).strip(), "on": True}
            m = re.match(r'^\s*severity:\s*(\w+)', line)
            if m and cur: cur["severity"] = m.group(1)
            m = re.match(r'^\s*title:\s*(.+)$', line)
            if m and cur: cur["title"] = m.group(1).strip()
    if cur: rules.append(cur)
    return rules or _defaults()

def _defaults():
    D = [
        ("destructive-command",    "CRITICAL", "Blocks rm -rf /, mkfs, dd to disk, shutdown, reboot"),
        ("secret-exfiltration",    "CRITICAL", "Blocks cat .env | curl, piping secrets to external hosts"),
        ("dos-resource-exhaustion","CRITICAL", "Blocks fork bombs, while-true loops, /dev/urandom abuse"),
        ("rce-canary",             "CRITICAL", "Blocks reverse shells, bash -i /dev/tcp, crontab injection"),
        ("privilege-escalation",   "CRITICAL", "Blocks chmod +s, sudoers edits, useradd, setcap"),
        ("prompt-injection",       "HIGH",     "Detects 'ignore instructions', 'reveal system prompt' in agent I/O"),
        ("remote-execution",       "HIGH",     "Blocks curl | bash, wget | sh fetch-and-execute chains"),
        ("secret-access",          "HIGH",     "Flags reads/writes to .env, .ssh/id_rsa, .aws/credentials"),
        ("suspicious-network",     "HIGH",     "Flags calls to webhook.site, ngrok, pastebin, Discord webhooks"),
        ("db-modification",        "HIGH",     "Flags DROP TABLE, DELETE FROM, TRUNCATE in shell commands"),
        ("db-access",              "HIGH",     "Flags pg_dump, mysqldump, SELECT FROM users/passwords/tokens"),
        ("path-traversal",         "HIGH",     "Flags ../../ traversal, reads of /etc/passwd, /proc/self/environ"),
        ("risky-write",            "MEDIUM",   "Flags writes to Dockerfile, CI workflows, package.json, go.mod"),
    ]
    return [{"id": i, "severity": s, "title": t, "on": True} for i, s, t in D]

# ── Agent detection ──────────────────────────────────────────────────────────

def detect_agents(target):
    td, home = Path(target), Path.home()
    return {
        "claude":   shutil.which("claude") is not None or (td/".claude").exists() or (home/".claude").exists(),
        "cursor":   (td/".cursor").exists() or (home/".cursor").exists(),
        "windsurf": (td/".windsurf").exists() or (home/".codeium").exists(),
        "openclaw": shutil.which("openclaw") is not None or (td/".openclaw").exists() or (home/".openclaw").exists(),
        "hermes":   shutil.which("hermes") is not None or (td/".hermes").exists() or (home/".hermes").exists(),
        "grok":     shutil.which("grok") is not None or (td/".grok").exists() or (home/".grok").exists(),
        "kiro":     shutil.which("kiro-cli") is not None or shutil.which("kiro") is not None or (td/".kiro").exists() or (home/".kiro").exists(),
    }

# ── Severity colors ──────────────────────────────────────────────────────────

def sev_color(s):
    s = s.upper()
    if s == "CRITICAL": return RED
    if s == "HIGH":     return YEL
    if s == "MEDIUM":   return BLU
    return DIM

# ── Shared UI pieces ─────────────────────────────────────────────────────────

def header_lines(step=None, total=None, label=None):
    tw = term_width()
    out = [
        "",
        f"  {w('PRISMOR', BOLD, CYAN)}  {w('· ' + VERSION, DIM)}",
    ]
    if step and label:
        out.append(f"  {w(f'Step {step}/{total}', DIM)}  {w(label, BOLD)}")
    out.append(w("  " + "─" * min(tw - 4, 64), DIM))
    out.append("")
    return out

def control_line(items):
    """items: list of (key, desc)"""
    parts = [w(k, BOLD, CYAN) + w(f" {d}", DIM) for k, d in items]
    return "  " + w(" · ", DIM).join(parts)

# ── Step 1: Enforcement Mode ─────────────────────────────────────────────────

def step_mode(current="enforce"):
    opts = [
        ("observe", "Log and warn, never block"),
        ("enforce", "Block dangerous actions in real time"),
    ]
    sel = 0 if current == "observe" else 1

    while True:
        lines = header_lines(1, 3, "ENFORCEMENT MODE")
        for i, (name, desc) in enumerate(opts):
            arrow = w("▸ ", CYAN) if i == sel else "  "
            dot   = w("●", GRN) if i == sel else w("○", DIM)
            nm    = pad(w(name, BOLD) if i == sel else w(name, DIM), 16)
            lines.append(f"  {arrow}{dot}  {nm}{w(desc, DIM)}")
        lines.append("")
        lines.append(control_line([("↑↓", "select"), ("enter", "next"), ("q", "quit")]))
        render(lines)

        key = read_key()
        if key in (UP,):    sel = (sel - 1) % len(opts)
        elif key in (DOWN,):  sel = (sel + 1) % len(opts)
        elif key in (ENTER, '\n'): return opts[sel][0]
        elif key in ('q', 'Q', '\x03'): cleanup(); sys.exit(0)

# ── Step 2: Agent Selection ──────────────────────────────────────────────────

def step_agents(target):
    detected = detect_agents(target)
    agents = [
        {"name": "claude",   "label": "Claude Code", "on": detected.get("claude", False)},
        {"name": "cursor",   "label": "Cursor",      "on": detected.get("cursor", False)},
        {"name": "windsurf", "label": "Windsurf",     "on": detected.get("windsurf", False)},
        {"name": "openclaw", "label": "OpenClaw",     "on": detected.get("openclaw", False)},
        {"name": "hermes",   "label": "Hermes",       "on": detected.get("hermes", False)},
        {"name": "grok",     "label": "Grok Build",   "on": detected.get("grok", False)},
        {"name": "kiro",     "label": "Kiro CLI",     "on": detected.get("kiro", False)},
    ]
    if not any(a["on"] for a in agents):
        agents[0]["on"] = True
    sel = 0

    while True:
        lines = header_lines(2, 3, "AGENTS")
        lines.append(f"  {w('Select agents to install Prismor hooks for:', DIM)}")
        lines.append("")
        for i, ag in enumerate(agents):
            arrow = w("▸ ", CYAN) if i == sel else "  "
            dot   = w("●", GRN) if ag["on"] else w("○", DIM)
            name  = pad(w(ag["label"], BOLD) if i == sel else ag["label"], 18)
            tag   = w("detected", GRN) if detected[ag["name"]] else w("not found", DIM)
            lines.append(f"  {arrow}{dot}  {name} {tag}")
        lines.append("")
        lines.append(control_line([
            ("↑↓", "move"), ("space", "toggle"),
            ("←", "back"), ("enter", "next"),
        ]))
        render(lines)

        key = read_key()
        if key in (UP,):    sel = (sel - 1) % len(agents)
        elif key in (DOWN,):  sel = (sel + 1) % len(agents)
        elif key == SPACE:    agents[sel]["on"] = not agents[sel]["on"]
        elif key in (LEFT, 'b', 'B'): return BACK
        elif key in (ENTER, '\n'):
            chosen = [a["name"] for a in agents if a["on"]]
            return chosen if chosen else ["claude"]
        elif key in ('q','Q','\x03'): cleanup(); sys.exit(0)

# ── Step 3: Hook selection ───────────────────────────────────────────────────

def step_hooks(current=None):
    """Multi-select checklist: every hook with a one-liner description."""
    if current is None:
        current = _default_hooks()
    hooks = {d["id"]: current.get(d["id"], d["default"]) for d in HOOK_DEFS}
    sel = 0
    label_w = max(visible_len(d["label"]) for d in HOOK_DEFS) + 2

    while True:
        tw = term_width()
        lines = header_lines(3, 3, "HOOKS")
        lines.append(f"  {w('Select which hooks to install:', DIM)}")
        lines.append("")
        for i, hd in enumerate(HOOK_DEFS):
            arrow    = w("▸ ", CYAN) if i == sel else "  "
            dot      = w("●", GRN) if hooks[hd["id"]] else w("○", DIM)
            lbl      = pad(w(hd["label"], BOLD) if i == sel else hd["label"], label_w)
            max_desc = max(tw - label_w - 10, 20)
            desc     = w(hd["desc"][:max_desc], DIM)
            lines.append(f"  {arrow}{dot}  {lbl}{desc}")
        lines.append("")
        lines.append(control_line([
            ("↑↓", "move"), ("space", "toggle"),
            ("←", "back"), ("enter", "next"), ("q", "quit"),
        ]))
        render(lines)

        key = read_key()
        if key in (UP,):              sel = (sel - 1) % len(HOOK_DEFS)
        elif key in (DOWN,):          sel = (sel + 1) % len(HOOK_DEFS)
        elif key == SPACE:            hooks[HOOK_DEFS[sel]["id"]] = not hooks[HOOK_DEFS[sel]["id"]]
        elif key in (LEFT, 'b', 'B'): return BACK
        elif key in (ENTER, '\n'):    return dict(hooks)
        elif key in ('q','Q','\x03'): cleanup(); sys.exit(0)

# ── Confirm ──────────────────────────────────────────────────────────────────

def step_confirm(target, mode, rules, agents, hooks=None):
    if hooks is None:
        hooks = _default_hooks()
    home = str(Path.home())
    disp = str(target).replace(home, "~")
    n_on = sum(1 for r in rules if r["on"])
    ags  = ", ".join(agents)

    W = 48  # inner box width

    def bdr(ch_l, ch_fill, ch_r):
        return w(f"  {ch_l}{ch_fill * W}{ch_r}", DIM)
    def row(content=""):
        vl = visible_len(content)
        p = " " * max(0, W - vl - 2)
        return w("  │", DIM) + " " + content + p + " " + w("│", DIM)
    def kv(k, v, vc=WHT):
        return f"{pad(w(k, DIM), 14)}{w(v, vc)}"

    while True:
        lines = header_lines()
        lines.append(bdr("╭", "─", "╮"))
        lines.append(row(w("READY TO INSTALL", BOLD)))
        lines.append(row())
        lines.append(row(kv("Project", disp[:30])))
        lines.append(row(kv("Mode", mode, GRN if mode == "enforce" else YEL)))
        lines.append(row(kv("Rules", f"{n_on}/{len(rules)} enabled")))
        lines.append(row(kv("Agents", ags)))
        n_hooks = sum(1 for d in HOOK_DEFS if hooks.get(d["id"], d["default"]))
        lines.append(row(kv("Hooks", f"{n_hooks}/{len(HOOK_DEFS)} enabled",
                              GRN if n_hooks else DIM)))
        lines.append(row())
        lines.append(bdr("╰", "─", "╯"))
        lines.append("")
        lines.append(control_line([
            ("enter", "install"), ("←", "back"), ("q", "quit"),
        ]))
        render(lines)

        key = read_key()
        if key in (ENTER, '\n'): return True
        elif key in (LEFT, 'b', 'B'): return BACK
        elif key in ('q','Q','\x03'): cleanup(); sys.exit(0)

# ── Install ──────────────────────────────────────────────────────────────────

SPIN = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

def spinner_run(label, fn):
    """Run fn() with a spinner. fn should return (ok, msg)."""
    stop = threading.Event()
    def spin():
        i = 0
        while not stop.is_set():
            f = SPIN[i % len(SPIN)]
            sys.stdout.write(f"\r  {w(f, CYAN)}  {label}   ")
            sys.stdout.flush()
            i += 1
            time.sleep(0.08)
    t = threading.Thread(target=spin, daemon=True)
    t.start()
    try:
        ok, msg = fn()
    except Exception as e:
        ok, msg = False, str(e)[:40]
    stop.set()
    t.join(timeout=0.3)
    icon = w("✓", GRN) if ok else w("✗", RED)
    suffix = f"  {w(msg, DIM)}" if msg else ""
    sys.stdout.write(f"\r  {icon}  {label}{suffix}            \n")
    sys.stdout.flush()

def do_install(target, mode, rules, agents, hooks=None):
    # Switch back to normal buffer for install output
    sys.stdout.write(ALT_OFF)
    sys.stdout.write("\033[H\033[J" + HIDE)
    sys.stdout.flush()
    print(w("  Installing Prismor...\n", BOLD, CYAN))

    if hooks is None:
        hooks = _default_hooks()
    target = Path(target).resolve()
    cli = PRISMOR_DIR / "immunity"

    # 0. Register workspace globally
    try:
        sys.path.insert(0, str(PRISMOR_DIR))
        from prismor.runtime.store import register_workspace
        register_workspace(target)
    except Exception:
        pass

    # 1. Update prismor
    def update():
        if not PRISMOR_DIR.exists():
            return False, "not found"
        r = subprocess.run(["git","-C",str(PRISMOR_DIR),"pull","--quiet"],
                           capture_output=True, timeout=15)
        return r.returncode == 0, "up to date" if r.returncode == 0 else "offline"
    spinner_run("Updating Prismor", update)

    # 2. Policy overrides
    disabled = [r["id"] for r in rules if not r["on"]]
    if disabled:
        def write_policy():
            d = target / ".prismor"
            d.mkdir(exist_ok=True)
            txt = 'version: "1.0"\nrules:\n'
            for rid in disabled:
                txt += f"  - id: {rid}\n    enabled: false\n"
            (d / "policy.yaml").write_text(txt)
            return True, f"{len(disabled)} disabled"
        spinner_run("Writing policy overrides", write_policy)

    # 3. Prismor runtime hooks
    if hooks.get("runtime", True):
        for agent in agents:
            def install(a=agent):
                if not cli.exists():
                    return False, "prismor entry point not found"
                r = subprocess.run([sys.executable, str(cli), "install-hooks",
                                    "--agent", a, "--workspace", str(target),
                                    "--scope", "project", "--mode", mode],
                                   capture_output=True, timeout=30)
                return r.returncode == 0, ""
            spinner_run(f"Installing {agent} hooks", install)

    # 3b. Cloaking hooks (Claude Code only)
    if hooks.get("cloak-core", True) and "claude" in agents:
        def install_cloak():
            if not cli.exists():
                return False, "prismor entry point not found"
            if not shutil.which("jq"):
                return False, "jq not found (brew install jq)"
            cmd = [sys.executable, str(cli), "cloak", "install",
                   "--workspace", str(target), "--scope", "project"]
            if not hooks.get("cloak-guard", True):
                cmd.append("--no-secret-guard")
            if not hooks.get("cloak-prompt", True):
                cmd.append("--no-userprompt-guard")
            if hooks.get("cloak-sweep", False):
                cmd.append("--sweep-on-stop")
            r = subprocess.run(cmd, capture_output=True, timeout=30)
            return r.returncode == 0, "enabled" if r.returncode == 0 else r.stderr.decode()[:40]
        spinner_run("Installing cloaking hooks", install_cloak)

    # 4. CLAUDE.md
    def update_claude():
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
    spinner_run("Updating CLAUDE.md", update_claude)

    # 4b. Install the immunity-agent Claude skill (Claude Code only).
    if "claude" in agents:
        def install_skill():
            skill_md = PRISMOR_DIR / "SKILL.md"
            docs_src = PRISMOR_DIR / "docs"
            if not skill_md.exists():
                return True, "skipped (skill not found)"
            dest = target / ".claude" / "skills" / "immunity-agent"
            if (dest / "SKILL.md").exists():
                return True, "already present"
            try:
                dest.mkdir(parents=True, exist_ok=True)
                shutil.copy2(skill_md, dest / "SKILL.md")
                if docs_src.is_dir():
                    docs_dest = dest / "docs"
                    docs_dest.mkdir(exist_ok=True)
                    for md in docs_src.glob("*.md"):
                        shutil.copy2(md, docs_dest / md.name)
                return True, "installed"
            except OSError as e:
                return False, str(e)[:40]
        spinner_run("Installing immunity-agent skill", install_skill)

    # 5. Verify feed
    def verify():
        vsh = PRISMOR_DIR / "scripts" / "verify_feed.sh"
        fj  = PRISMOR_DIR / "advisories" / "immunity-feed.json"
        pk  = PRISMOR_DIR / "keys" / "public.pub"
        if not all(p.exists() for p in (vsh, fj, pk)):
            return True, "skipped"
        r = subprocess.run(["bash", str(vsh), str(fj), str(pk)],
                           capture_output=True, timeout=15)
        return r.returncode == 0, "verified" if r.returncode == 0 else "failed"
    spinner_run("Verifying feed signature", verify)

    # 6. Add prismor to PATH
    def add_to_path():
        wrapper = PRISMOR_DIR / "scripts" / "prismor"
        if not wrapper.exists():
            return False, "wrapper script not found"
        # Symlink into /usr/local/bin if writable, else add to PATH in rc
        local_bin = Path("/usr/local/bin")
        link = local_bin / "prismor"
        if local_bin.exists() and os.access(str(local_bin), os.W_OK):
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(wrapper)
            return True, "linked to /usr/local/bin/prismor"
        # Fallback: add scripts dir to PATH in shell rc
        export_line = f'export PATH="{PRISMOR_DIR}/scripts:$PATH"'
        shell = os.environ.get("SHELL", "/bin/zsh")
        rc = Path.home() / (".zshrc" if "zsh" in shell else ".bashrc" if "bash" in shell else ".profile")
        content = rc.read_text() if rc.exists() else ""
        # Clean up legacy `prismor` alias if present (pre-unification leftover)
        if "alias prismor=" in content:
            lines = content.splitlines(keepends=True)
            lines = [l for l in lines if "alias prismor=" not in l]
            content = "".join(lines)
            rc.write_text(content)
        if str(PRISMOR_DIR / "scripts") in content:
            return True, "already in " + rc.name
        rc.write_text(content.rstrip() + f"\n\n# Prismor\n{export_line}\n")
        return True, f"PATH added to {rc.name}"
    spinner_run("Adding prismor command", add_to_path)

    # Done
    home = str(Path.home())
    print()
    print(w("  ╭───────────────────────────────────────────╮", DIM))
    print(w("  │", DIM) + w("  Prismor installed successfully!    ", GRN, BOLD) + w("│", DIM))
    print(w("  ╰───────────────────────────────────────────╯", DIM))
    print()
    def info(k, v):
        print(f"  {w(k + ':', GRN)}  {w(v, DIM)}")
    n_hooks = sum(1 for d in HOOK_DEFS if hooks.get(d["id"], d["default"]))
    hooks_off = [d["label"] for d in HOOK_DEFS if not hooks.get(d["id"], d["default"])]
    off_note = f"  — off by choice: {', '.join(hooks_off)}" if hooks_off else ""
    info("Hooks",      f"{n_hooks}/{len(HOOK_DEFS)} layers enabled  (mode: {mode}){off_note}")
    if "claude" in agents:
        info("Skill",  str(target / ".claude" / "skills" / "immunity-agent").replace(home, "~"))
    info("Docs",       "https://github.com/PrismorSec/prismor")
    info("Feed",       str(PRISMOR_DIR / "advisories/immunity-feed.json").replace(home, "~"))
    info("Config",     str(target / "CLAUDE.md").replace(home, "~"))
    info("Command",    "prismor (restart shell if not found)")
    print()
    print(w("  Quick commands:", GRN))
    print(f"    prismor status                      {w('this workspace health check', DIM)}")
    print(f"    prismor status --all                {w('overview across all workspaces', DIM)}")
    print(f"    prismor sessions --findings-only     {w('all flagged sessions by risk', DIM)}")
    print(f"    prismor check \"rm -rf /\"             {w('pre-check a command', DIM)}")
    print()
    sys.stdout.write(SHOW)
    sys.stdout.flush()

# ── Non-interactive ──────────────────────────────────────────────────────────

def run_non_interactive(target):
    mode  = os.environ.get("PRISMOR_MODE", "observe")
    cloak = os.environ.get("PRISMOR_CLOAK", "").lower() in {"1", "true", "yes", "on"}
    rules = load_rules()
    target = Path(target).resolve()
    det    = detect_agents(target)
    agents = [n for n, ok in det.items() if ok] or ["claude"]
    hooks  = _default_hooks()
    if not cloak:
        hooks["cloak-core"]   = False
        hooks["cloak-guard"]  = False
        hooks["cloak-prompt"] = False
        hooks["cloak-sweep"]  = False
    cloak_tag = ", cloak=yes" if cloak else ""
    print(f"[prismor] Non-interactive (mode={mode}, agents={','.join(agents)}{cloak_tag})")
    do_install(target, mode, rules, agents, hooks=hooks)

# ── Wizard ───────────────────────────────────────────────────────────────────

def run_wizard(target):
    # Enter alternate screen buffer for a clean canvas
    sys.stdout.write(ALT_ON + HIDE)
    sys.stdout.flush()
    raw_on()

    # Detection rules ship enabled by default — there is no per-rule toggle
    # step. Rules are loaded only for the confirm-screen count and do_install.
    rules = load_rules()
    mode = "enforce"
    agents = None
    hooks = _default_hooks()
    step = 1

    try:
        while True:
            if step == 1:
                result = step_mode(mode)
                mode = result
                step = 2
            elif step == 2:
                result = step_agents(target)
                if result is BACK:
                    step = 1; continue
                agents = result
                step = 3
            elif step == 3:
                result = step_hooks(hooks)
                if result is BACK:
                    step = 2; continue
                hooks = result
                step = 4
            elif step == 4:
                result = step_confirm(target, mode, rules, agents, hooks=hooks)
                if result is BACK:
                    step = 3; continue
                break  # confirmed → install
    except Exception:
        rules = load_rules()
        mode = "enforce"
        agents = ["claude"]
        hooks = _default_hooks()

    raw_off()
    do_install(target, mode, rules, agents, hooks=hooks)

# ── Entry ────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    non_interactive = "--non-interactive" in args
    args = [a for a in args if not a.startswith("--")]
    target = Path(args[0]).resolve() if args else Path.cwd()

    if not target.exists():
        sys.stderr.write(f"[prismor] Directory not found: {target}\n")
        sys.exit(1)

    if non_interactive or not sys.stdin.isatty():
        run_non_interactive(target)
    else:
        run_wizard(target)

if __name__ == "__main__":
    main()
