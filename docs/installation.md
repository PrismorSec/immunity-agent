# Installation

Full detail behind the three methods in the [README Quick Start](../README.md#quick-start), plus the less-common paths.

## Curl

```bash
curl -sSL https://prismor.dev/install | sh
```

Detects your environment and uses the right install method automatically.

## Skill (zero-interrupt setup)

Point your agent at [`SKILL.md`](../SKILL.md). It is a standing instruction file: the agent reads it at session start, checks whether Prismor is installed, and follows the decision tree throughout the session without pausing your workflow.

For Claude Code, add to your `CLAUDE.md`:

```markdown
Read `SKILL.md` and follow its instructions for runtime security.
```

Or via raw URL (works in any agent config file: CLAUDE.md, AGENTS.md, .cursorrules, .windsurfrules):

```markdown
Read `https://raw.githubusercontent.com/PrismorSec/prismor/main/SKILL.md` and follow its instructions.
```

See [`SKILL.md`](../SKILL.md) for the full decision tree and hard rules.

## Pip

```bash
pip install prismor
prismor setup          # interactive 4-step onboarding wizard
```

`prismor setup` lets you pick enforcement mode, toggle detection rules, select agents, and optionally enable secret cloaking. Pass `--non-interactive` to skip the TUI.

## Git clone + wizard

```bash
pip3 install pyyaml                          # on Debian/Ubuntu use: sudo apt install python3-yaml
git clone https://github.com/PrismorSec/prismor.git ~/.prismor
PRISMOR_MODE=enforce PRISMOR_CLOAK=1 bash ~/.prismor/scripts/init.sh .
```

If you are testing from a source checkout on a machine that already has a
different `prismor` install, use the repo shim for health checks:

```bash
python3 ~/.prismor/bin/prismor --version
python3 ~/.prismor/bin/prismor status
```

That path forces imports to resolve to the checked-out runtime instead of a
stale package earlier on `sys.path`.

> On externally-managed Pythons (PEP 668 — Ubuntu 23.04+, Homebrew) `pip3 install` refuses to run; install PyYAML from your system package manager instead (`sudo apt install python3-yaml`, `brew install pyyaml`, …). `init.sh` will tell you if it's missing.

This installs enforce-mode Prismor hooks and the Cloak prevention layer. To register a secret, run `prismor cloak add stripe_key` and enter the value when prompted. To import an entire dotenv file at once, run `prismor cloak add --env-file .env`. Claude/Hermes can auto-decloak placeholders at the tool boundary. Codex hooks are block-only, so run placeholder commands through `prismor cloak run -- <command>`.

Prefer the interactive wizard? Drop the env vars:

```bash
bash ~/.prismor/scripts/init.sh .
```
