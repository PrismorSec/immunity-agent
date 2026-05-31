#!/bin/bash
set -e

# Prismor Init — Add Prismor security to any project
# Usage: curl -fsSL https://raw.githubusercontent.com/PrismorSec/immunity-agent/main/scripts/init.sh | bash
#    or: bash /path/to/immunity-agent/scripts/init.sh [TARGET_DIR]
#
# Environment:
#   PRISMOR_MODE      observe | enforce   (default: observe)
#   PRISMOR_CLOAK     1 | true | yes      (default: off — opts into the secret
#                                          cloaking prevention layer)

PRISMOR_REPO="https://github.com/PrismorSec/immunity-agent.git"
PRISMOR_DIR="${PRISMOR_HOME:-$HOME/.prismor}"
TARGET_DIR="${1:-.}"
MODE="${PRISMOR_MODE:-observe}"
CLOAK_RAW="$(printf '%s' "${PRISMOR_CLOAK:-}" | tr '[:upper:]' '[:lower:]')"
case "$CLOAK_RAW" in
    1|true|yes|on) CLOAK=1 ;;
    *)             CLOAK=0 ;;
esac

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[prismor]${NC} $1"; }
ok()    { echo -e "${GREEN}[prismor]${NC} $1"; }
warn()  { echo -e "${YELLOW}[prismor]${NC} $1"; }
err()   { echo -e "${RED}[prismor]${NC} $1" >&2; }

# ── Interactive TUI wizard (when stdin is a real TTY) ────────────────────
SETUP_PY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/setup.py"
if [ -t 0 ] && [ -f "$SETUP_PY" ] && command -v python3 &>/dev/null; then
    exec python3 "$SETUP_PY" "$TARGET_DIR"
fi

# ── Preflight: check critical dependencies ──────────────────────────────
if command -v python3 &>/dev/null; then
    if ! python3 -c "import yaml" 2>/dev/null; then
        warn "PyYAML is not installed. It is required for the policy engine."
        warn "Without it, Warden cannot load any detection rules."
        echo ""
        info "Install with one of:"
        info "  pip3 install pyyaml"
        info "  apt-get install python3-yaml"
        info "  brew install pyyaml"
        echo ""
        err "Aborting installation. Install PyYAML first, then re-run."
        exit 1
    fi
else
    err "python3 is required but not found in PATH."
    exit 1
fi

# ── Non-interactive / piped fallback ─────────────────────────────────────
SETUP_PY_FALLBACK="${PRISMOR_DIR}/scripts/setup.py"
if [ -f "$SETUP_PY_FALLBACK" ] && command -v python3 &>/dev/null; then
    exec python3 "$SETUP_PY_FALLBACK" "$TARGET_DIR" --non-interactive
fi

# ── Step 1: Ensure Prismor is cloned locally ────────────────────────────
if [ -d "$PRISMOR_DIR" ] && [ -f "$PRISMOR_DIR/immunity" ]; then
    info "Prismor found at $PRISMOR_DIR"
    info "Pulling latest..."
    git -C "$PRISMOR_DIR" pull --quiet 2>/dev/null || warn "Could not pull (offline?). Using existing version."
else
    info "Cloning Prismor to $PRISMOR_DIR..."
    git clone --quiet "$PRISMOR_REPO" "$PRISMOR_DIR"
    ok "Cloned."
fi

# ── Step 2: Detect IDE/agent ─────────────────────────────────────────────
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
AGENTS_FOUND=()

if command -v claude &>/dev/null || [ -d "$TARGET_DIR/.claude" ]; then
    AGENTS_FOUND+=("claude")
fi
if [ -d "$TARGET_DIR/.cursor" ] || [ -d "$HOME/.cursor" ]; then
    AGENTS_FOUND+=("cursor")
fi
if [ -d "$TARGET_DIR/.windsurf" ] || [ -d "$HOME/.codeium" ]; then
    AGENTS_FOUND+=("windsurf")
fi

if [ ${#AGENTS_FOUND[@]} -eq 0 ]; then
    AGENTS_FOUND=("claude")
    info "No IDE detected, defaulting to Claude Code."
fi

info "Detected agents: ${AGENTS_FOUND[*]}"

# ── Step 3: Generate CLAUDE.md (or append to existing) ──────────────────
CLAUDE_MD="$TARGET_DIR/CLAUDE.md"
PRISMOR_BLOCK="## Security (Prismor)

At the start of every session, read \`https://raw.githubusercontent.com/PrismorSec/security-playbook/main/security.md\` and follow its instructions.

This loads behavioral guardrails, secure coding rules (OWASP Top 10), and LLM security rules (OWASP LLM Top 10).

For more info: https://github.com/PrismorSec/prismor"

if [ -f "$CLAUDE_MD" ]; then
    if grep -q "Prismor" "$CLAUDE_MD" 2>/dev/null; then
        ok "CLAUDE.md already has Prismor section. Skipping."
    else
        info "Appending Prismor section to existing CLAUDE.md..."
        echo "" >> "$CLAUDE_MD"
        echo "$PRISMOR_BLOCK" >> "$CLAUDE_MD"
        ok "Appended to CLAUDE.md"
    fi
else
    info "Creating CLAUDE.md..."
    echo "$PRISMOR_BLOCK" > "$CLAUDE_MD"
    ok "Created CLAUDE.md"
fi

# ── Step 4: Install Warden hooks ────────────────────────────────────────
info "Installing Warden hooks (mode: $MODE)..."
HOOKS_OK=0
for agent in "${AGENTS_FOUND[@]}"; do
    # Capture stderr so we can surface the real cause on failure instead of
    # silently swallowing it (a failed install must never look like success).
    if hook_err="$(python3 "$PRISMOR_DIR/immunity" install-hooks \
        --agent "$agent" \
        --workspace "$TARGET_DIR" \
        --scope project \
        --mode "$MODE" 2>&1)"; then
        ok "Installed $agent hooks"
        HOOKS_OK=$((HOOKS_OK + 1))
    else
        warn "Could not install $agent hooks"
        printf '%s\n' "$hook_err" | tail -3 | sed 's/^/      /' >&2
    fi
done

# ── Step 4b: Cloaking hooks (opt-in) ────────────────────────────────────
if [ "$CLOAK" = "1" ]; then
    case " ${AGENTS_FOUND[*]} " in
        *" claude "*)
            if ! command -v jq >/dev/null 2>&1; then
                warn "PRISMOR_CLOAK=1 set but jq is missing — install with 'brew install jq' and re-run"
            else
                info "Installing cloaking hooks (secret prevention layer)..."
                python3 "$PRISMOR_DIR/immunity" cloak install \
                    --workspace "$TARGET_DIR" \
                    --scope project >/dev/null 2>&1 && \
                    ok "Cloaking hooks installed. Register secrets with: immunity cloak add <name>" || \
                    warn "Could not install cloaking hooks"
            fi
            ;;
        *)
            warn "PRISMOR_CLOAK=1 set but no Claude Code agent detected — cloaking supports Claude Code only"
            ;;
    esac
fi

# ── Step 4c: Put `immunity` on PATH ─────────────────────────────────────
# The git-clone path (this script) otherwise leaves no `immunity` command,
# so the cloak/status commands the README points at would be "not found".
WRAPPER="$PRISMOR_DIR/scripts/immunity"
if [ -f "$WRAPPER" ]; then
    if [ -w /usr/local/bin ]; then
        ln -sf "$WRAPPER" /usr/local/bin/immunity \
            && ok "Linked 'immunity' to /usr/local/bin" \
            || warn "Could not link 'immunity' to /usr/local/bin"
    else
        case "${SHELL:-}" in
            *zsh)  RC="$HOME/.zshrc" ;;
            *bash) RC="$HOME/.bashrc" ;;
            *)     RC="$HOME/.profile" ;;
        esac
        if grep -qF "$PRISMOR_DIR/scripts" "$RC" 2>/dev/null; then
            ok "'immunity' already on PATH via $(basename "$RC")"
        else
            printf '\n# Prismor immunity\nexport PATH="%s/scripts:$PATH"\n' "$PRISMOR_DIR" >> "$RC"
            ok "Added 'immunity' to PATH in $(basename "$RC") — run: source $RC"
        fi
    fi
else
    warn "immunity wrapper not found at $WRAPPER — CLI not added to PATH"
fi

# ── Step 5: Verify feed ─────────────────────────────────────────────────
if [ -f "$PRISMOR_DIR/keys/public.pub" ]; then
    if bash "$PRISMOR_DIR/scripts/verify_feed.sh" "$PRISMOR_DIR/advisories/immunity-feed.json" "$PRISMOR_DIR/keys/public.pub" >/dev/null 2>&1; then
        ok "Feed signature verified"
    else
        warn "Feed signature verification failed"
    fi
fi

# ── Done ─────────────────────────────────────────────────────────────────
echo ""
if [ "$HOOKS_OK" -eq 0 ]; then
    err "Initialization FAILED — no hooks were installed for any agent."
    err "Warden is NOT monitoring $TARGET_DIR. See the errors above for the cause."
    err "A CLAUDE.md was written, but without hooks nothing is enforced."
    exit 1
fi

ok "Prismor initialized for: $TARGET_DIR"
echo ""
echo -e "  ${GREEN}Warden:${NC}  hooks installed for $HOOKS_OK agent(s) (mode: $MODE)"
echo -e "  ${GREEN}Config:${NC}  $CLAUDE_MD"
echo ""
if [ "$MODE" != "enforce" ]; then
    echo -e "  To switch to enforce mode:  ${YELLOW}PRISMOR_MODE=enforce bash $PRISMOR_DIR/scripts/init.sh $TARGET_DIR${NC}"
fi
if [ "$CLOAK" != "1" ]; then
    echo -e "  To enable secret cloaking: ${YELLOW}PRISMOR_CLOAK=1 bash $PRISMOR_DIR/scripts/init.sh $TARGET_DIR${NC}"
fi
echo -e "  To update the feed:         ${YELLOW}git -C $PRISMOR_DIR pull${NC}"

# ── Optional: Analyze current session state ────────────────────────────────
# Only prompt when attached to a real terminal. In piped / non-interactive runs
# (curl | bash, CI) `read` hits EOF and, under `set -e`, would abort the script
# with a non-zero status *after* a fully successful install.
if [ -t 0 ]; then
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    read -p "$(echo -e ${YELLOW}'Check current session for findings? (y/n):'${NC}) " -n 1 -r || true
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        info "Analyzing your current session..."
        python3 "$PRISMOR_DIR/immunity" analyze 2>/dev/null || \
            warn "Session analysis failed"
    fi
    echo ""
fi
