#!/bin/bash
# Lethal-trifecta crossover — REAL hook path proof.
#
# Drives Prismor's actual `hook-dispatch` CLI (the exact command Claude Code runs
# on PreToolUse) with two crafted tool calls in one session: a red read_email,
# then a blue send_email. The second is a red x blue crossover and Prismor
# aborts it with exit code 2 and a block message on stderr — the same terminal
# block the agent would receive, preventing the tool from ever executing.
#
# Usage:  bash examples/lethal-trifecta/hook_demo.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"     # prismor package root (has the `prismor/` namespace dir)
export PYTHONPATH="$REPO_ROOT"

WS="$(mktemp -d -t trifecta-hook)"
mkdir -p "$WS/.prismor"
cat > "$WS/.prismor/policy.yaml" <<'YAML'
version: "1.0"
settings:
  tool_categories:
    enabled: true
    mode: enforce            # terminal, non-overridable crossover block
    map:
      mcp__Gmail__read_email: red
      mcp__Gmail__send_email: blue
YAML

SID="hookdemo-$$-$RANDOM"
CLI=(python3 -m prismor.runtime.immunity_cli hook-dispatch --agent claude --workspace "$WS" --mode enforce)

run() {  # $1 = tool_name, $2 = tool_input json
  printf '{"hook_event_name":"PreToolUse","tool_name":"%s","tool_input":%s,"session_id":"%s","cwd":"%s"}' \
    "$1" "$2" "$SID" "$WS" | "${CLI[@]}"
  echo "  -> exit=$?"
}

echo "=== Real hook path: red read_email, then blue send_email (same session) ==="
echo
echo "[1] PreToolUse mcp__Gmail__read_email (RED)  — expect ALLOW (exit 0):"
run "mcp__Gmail__read_email" '{"query":"is:unread"}'
echo
echo "[2] PreToolUse mcp__Gmail__send_email (BLUE) — expect BLOCK (exit 2):"
run "mcp__Gmail__send_email" '{"to":"x@example.com","subject":"Invoices"}'
echo
echo "The blue call was terminated before execution — the exfil never runs."
rm -rf "$WS"
