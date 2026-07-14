#!/bin/bash
# Lethal-trifecta red/blue crossover — live enforcement demo.
# Runs crafted red/blue tool-call sequences through the real Prismor decision
# path and prints ALLOW / BLOCK per call.
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"   # the prismor package root (contains the `prismor/` namespace dir)
PYTHONPATH="$REPO_ROOT" python3 "$HERE/demo.py"
