#!/usr/bin/env bash
# Builds a portable, dependency-bundled distribution of the prismor CLI
# (immunity-agent runtime + shim) that runs on any macOS/Linux box with a
# system python3 — no `pip install` required.
#
# Packages prismor as a zipapp (a single executable .pyz with its pure-Python
# dependencies vendored in), wraps it with a thin `prismor`/`immunity`
# launcher script, and tars/zips the result. Used by .github/workflows/release.yml;
# also runnable locally: `scripts/build_portable.sh [output-dir]`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT/dist-portable}"
VERSION="$(sed -n 's/^__version__ = "\(.*\)".*/\1/p' "$ROOT/prismor/runtime/__init__.py")"

if [ -z "$VERSION" ]; then
  echo "error: could not read __version__ from prismor/runtime/__init__.py" >&2
  exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

VENDOR="$STAGE/vendor"
mkdir -p "$VENDOR"

# Vendor the runtime's only hard dependency + the package itself into a
# flat tree that `python -m zipapp` can fold into one .pyz.
python3 -m pip install --no-compile --target "$VENDOR" "$ROOT" >/dev/null

BUNDLE_NAME="prismor-${VERSION}-portable"
BUNDLE_DIR="$STAGE/$BUNDLE_NAME"
mkdir -p "$BUNDLE_DIR"

python3 -m zipapp "$VENDOR" \
  --output "$BUNDLE_DIR/prismor.pyz" \
  --main "prismor.runtime.immunity_cli:main" \
  --compress

cat > "$BUNDLE_DIR/prismor" <<'LAUNCHER'
#!/usr/bin/env bash
# Portable prismor launcher — runs the bundled prismor.pyz with whatever
# python3 is on PATH. No pip install, no virtualenv.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/prismor.pyz" "$@"
LAUNCHER
chmod +x "$BUNDLE_DIR/prismor"
cp "$BUNDLE_DIR/prismor" "$BUNDLE_DIR/immunity"

cat > "$BUNDLE_DIR/README.txt" <<EOF
prismor ${VERSION} — portable bundle

Requires: python3 (>=3.8) on PATH. No pip install needed.

Usage:
  ./prismor --help
  ./prismor init

Add this directory to PATH to use 'prismor'/'immunity' from anywhere.
EOF

mkdir -p "$OUT_DIR"
tar -czf "$OUT_DIR/${BUNDLE_NAME}.tar.gz" -C "$STAGE" "$BUNDLE_NAME"
(cd "$STAGE" && zip -qr "$OUT_DIR/${BUNDLE_NAME}.zip" "$BUNDLE_NAME")

echo "Built portable artifacts in $OUT_DIR:"
ls -la "$OUT_DIR"
