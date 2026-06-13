#!/usr/bin/env python3
"""Reject oversized files before they enter git history.

A security product shouldn't bloat its own repo: a single demo GIF that was
replaced four times left ~58 MiB of dead weight in this repo's pack and made
every clone slow (audit §1). This guard stops new large blobs at the door so it
can't recur — there is no cheap way to remove a big blob once it's in history.

Two modes, same limit:
  * pre-commit  : ``check_blob_size.py``        -> checks staged files
  * CI / manual : ``check_blob_size.py FILE...`` -> checks the given files

Exit 0 if everything is within the limit, 1 (with a report) otherwise.
Override the limit with ``--max-bytes`` or ``$MAX_BLOB_BYTES`` (default 1 MiB).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

DEFAULT_MAX_BYTES = 1024 * 1024  # 1 MiB


def staged_files() -> list[str]:
    """Files staged for commit (added/copied/modified/renamed), for pre-commit."""
    out = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True, text=True, check=True,
    ).stdout
    return [line for line in out.splitlines() if line.strip()]


def human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} GiB"


def main() -> int:
    ap = argparse.ArgumentParser(description="Fail if any file exceeds the size limit.")
    ap.add_argument("files", nargs="*", help="Files to check (default: staged files).")
    ap.add_argument(
        "--max-bytes", type=int,
        default=int(os.environ.get("MAX_BLOB_BYTES", DEFAULT_MAX_BYTES)),
        help="Maximum allowed file size in bytes (default: 1 MiB).",
    )
    args = ap.parse_args()

    files = args.files or staged_files()
    offenders = []
    for path in files:
        if not os.path.isfile(path):  # deleted/renamed-away paths
            continue
        size = os.path.getsize(path)
        if size > args.max_bytes:
            offenders.append((path, size))

    if not offenders:
        return 0

    limit = human(args.max_bytes)
    print(f"\n✗ {len(offenders)} file(s) exceed the {limit} blob limit:\n", file=sys.stderr)
    for path, size in sorted(offenders, key=lambda x: -x[1]):
        print(f"    {human(size):>10}  {path}", file=sys.stderr)
    print(
        "\nLarge binaries bloat every clone forever. Instead:\n"
        "  • host demo media as GitHub release assets / a CDN and hot-link it, or\n"
        "  • track it with Git LFS, or\n"
        f"  • if it's genuinely needed in-tree, raise the limit via --max-bytes / $MAX_BLOB_BYTES.\n",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
