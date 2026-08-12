#!/usr/bin/env python3
"""Asserts tag / CHANGELOG.md / __version__ agree before a release publishes.

release-please writes the version to prismor/runtime/__init__.py and adds a
matching CHANGELOG.md entry as part of the same commit that gets tagged
`vX.Y.Z`. This script re-checks that invariant in the publish job (release.yml)
so a manual tag push, a hand-edited CHANGELOG, or a release-please misfire
can't slip an inconsistent release out the door.

Usage: scripts/validate_release.py <tag>   # e.g. v1.41.0
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read_version() -> str:
    text = (ROOT / "prismor/runtime/__init__.py").read_text()
    match = re.search(r'^__version__ = "([^"]+)"', text, re.MULTILINE)
    if not match:
        sys.exit("error: could not find __version__ in prismor/runtime/__init__.py")
    return match.group(1)


def changelog_has_entry(version: str) -> bool:
    text = (ROOT / "CHANGELOG.md").read_text()
    return re.search(rf"^## \[{re.escape(version)}\]", text, re.MULTILINE) is not None


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <tag>")

    tag = sys.argv[1]
    if not tag.startswith("v"):
        sys.exit(f"error: tag '{tag}' does not start with 'v'")
    tag_version = tag[1:]

    init_version = read_version()
    if tag_version != init_version:
        sys.exit(
            f"error: tag {tag} does not match __version__ "
            f"'{init_version}' in prismor/runtime/__init__.py"
        )

    if not changelog_has_entry(init_version):
        sys.exit(
            f"error: CHANGELOG.md has no '## [{init_version}]' entry "
            f"matching tag {tag}"
        )

    print(f"OK: tag {tag} matches __version__ and has a CHANGELOG.md entry")


if __name__ == "__main__":
    main()
