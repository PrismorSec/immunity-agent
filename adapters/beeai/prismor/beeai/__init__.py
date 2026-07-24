"""Prismor adapter for BeeAI Framework.

Preferred import path::

    from prismor.beeai import guard_tool, guard_tools

Aliases the ``prismor_beeai`` implementation module so both import paths
resolve to the same module object.
"""
import sys as _sys

# See PrismorSec/prismor#173 -- mirrors the other adapters' shims' defense
# against the 'prismor' package directory leaking onto sys.path and
# shadowing a real top-level 'beeai' import.
if __name__ != "prismor.beeai":
    raise ImportError(
        f"prismor.beeai was imported as {__name__!r}, not 'prismor.beeai' — the "
        "'prismor' package directory is on sys.path and may be shadowing another "
        "package. Remove it from sys.path (see PrismorSec/prismor#173)."
    )

import prismor_beeai as _impl

_sys.modules[__name__] = _impl
