"""Prismor adapter for Agno.

Preferred import path::

    from prismor.agno import make_tool_hook, prismor_tool_hook

Aliases the ``prismor_agno`` implementation module so both import paths
resolve to the same module object.
"""
import sys as _sys

# See PrismorSec/prismor#173 -- mirrors the other adapters' shims' defense
# against the 'prismor' package directory leaking onto sys.path and
# shadowing a real top-level 'agno' import.
if __name__ != "prismor.agno":
    raise ImportError(
        f"prismor.agno was imported as {__name__!r}, not 'prismor.agno' — the "
        "'prismor' package directory is on sys.path and may be shadowing another "
        "package. Remove it from sys.path (see PrismorSec/prismor#173)."
    )

import prismor_agno as _impl

_sys.modules[__name__] = _impl
