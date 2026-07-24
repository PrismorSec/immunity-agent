"""Prismor adapter for Google ADK.

Preferred import path::

    from prismor.google_adk import make_before_tool_callback

Aliases the ``prismor_google_adk`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

# See PrismorSec/prismor#173 -- mirrors the other adapters' shims' defense
# against the 'prismor' package directory leaking onto sys.path and
# shadowing a real top-level import.
if __name__ != "prismor.google_adk":
    raise ImportError(
        f"prismor.google_adk was imported as {__name__!r}, not "
        "'prismor.google_adk' — the 'prismor' package directory is on "
        "sys.path and may be shadowing another package. Remove it from "
        "sys.path (see PrismorSec/prismor#173)."
    )

import prismor_google_adk as _impl

_sys.modules[__name__] = _impl
