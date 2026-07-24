"""Prismor adapter for Semantic Kernel.

Preferred import path::

    from prismor.semantic_kernel import make_filter

Aliases the ``prismor_semantic_kernel`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

# See PrismorSec/prismor#173 -- mirrors the other adapters' shims' defense
# against the 'prismor' package directory leaking onto sys.path and
# shadowing a real top-level 'semantic_kernel' import.
if __name__ != "prismor.semantic_kernel":
    raise ImportError(
        f"prismor.semantic_kernel was imported as {__name__!r}, not "
        "'prismor.semantic_kernel' — the 'prismor' package directory is on "
        "sys.path and may be shadowing another package. Remove it from "
        "sys.path (see PrismorSec/prismor#173)."
    )

import prismor_semantic_kernel as _impl

_sys.modules[__name__] = _impl
