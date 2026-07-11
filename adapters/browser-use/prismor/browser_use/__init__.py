"""Prismor adapter for browser-use.

Preferred import path::

    from prismor.browser_use import guard_controller, use_subject

Aliases the ``prismor_browser_use`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

# This shim must only ever be imported as ``prismor.browser_use``. If the
# ``prismor`` package directory leaks onto sys.path, Python can resolve it as a
# *top-level* ``browser_use`` module; blindly aliasing sys.modules would then
# replace the real browser-use package with this adapter and break every
# downstream ``import browser_use``. Fail loudly instead. (The sys.path leak was
# fixed in PrismorSec/prismor#173 — this guard is defense in depth.)
if __name__ != "prismor.browser_use":
    raise ImportError(
        f"prismor.browser_use was imported as {__name__!r}, not 'prismor.browser_use' "
        "— the 'prismor' package directory is on sys.path and is shadowing the real "
        "'browser_use' package. Remove it from sys.path (see PrismorSec/prismor#173)."
    )

import prismor_browser_use as _impl

_sys.modules[__name__] = _impl
