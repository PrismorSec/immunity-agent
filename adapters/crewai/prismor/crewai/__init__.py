"""Prismor adapter for CrewAI.

Preferred import path::

    from prismor.crewai import guard_tools, use_subject

Aliases the ``prismor_crewai`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

# This shim must only ever be imported as ``prismor.crewai``. If the ``prismor``
# package directory leaks onto sys.path, Python can resolve it as a *top-level*
# ``crewai`` module; blindly aliasing sys.modules would then replace the real
# CrewAI SDK with this adapter and break every downstream ``import crewai``.
# Fail loudly instead. (The sys.path leak was fixed in PrismorSec/prismor#173 —
# this guard is defense in depth so the two can never combine again.)
if __name__ != "prismor.crewai":
    raise ImportError(
        f"prismor.crewai was imported as {__name__!r}, not 'prismor.crewai' — the "
        "'prismor' package directory is on sys.path and is shadowing the real "
        "'crewai' SDK. Remove it from sys.path (see PrismorSec/prismor#173)."
    )

import prismor_crewai as _impl

_sys.modules[__name__] = _impl
