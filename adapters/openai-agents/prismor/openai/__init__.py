"""Prismor adapter for the OpenAI Agents SDK.

Preferred import path::

    from prismor.openai import guard_agent, use_subject

Aliases the ``prismor_openai`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

# This shim must only ever be imported as ``prismor.openai``. If the ``prismor``
# package directory leaks onto sys.path, Python can resolve it as a *top-level*
# ``openai`` module; blindly aliasing sys.modules would then replace the real
# OpenAI SDK with this adapter and break every downstream ``import openai``.
# Fail loudly instead. (The sys.path leak was fixed in PrismorSec/prismor#173 —
# this guard is defense in depth so the two can never combine again.)
if __name__ != "prismor.openai":
    raise ImportError(
        f"prismor.openai was imported as {__name__!r}, not 'prismor.openai' — the "
        "'prismor' package directory is on sys.path and is shadowing the real "
        "'openai' SDK. Remove it from sys.path (see PrismorSec/prismor#173)."
    )

import prismor_openai as _impl

_sys.modules[__name__] = _impl
