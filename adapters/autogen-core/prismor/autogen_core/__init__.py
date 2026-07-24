"""Prismor adapter for AutoGen Core.

Preferred import path::

    from prismor.autogen_core import PrismorInterventionHandler

Aliases the ``prismor_autogen_core`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

# See PrismorSec/prismor#173 -- mirrors the CrewAI/LangChain/Pydantic AI
# shims' defense against the 'prismor' package directory leaking onto
# sys.path and shadowing a real top-level import.
if __name__ != "prismor.autogen_core":
    raise ImportError(
        f"prismor.autogen_core was imported as {__name__!r}, not 'prismor.autogen_core' — "
        "the 'prismor' package directory is on sys.path and may be shadowing another "
        "package. Remove it from sys.path (see PrismorSec/prismor#173)."
    )

import prismor_autogen_core as _impl

_sys.modules[__name__] = _impl
