"""Prismor adapter for Pydantic AI.

Preferred import path::

    from prismor.pydantic_ai import guard_toolsets, PrismorToolset

Aliases the ``prismor_pydantic_ai`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

# See PrismorSec/prismor#173 -- this guard mirrors the CrewAI/LangChain shims'
# defense against the 'prismor' package directory leaking onto sys.path and
# shadowing a real top-level 'pydantic_ai' import.
if __name__ != "prismor.pydantic_ai":
    raise ImportError(
        f"prismor.pydantic_ai was imported as {__name__!r}, not 'prismor.pydantic_ai' — "
        "the 'prismor' package directory is on sys.path and may be shadowing another "
        "package. Remove it from sys.path (see PrismorSec/prismor#173)."
    )

import prismor_pydantic_ai as _impl

_sys.modules[__name__] = _impl
