"""Prismor adapter for LangChain / LangGraph.

Preferred import path::

    from prismor.langchain import guard_tools, use_subject

Aliases the ``prismor_langchain`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

# This shim must only ever be imported as ``prismor.langchain``. If the
# ``prismor`` package directory leaks onto sys.path, Python can resolve it as a
# *top-level* ``langchain`` module; blindly aliasing sys.modules would then
# replace the real LangChain package with this adapter and break every
# downstream ``import langchain``. Fail loudly instead. (The sys.path leak was
# fixed in PrismorSec/prismor#173 — this guard is defense in depth.)
if __name__ != "prismor.langchain":
    raise ImportError(
        f"prismor.langchain was imported as {__name__!r}, not 'prismor.langchain' — "
        "the 'prismor' package directory is on sys.path and is shadowing the real "
        "'langchain' package. Remove it from sys.path (see PrismorSec/prismor#173)."
    )

import prismor_langchain as _impl

_sys.modules[__name__] = _impl
