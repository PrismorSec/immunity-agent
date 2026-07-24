"""Prismor adapter for the Claude Agent SDK.

Preferred import path::

    from prismor.claude_agent_sdk import prismor_hook_matcher

Aliases the ``prismor_claude_agent_sdk`` implementation module so both
import paths resolve to the same module object.
"""
import sys as _sys

# See PrismorSec/prismor#173 -- mirrors the other adapters' shims' defense
# against the 'prismor' package directory leaking onto sys.path and
# shadowing a real top-level 'claude_agent_sdk' import.
if __name__ != "prismor.claude_agent_sdk":
    raise ImportError(
        f"prismor.claude_agent_sdk was imported as {__name__!r}, not "
        "'prismor.claude_agent_sdk' — the 'prismor' package directory is on "
        "sys.path and may be shadowing another package. Remove it from "
        "sys.path (see PrismorSec/prismor#173)."
    )

import prismor_claude_agent_sdk as _impl

_sys.modules[__name__] = _impl
