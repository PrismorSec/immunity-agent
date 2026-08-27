"""Make the bundled framework adapters importable from a source checkout.

Installed, ``prismor.langchain`` and friends land inside the same ``prismor/``
package the runtime ships, so they are ordinary subpackages. In the repo they
live under ``adapters/<framework>/prismor/<framework>/`` instead — and since
``prismor/__init__.py`` exists (deliberately: it stops an unrelated installed
``prismor`` distribution from shadowing the repo-local runtime, see
PrismorSec/prismor#173), ``prismor`` is a regular package whose ``__path__``
does not grow when a new sys.path entry appears. Four adapter test modules
therefore failed at *collection* with ``No module named 'prismor.langchain'``
unless the extras happened to be pip-installed.

Extending ``__path__`` here fixes all of them in one place, before any test
module is imported. Each adapter directory also goes on ``sys.path`` so the
flat ``prismor_<framework>`` implementation modules the shims re-export from
resolve too.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ADAPTERS = Path(__file__).resolve().parent.parent / "adapters"


def _wire_adapters() -> None:
    import prismor

    for adapter in sorted(_ADAPTERS.iterdir()):
        shim_root = adapter / "prismor"
        if not shim_root.is_dir():
            continue  # non-Python adapter (vercel-ai, mastra)
        if str(adapter) not in sys.path:
            sys.path.insert(0, str(adapter))
        if str(shim_root) not in prismor.__path__:
            prismor.__path__.append(str(shim_root))


_wire_adapters()
