"""Regression: importing the Prismor runtime must not put the ``prismor``
package directory on ``sys.path``.

If it does, the PEP-420 namespace subpackages that ship the framework-adapter
shims (``prismor/openai``, ``prismor/crewai``, ``prismor/langchain``,
``prismor/browser_use``) become importable as TOP-LEVEL modules — so a plain
``import openai`` resolves to ``prismor/openai`` and its alias shim hijacks
``sys.modules['openai']``, shadowing the real SDK the adapter is meant to wrap.
That broke every in-process framework adapter.

The root cause was a stray ``sys.path.insert(0, os.path.dirname(_HERE))`` at the
top of ``prismor/runtime/semantic_guard_v2.py`` (a v1 relic — the sibling import
resolves through the installed ``prismor`` namespace without it).
"""
import subprocess
import sys
import textwrap


def test_runtime_import_does_not_pollute_syspath():
    # Use a fresh interpreter so module-level side effects actually run
    # (an already-imported module would not re-execute its top-level code).
    code = textwrap.dedent(
        """
        import os, sys
        import prismor
        pkg_dirs = {os.path.realpath(p) for p in prismor.__path__}
        # Importing the runtime pulls in semantic_guard_v2 at module load.
        import prismor.runtime.semantic_guard_v2  # noqa: F401
        leaked = sorted(pkg_dirs & {os.path.realpath(p) for p in sys.path if p})
        if leaked:
            print("LEAKED:" + ";".join(leaked))
            sys.exit(1)
        """
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, (
        "prismor package dir leaked onto sys.path — prismor/<subdir> namespace "
        "packages would shadow real top-level SDKs.\n"
        + result.stdout
        + result.stderr
    )
