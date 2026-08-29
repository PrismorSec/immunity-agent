"""The ``if __name__ == "__main__"`` guard must be the last statement in a CLI.

``python -m prismor.runtime.cli`` executes the module top to bottom, so a
function defined *below* the guard does not exist yet when ``main()`` dispatches
to it. That is not a hypothetical: ``_print_surfaces`` was appended after the
guard, which left ``prismor surfaces`` working through the console script entry
point (which imports the module fully, then calls ``main()``) and dying with
``NameError: name '_print_surfaces' is not defined`` under ``python -m`` — the
form the docs and several examples use.

An AST check rather than a subprocess run, because the failure is structural and
every ``main()`` dispatch that would exercise it reads real machine state
(enrolment, installed hooks) that a test has no business depending on.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

_RUNTIME = Path(__file__).resolve().parent.parent / "prismor" / "runtime"
CLI_MODULES = ["cli.py", "immunity_cli.py"]


def _guard_index(tree: ast.Module) -> int:
    for i, node in enumerate(tree.body):
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"):
            return i
    return -1


@pytest.mark.parametrize("module", CLI_MODULES)
def test_cli_main_guard_is_last(module):
    path = _RUNTIME / module
    tree = ast.parse(path.read_text(encoding="utf-8"))
    idx = _guard_index(tree)
    assert idx != -1, f"{module}: no `if __name__ == '__main__'` guard"

    after = [n for n in tree.body[idx + 1:]
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    assert not after, (
        f"{module}: {', '.join(n.name for n in after)} defined after the "
        "__main__ guard — unreachable under `python -m`. Move the guard to the "
        "end of the file.")
