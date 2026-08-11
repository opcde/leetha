"""Every shipped module must at least import.

A syntax error in console.py once passed the entire 1441-test suite, because
nothing imported it: the interactive console is driven by signals and a REPL,
so no test touches it. This catches that whole class of breakage -- syntax
errors, bad imports, module-level exceptions -- for the price of an import.
"""

import importlib
import pkgutil

import pytest

import leetha

#: Modules that legitimately cannot be imported in a test process.
_SKIP = {
    # Nothing yet -- add with a reason if a module needs hardware or root.
}


def _iter_modules():
    for mod in pkgutil.walk_packages(leetha.__path__, prefix="leetha."):
        if mod.name in _SKIP:
            continue
        yield mod.name


@pytest.mark.parametrize("module_name", sorted(_iter_modules()))
def test_module_imports(module_name):
    importlib.import_module(module_name)
