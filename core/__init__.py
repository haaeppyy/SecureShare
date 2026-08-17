"""SecureShare core: pairing, crypto, discovery, transfer, trust store.

Must be importable on any Python >= 3.10.  The version guard lives here
because submodule annotations (``str | None``, etc.) are evaluated at
import time and would raise TypeError on older interpreters before a
friendlier message could be shown.
"""

import sys

MIN_PYTHON = (3, 10)


def check_python_version() -> None:
    """Raise with a clear message when the interpreter is too old."""
    if sys.version_info < MIN_PYTHON:
        raise RuntimeError(
            f"SecureShare requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer "
            f"(recommended: 3.12); this interpreter is {sys.version.split()[0]}."
        )


check_python_version()
