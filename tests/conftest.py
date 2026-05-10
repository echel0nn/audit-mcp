"""Pytest config: inject the ``src`` layout onto ``sys.path``.

The project uses a ``src/`` layout but is not pip-installed in the test env, so
plain ``import audit_mcp`` would fail. Prepending the ``src`` directory makes
the package importable without requiring an editable install.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
