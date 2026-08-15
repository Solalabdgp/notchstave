"""Make the repository root importable so `import deriver` works from anywhere.

The deriver is installed as its own package (``deriver/pyproject.toml``) with
``package-dir`` mapping the import name onto this directory, so in a real
environment no path juggling is needed. This keeps `pytest deriver/tests`
working from a bare checkout too.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
