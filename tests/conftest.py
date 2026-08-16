"""Make the repository root importable so `import watcher` works from a bare checkout.

Same arrangement as `deriver/tests/conftest.py`. In a real environment the root
package is installed (`pip install -e .`) and no path juggling is needed; this
keeps `pytest tests/` working without an install step, which is what makes the
"no network, no database, no install" property of this suite actually usable.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
