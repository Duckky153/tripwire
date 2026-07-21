"""Put the repo root on sys.path so `import arcade_demo.server` resolves under pytest.

`arcade_demo` is a standalone example dir, not installed into the environment, so its
parent (the repo root) must be importable for the package-qualified test import to work.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
