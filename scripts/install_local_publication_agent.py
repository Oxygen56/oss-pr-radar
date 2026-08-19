#!/usr/bin/env python3
"""Compatibility entrypoint for the unified three-worker installer.

This historical name no longer owns a LaunchAgent. It delegates to the
release-bound worker installer, which validates runtime identity and
operational authorization before any service or plist write.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from install_local_publication_workers import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
