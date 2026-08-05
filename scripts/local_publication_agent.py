#!/usr/bin/env python3
"""Advance completed task results without waiting for the hourly controller."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.local_publication import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
