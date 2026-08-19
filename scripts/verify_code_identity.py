#!/usr/bin/env python3
"""Verify the exact release or clean development root used by Stage 6."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.release_binding import resolve_code_identity  # noqa: E402


def main() -> int:
    identity = resolve_code_identity(ROOT)
    print(json.dumps({"root": str(identity.root), "commit": identity.commit, "kind": identity.kind}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
