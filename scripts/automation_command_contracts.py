#!/usr/bin/env python3
"""Export exact release-bound automation command contracts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.automation_contracts import build_contracts  # noqa: E402
from oss_pr_radar.util import atomic_write_json  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    value = build_contracts(args.runtime_root)
    if args.output:
        atomic_write_json(args.output, value)
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
