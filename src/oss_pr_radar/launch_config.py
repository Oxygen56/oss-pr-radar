"""Parse the launchd configuration printed for a loaded service."""

from __future__ import annotations

import re
from typing import Any


def parse_launchctl_config(output: str) -> dict[str, Any]:
    """Extract the exact command and working directory from launchctl text."""

    arguments: list[str] = []
    in_arguments = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("arguments ="):
            in_arguments = "{" in stripped and "}" not in stripped
            continue
        if in_arguments:
            if stripped.startswith("}"):
                in_arguments = False
            elif stripped:
                arguments.append(stripped.strip('"'))
    program = re.search(r"^\s*program = (.+)$", output, re.MULTILINE)
    workdir = re.search(r"^\s*working directory = (.+)$", output, re.MULTILINE)
    plist_path = re.search(r"^\s*path = (.+)$", output, re.MULTILINE)
    return {
        "ProgramArguments": arguments or ([program.group(1).strip()] if program else None),
        "WorkingDirectory": workdir.group(1).strip() if workdir else None,
        "PlistPath": plist_path.group(1).strip() if plist_path else None,
    }
