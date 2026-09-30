"""Run the installed package against the synthetic example fixture."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    command = [
        sys.executable,
        "-m",
        "agent_policy.cli",
        "dry-run",
        "--policy",
        str(root / "examples/policy.json"),
        "--request",
        str(root / "examples/request.json"),
        "--receipt",
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, file=sys.stderr, end="")
    if completed.stdout:
        receipt = json.loads(completed.stdout)
        assert receipt["performed"] is False
        assert receipt["result"]["decision"] == "deny"
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
