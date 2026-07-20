#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "audit_nginx_map_risk.py"
SAMPLES = ROOT / "samples"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCANNER), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def main() -> int:
    normal = run(str(SAMPLES))
    assert normal.returncode == 0, normal.stderr
    assert "[review]" in normal.stdout, normal.stdout

    failing = run("--fail-on-findings", str(SAMPLES))
    assert failing.returncode == 1, failing.stdout
    assert "possible capture/map expression" in failing.stdout, failing.stdout

    print("self-check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
