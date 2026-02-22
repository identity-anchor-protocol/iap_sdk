from __future__ import annotations

import subprocess
import sys


def test_doc_command_validator_passes() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/validate_doc_commands.py"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "doc command validation passed" in proc.stdout
