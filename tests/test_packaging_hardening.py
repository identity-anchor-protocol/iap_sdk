from __future__ import annotations

import os
from pathlib import Path


def test_compatibility_matrix_mentions_protocol_and_endpoints() -> None:
    content = Path("COMPATIBILITY.md").read_text(encoding="utf-8")
    assert "IAP-0.1" in content
    assert "/registry/public-key" in content
    assert "/v1/continuity/requests" in content


def test_smoke_install_script_is_executable() -> None:
    script_path = Path("scripts/smoke_install.sh")
    assert script_path.exists()
    st_mode = script_path.stat().st_mode
    assert bool(st_mode & os.X_OK)
