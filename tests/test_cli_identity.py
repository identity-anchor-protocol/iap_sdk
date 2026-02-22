from __future__ import annotations

import os
import stat

from iap_sdk.cli.identity import load_or_create_identity


def test_load_or_create_identity_is_idempotent(tmp_path) -> None:
    identity_path = tmp_path / "identity.json"

    first, created_first, _ = load_or_create_identity(identity_path)
    second, created_second, _ = load_or_create_identity(identity_path)

    assert created_first is True
    assert created_second is False
    assert first.agent_id == second.agent_id
    assert first.public_key_b64 == second.public_key_b64


def test_identity_file_permissions_owner_only_on_posix(tmp_path) -> None:
    identity_path = tmp_path / "identity.json"
    _, _, path = load_or_create_identity(identity_path)

    if os.name != "posix":
        return

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600
