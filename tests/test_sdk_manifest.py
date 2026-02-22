from __future__ import annotations

from iap_sdk.errors import SchemaValidationError
from iap_sdk.manifest import build_identity_manifest


def test_manifest_hash_is_stable_across_entry_order() -> None:
    files_a = {
        "SOUL.md": "line1\nline2\n",
        "AGENT.md": "agent: atlas\n",
        "skills/SKILL.md": "skill content\n",
    }
    files_b = {
        "skills/SKILL.md": "skill content\n",
        "AGENT.md": "agent: atlas\n",
        "SOUL.md": "line1\nline2\n",
    }
    manifest_a = build_identity_manifest(files_a)
    manifest_b = build_identity_manifest(files_b)
    assert manifest_a["manifest_hash"] == manifest_b["manifest_hash"]


def test_manifest_normalizes_line_endings() -> None:
    files_lf = {
        "SOUL.md": "alpha\nbeta\n",
        "AGENT.md": "gamma\ndelta\n",
    }
    files_crlf = {
        "SOUL.md": "alpha\r\nbeta\r\n",
        "AGENT.md": "gamma\r\ndelta\r\n",
    }
    manifest_lf = build_identity_manifest(files_lf)
    manifest_crlf = build_identity_manifest(files_crlf)
    assert manifest_lf["manifest_hash"] == manifest_crlf["manifest_hash"]


def test_manifest_hash_changes_when_content_changes() -> None:
    base = {
        "SOUL.md": "soul v1\n",
        "AGENT.md": "agent v1\n",
    }
    changed = {
        "SOUL.md": "soul v2\n",
        "AGENT.md": "agent v1\n",
    }
    manifest_base = build_identity_manifest(base)
    manifest_changed = build_identity_manifest(changed)
    assert manifest_base["manifest_hash"] != manifest_changed["manifest_hash"]


def test_manifest_requires_core_paths() -> None:
    with_just_agent = {"AGENT.md": "agent only\n"}
    try:
        build_identity_manifest(with_just_agent)
    except SchemaValidationError as exc:
        assert "SOUL.md" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected SchemaValidationError")
