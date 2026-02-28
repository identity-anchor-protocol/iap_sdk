from __future__ import annotations

import io
import json
import os
from pathlib import Path

from iap_sdk.cli.main import main


def test_version_json_has_expected_fields() -> None:
    out = io.StringIO()
    err = io.StringIO()

    rc = main(["version", "--json"], stdout=out, stderr=err)
    assert rc == 0
    assert err.getvalue() == ""

    payload = json.loads(out.getvalue())
    assert payload["cli"] == "iap-agent"
    assert payload["protocol_version"] == "IAP-0.1"
    assert isinstance(payload["sdk_version"], str)
    assert payload["beta_mode"] is True


def test_beta_warning_emitted_for_non_version_command(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("beta_mode = true\n", encoding="utf-8")
    identity_path = tmp_path / "identity.json"

    out = io.StringIO()
    err = io.StringIO()

    rc = main(
        ["--config", str(config_path), "init", "--identity-file", str(identity_path)],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    assert "agent_id:" in out.getvalue()
    assert "[beta]" in err.getvalue()


def test_beta_warning_suppressed_when_beta_mode_false(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("beta_mode = false\n", encoding="utf-8")
    identity_path = tmp_path / "identity.json"

    out = io.StringIO()
    err = io.StringIO()

    rc = main(
        ["--config", str(config_path), "init", "--identity-file", str(identity_path)],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    assert "agent_id:" in out.getvalue()
    assert err.getvalue() == ""


def test_version_command_ignores_beta_warning(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("beta_mode = true\n", encoding="utf-8")

    out = io.StringIO()
    err = io.StringIO()

    rc = main(["--config", str(config_path), "version"], stdout=out, stderr=err)
    assert rc == 0
    assert "iap-agent" in out.getvalue()
    assert err.getvalue() == ""


def test_invalid_config_returns_error(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text('maturity_level = "experimental"\n', encoding="utf-8")

    out = io.StringIO()
    err = io.StringIO()

    rc = main(["--config", str(config_path), "version"], stdout=out, stderr=err)
    assert rc == 1
    assert out.getvalue() == ""
    assert "config error" in err.getvalue()


def test_init_show_public_json_omits_private_key(tmp_path) -> None:
    identity_path = tmp_path / "identity.json"
    out = io.StringIO()
    err = io.StringIO()

    rc = main(
        ["init", "--identity-file", str(identity_path), "--show-public", "--json"],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    assert err.getvalue().startswith("[beta]")
    payload = json.loads(out.getvalue())
    assert payload["created"] is True
    assert "private_key_b64" not in payload


def test_init_json_omits_private_key_by_default(tmp_path) -> None:
    identity_path = tmp_path / "identity.json"
    out = io.StringIO()
    err = io.StringIO()

    rc = main(["init", "--identity-file", str(identity_path), "--json"], stdout=out, stderr=err)
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert "private_key_b64" not in payload


def test_init_json_includes_private_key_with_explicit_flag(tmp_path) -> None:
    identity_path = tmp_path / "identity.json"
    out = io.StringIO()
    err = io.StringIO()

    rc = main(
        ["init", "--identity-file", str(identity_path), "--json", "--export-private-key"],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert isinstance(payload["private_key_b64"], str)


def test_init_project_local_identity_path(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    out = io.StringIO()
    err = io.StringIO()

    rc = main(["init", "--project-local", "--json"], stdout=out, stderr=err)
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["identity_path"] == str(tmp_path / ".iap" / "identity" / "ed25519.json")


def test_init_project_local_conflicts_with_identity_file(tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()
    identity_path = tmp_path / "identity.json"
    rc = main(
        ["init", "--project-local", "--identity-file", str(identity_path), "--json"],
        stdout=out,
        stderr=err,
    )
    assert rc == 1
    assert "cannot use --project-local together with --identity-file" in err.getvalue()


def test_registry_status_uses_identity_fallback_and_prints_json(tmp_path, monkeypatch) -> None:
    identity_path = tmp_path / "identity.json"

    class _Identity:
        agent_id = "ed25519:test-fallback"

    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (_Identity(), identity_path),
    )

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key

        def get_agent_registry_status(self, agent_id: str) -> dict:
            return {
                "agent_id": agent_id,
                "has_identity_anchor": True,
                "identity_anchor_request_id": "anchor-req",
                "identity_anchor_issued_at": "2026-02-27T12:00:00Z",
                "latest_continuity_sequence": 2,
                "latest_continuity_memory_root": "a" * 64,
                "latest_continuity_request_id": "cont-req",
                "latest_continuity_issued_at": "2026-02-27T12:05:00Z",
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    out = io.StringIO()
    err = io.StringIO()
    rc = main(
        [
            "registry",
            "status",
            "--identity-file",
            str(identity_path),
            "--registry-base",
            "https://registry.ia-protocol.com",
            "--json",
        ],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["has_identity_anchor"] is True
    assert payload["latest_continuity_sequence"] == 2


def test_registry_status_accepts_explicit_agent_id(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("beta_mode = false\n", encoding="utf-8")

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key

        def get_agent_registry_status(self, agent_id: str) -> dict:
            return {
                "agent_id": agent_id,
                "has_identity_anchor": False,
                "identity_anchor_request_id": None,
                "identity_anchor_issued_at": None,
                "latest_continuity_sequence": None,
                "latest_continuity_memory_root": None,
                "latest_continuity_request_id": None,
                "latest_continuity_issued_at": None,
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    out = io.StringIO()
    err = io.StringIO()
    rc = main(
        [
            "--config",
            str(config_path),
            "registry",
            "status",
            "--agent-id",
            "ed25519:test-agent",
            "--registry-base",
            "https://registry.ia-protocol.com",
        ],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    assert "agent_id: ed25519:test-agent" in out.getvalue()
    assert "has_identity_anchor: False" in out.getvalue()
    assert err.getvalue() == ""


def test_registry_status_passes_configured_api_key(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        'beta_mode = false\nregistry_api_key = "iap_live_test"\n',
        encoding="utf-8",
    )
    captured: dict[str, str | None] = {}

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key
            captured["base_url"] = base_url
            captured["api_key"] = api_key

        def get_agent_registry_status(self, agent_id: str) -> dict:
            return {
                "agent_id": agent_id,
                "has_identity_anchor": False,
                "identity_anchor_request_id": None,
                "identity_anchor_issued_at": None,
                "latest_continuity_sequence": None,
                "latest_continuity_memory_root": None,
                "latest_continuity_request_id": None,
                "latest_continuity_issued_at": None,
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    out = io.StringIO()
    err = io.StringIO()
    rc = main(
        [
            "--config",
            str(config_path),
            "registry",
            "status",
            "--agent-id",
            "ed25519:test-agent",
        ],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    assert captured == {
        "base_url": "https://registry.ia-protocol.com",
        "api_key": "iap_live_test",
    }


def test_upgrade_status_reports_registry_capabilities_and_sequences(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        'beta_mode = false\nconfig_schema_version = 2\nregistry_api_key = "iap_live_test"\n',
        encoding="utf-8",
    )
    state_root = tmp_path / ".iap" / "state" / "state_root.json"
    state_root.parent.mkdir(parents=True, exist_ok=True)
    state_root.write_text(
        json.dumps({"schema_version": 1, "sequence": 1}, sort_keys=True),
        encoding="utf-8",
    )
    identity_path = tmp_path / ".iap" / "identity" / "ed25519.json"

    class _Identity:
        agent_id = "ed25519:test-upgrade"

    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (_Identity(), identity_path),
    )

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key

        def get_registry_info(self) -> dict:
            return {
                "registry_id": "iap-registry-main",
                "registry_public_key_fingerprint": "a" * 64,
                "version": "0.2.0",
                "protocol_version": "IAP-0.1",
                "minimum_recommended_sdk_version": "9.9.9",
                "supported_features": ["agent_status", "continuity", "identity_anchor"],
            }

        def get_agent_registry_status(self, agent_id: str) -> dict:
            return {
                "agent_id": agent_id,
                "has_identity_anchor": True,
                "latest_continuity_sequence": 3,
                "latest_continuity_memory_root": "b" * 64,
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    out = io.StringIO()
    err = io.StringIO()
    rc = main(
        ["--config", str(config_path), "upgrade", "status", "--project-local", "--json"],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["config_schema_version"] == 2
    assert payload["local_meta_schema_version"] == 1
    assert payload["local_meta_detected_schema_version"] == 0
    assert payload["local_state_detected_schema_version"] == 1
    assert payload["identity_scope"] == "project-local"
    assert payload["latest_registry_sequence"] == 3
    assert any(
        "registry continuity sequence is ahead of local state" in item
        for item in payload["warnings"]
    )
    assert any("upgrade iap-agent" in item for item in payload["next_actions"])
    assert err.getvalue() == ""


def test_upgrade_status_warns_when_global_identity_is_selected(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("beta_mode = false\n", encoding="utf-8")

    class _Identity:
        agent_id = "ed25519:test-global"

    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (_Identity(), path),
    )

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key

        def get_registry_info(self) -> dict:
            return {
                "registry_id": "iap-registry-main",
                "registry_public_key_fingerprint": "a" * 64,
                "version": "0.2.0",
                "protocol_version": "IAP-0.1",
                "minimum_recommended_sdk_version": "0.1.6",
                "supported_features": [],
            }

        def get_agent_registry_status(self, agent_id: str) -> dict:
            return {"agent_id": agent_id, "has_identity_anchor": False}

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    out = io.StringIO()
    err = io.StringIO()
    rc = main(["--config", str(config_path), "upgrade", "status", "--json"], stdout=out, stderr=err)
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["identity_scope"] == "global"
    assert any("current identity is global" in item for item in payload["warnings"])


def test_init_json_includes_meta_file(tmp_path) -> None:
    identity_path = tmp_path / "identity.json"
    out = io.StringIO()
    err = io.StringIO()
    cwd = Path.cwd()
    try:
        os.chdir(tmp_path)
        rc = main(["init", "--identity-file", str(identity_path), "--json"], stdout=out, stderr=err)
        assert rc == 0
        payload = json.loads(out.getvalue())
        assert payload["meta_schema_version"] == 1
        assert payload["meta_file"] == str(tmp_path / ".iap" / "meta.json")
    finally:
        os.chdir(cwd)
