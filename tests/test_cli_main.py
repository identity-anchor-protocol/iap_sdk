from __future__ import annotations

import io
import json
import os
from pathlib import Path

from iap_sdk.cli.main import main
from iap_sdk.errors import RegistryRequestError


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


def test_registry_set_base_stores_value_in_selected_config(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    out = io.StringIO()
    err = io.StringIO()

    rc = main(
        [
            "--config",
            str(config_path),
            "registry",
            "set-base",
            "--base",
            "https://registry.example",
            "--json",
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["registry_base_stored"] is True
    assert payload["registry_base_cleared"] is False
    assert payload["config_file"] == str(config_path)
    written = config_path.read_text(encoding="utf-8")
    assert 'registry_base = "https://registry.example"' in written
    assert "beta mode" in err.getvalue()


def test_registry_set_api_key_stores_and_clears_value(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    out = io.StringIO()
    err = io.StringIO()

    rc_store = main(
        [
            "--config",
            str(config_path),
            "registry",
            "set-api-key",
            "--api-key",
            "iapk_live_test",
            "--json",
        ],
        stdout=out,
        stderr=err,
    )

    assert rc_store == 0
    payload = json.loads(out.getvalue())
    assert payload["registry_api_key_stored"] is True
    assert 'registry_api_key = "iapk_live_test"' in config_path.read_text(encoding="utf-8")
    assert "beta mode" in err.getvalue()

    out = io.StringIO()
    err = io.StringIO()
    rc_clear = main(
        ["--config", str(config_path), "registry", "set-api-key", "--clear"],
        stdout=out,
        stderr=err,
    )

    assert rc_clear == 0
    assert "registry_api_key: cleared" in out.getvalue()
    assert 'registry_api_key = "iapk_live_test"' not in config_path.read_text(encoding="utf-8")
    assert "beta mode" in err.getvalue()


def test_setup_stores_multiple_values_and_runs_check(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"

    class _Identity:
        agent_id = "ed25519:test-agent"

    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (_Identity(), Path(path or "id")),
    )

    class _Client:
        def __init__(
            self,
            *,
            base_url: str,
            api_key: str | None = None,
            account_token: str | None = None,
        ) -> None:
            self.base_url = base_url
            self.api_key = api_key
            self.account_token = account_token

        def get_registry_info(self) -> dict:
            return {
                "version": "0.2.0",
                "minimum_recommended_sdk_version": "0.1.6",
                "supported_features": ["account_tokens"],
            }

        def get_agent_registry_status(self, agent_id: str) -> dict:
            return {
                "agent_id": agent_id,
                "has_identity_anchor": True,
                "latest_continuity_sequence": 2,
            }

        def get_account_usage(self) -> dict:
            return {
                "linked_key_count": 1,
                "effective_remaining_identity_anchor": 1,
                "effective_remaining_continuity": 5,
                "effective_remaining_lineage": 0,
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    out = io.StringIO()
    err = io.StringIO()
    rc = main(
        [
            "--config",
            str(config_path),
            "setup",
            "--registry-base",
            "https://registry.example",
            "--registry-api-key",
            "iapk_live_test",
            "--account-token",
            "iapt_live_test",
            "--check",
            "--json",
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["mutations"] == [
        "registry_base stored",
        "registry_api_key stored",
        "account_token stored",
    ]
    assert payload["registry_check"]["registry_reachable"] is True
    written = config_path.read_text(encoding="utf-8")
    assert 'registry_base = "https://registry.example"' in written
    assert 'registry_api_key = "iapk_live_test"' in written
    assert 'account_token = "iapt_live_test"' in written
    assert "beta mode" in err.getvalue()


def test_setup_requires_at_least_one_action(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    out = io.StringIO()
    err = io.StringIO()

    rc = main(["--config", str(config_path), "setup"], stdout=out, stderr=err)

    assert rc == 1
    assert "no setup action requested" in err.getvalue()


def test_registry_check_reports_reachability_and_entitlements(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        (
            'beta_mode = false\n'
            'registry_api_key = "iapk_live_test"\n'
            'account_token = "iapt_live_test"\n'
        ),
        encoding="utf-8",
    )

    class _Identity:
        agent_id = "ed25519:test-agent"

    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (_Identity(), Path(path or "id")),
    )

    class _Client:
        def __init__(
            self,
            *,
            base_url: str,
            api_key: str | None = None,
            account_token: str | None = None,
        ) -> None:
            self.base_url = base_url
            self.api_key = api_key
            self.account_token = account_token

        def get_registry_info(self) -> dict:
            return {
                "version": "0.2.0",
                "minimum_recommended_sdk_version": "0.1.6",
                "supported_features": ["account_tier_enforcement", "account_tokens"],
            }

        def get_agent_registry_status(self, agent_id: str) -> dict:
            return {
                "agent_id": agent_id,
                "has_identity_anchor": True,
                "latest_continuity_sequence": 4,
            }

        def get_account_usage(self) -> dict:
            return {
                "linked_key_count": 1,
                "effective_remaining_identity_anchor": 1,
                "effective_remaining_continuity": 8,
                "effective_remaining_lineage": 0,
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    out = io.StringIO()
    err = io.StringIO()
    rc = main(["--config", str(config_path), "registry", "check", "--json"], stdout=out, stderr=err)

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["registry_reachable"] is True
    assert payload["registry_api_key_configured"] is True
    assert payload["account_token_valid"] is True
    assert payload["has_identity_anchor"] is True
    assert payload["latest_continuity_sequence"] == 4
    assert payload["effective_remaining_continuity"] == 8
    assert err.getvalue() == ""


def test_registry_check_warns_when_account_token_is_invalid(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        'beta_mode = false\naccount_token = "bad_token"\n',
        encoding="utf-8",
    )

    class _Identity:
        agent_id = "ed25519:test-agent"

    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (_Identity(), Path(path or "id")),
    )

    class _Client:
        def __init__(
            self,
            *,
            base_url: str,
            api_key: str | None = None,
            account_token: str | None = None,
        ) -> None:
            self.base_url = base_url
            self.api_key = api_key
            self.account_token = account_token

        def get_registry_info(self) -> dict:
            return {
                "version": "0.2.0",
                "minimum_recommended_sdk_version": "0.1.6",
                "supported_features": [],
            }

        def get_agent_registry_status(self, agent_id: str) -> dict:
            return {
                "agent_id": agent_id,
                "has_identity_anchor": False,
                "latest_continuity_sequence": None,
            }

        def get_account_usage(self) -> dict:
            raise RegistryRequestError(
                "registry request failed: 401 invalid account token",
                status_code=401,
                detail="invalid account token",
                error_code="invalid_account_token",
            )

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    out = io.StringIO()
    err = io.StringIO()
    rc = main(["--config", str(config_path), "registry", "check", "--json"], stdout=out, stderr=err)

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["registry_reachable"] is True
    assert payload["account_token_valid"] is False
    assert any("account token check failed" in item for item in payload["warnings"])
    assert any("refresh the account token" in item for item in payload["next_actions"])
    assert err.getvalue() == ""


def test_account_usage_passes_account_token_and_renders_json(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        'beta_mode = false\naccount_token = "iapt_test_token"\nsessions_dir = "'
        + str(tmp_path / "sessions")
        + '"\n',
        encoding="utf-8",
    )
    captured: dict[str, str | None] = {}

    class _Client:
        def __init__(
            self,
            *,
            base_url: str,
            api_key: str | None = None,
            account_token: str | None = None,
        ) -> None:
            captured["base_url"] = base_url
            captured["api_key"] = api_key
            captured["account_token"] = account_token

        def get_account_usage(self) -> dict:
            return {
                "account": {
                    "account_id": "acct_123",
                    "email": "admin@ia-protocol.com",
                    "tier": "beta",
                },
                "linked_key_count": 1,
                "quota_periods": ["2026-02"],
                "total_monthly_identity_anchor_quota": 1,
                "total_monthly_continuity_quota": 10,
                "total_monthly_lineage_quota": 0,
                "total_used_identity_anchor": 0,
                "total_used_continuity": 2,
                "total_used_lineage": 0,
                "total_remaining_identity_anchor": 1,
                "total_remaining_continuity": 8,
                "total_remaining_lineage": 0,
                "keys": [],
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    out = io.StringIO()
    err = io.StringIO()
    rc = main(
        ["--config", str(config_path), "account", "usage", "--json"],
        stdout=out,
        stderr=err,
    )

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["account"]["account_id"] == "acct_123"
    assert Path(payload["snapshot_file"]).exists()
    assert captured == {
        "base_url": "https://registry.ia-protocol.com",
        "api_key": None,
        "account_token": "iapt_test_token",
    }
    assert err.getvalue() == ""


def test_account_usage_requires_account_token(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("beta_mode = false\n", encoding="utf-8")
    out = io.StringIO()
    err = io.StringIO()

    rc = main(
        ["--config", str(config_path), "account", "usage"],
        stdout=out,
        stderr=err,
    )

    assert rc == 1
    assert out.getvalue() == ""
    assert "missing account token" in err.getvalue()


def test_account_usage_invalid_token_has_actionable_error(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        'beta_mode = false\naccount_token = "bad_token"\n',
        encoding="utf-8",
    )

    class _Client:
        def __init__(
            self,
            *,
            base_url: str,
            api_key: str | None = None,
            account_token: str | None = None,
        ) -> None:
            self.base_url = base_url
            self.api_key = api_key
            self.account_token = account_token

        def get_account_usage(self) -> dict:
            raise RegistryRequestError(
                "registry request failed: 401 invalid account token",
                status_code=401,
                detail="invalid account token",
                error_code="invalid_account_token",
                body={"detail": "invalid account token"},
            )

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    out = io.StringIO()
    err = io.StringIO()
    rc = main(
        ["--config", str(config_path), "account", "usage"],
        stdout=out,
        stderr=err,
    )

    assert rc == 2
    assert out.getvalue() == ""
    assert "ask your operator to issue a fresh account token" in err.getvalue()


def test_account_set_token_stores_value_in_selected_config(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    out = io.StringIO()
    err = io.StringIO()

    rc = main(
        [
            "--config",
            str(config_path),
            "account",
            "set-token",
            "--token",
            "iapt_live_test",
            "--json",
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["account_token_stored"] is True
    assert payload["account_token_cleared"] is False
    assert payload["config_file"] == str(config_path)
    written = config_path.read_text(encoding="utf-8")
    assert 'account_token = "iapt_live_test"' in written
    assert "beta mode" in err.getvalue()


def test_account_set_token_clear_removes_value(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text('[cli]\naccount_token = "iapt_live_test"\n', encoding="utf-8")
    out = io.StringIO()
    err = io.StringIO()

    rc = main(
        ["--config", str(config_path), "account", "set-token", "--clear"],
        stdout=out,
        stderr=err,
    )

    assert rc == 0
    assert "account_token: cleared" in out.getvalue()
    assert 'account_token = "iapt_live_test"' not in config_path.read_text(encoding="utf-8")
    assert "beta mode" in err.getvalue()


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


def test_upgrade_migrate_reports_pending_actions_without_writing(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    state_root = tmp_path / ".iap" / "state" / "state_root.json"
    state_root.parent.mkdir(parents=True, exist_ok=True)
    state_root.write_text(json.dumps({"sequence": 2}, sort_keys=True), encoding="utf-8")

    out = io.StringIO()
    err = io.StringIO()
    rc = main(["upgrade", "migrate", "--project-local", "--json"], stdout=out, stderr=err)
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["changed"] is False
    assert payload["actions_applied"] == []
    assert "refresh_local_meta" in payload["actions_pending"]
    assert "upgrade_state_root_schema" in payload["actions_pending"]
    assert any("dry run only" in item for item in payload["warnings"])
    assert not (tmp_path / ".iap" / "meta.json").exists()


def test_upgrade_migrate_apply_normalizes_meta_and_state_schema(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    state_root = tmp_path / ".iap" / "state" / "state_root.json"
    state_root.parent.mkdir(parents=True, exist_ok=True)
    state_root.write_text(json.dumps({"sequence": 4}, sort_keys=True), encoding="utf-8")

    out = io.StringIO()
    err = io.StringIO()
    rc = main(
        ["upgrade", "migrate", "--project-local", "--apply", "--json"],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["changed"] is True
    assert payload["actions_pending"] == []
    assert "refresh_local_meta" in payload["actions_applied"]
    assert "upgrade_state_root_schema" in payload["actions_applied"]

    meta_payload = json.loads((tmp_path / ".iap" / "meta.json").read_text(encoding="utf-8"))
    assert meta_payload["schema_version"] == 1
    assert meta_payload["identity_path"] == str(tmp_path / ".iap" / "identity" / "ed25519.json")

    state_payload = json.loads(state_root.read_text(encoding="utf-8"))
    assert state_payload["schema_version"] == 1
    assert state_payload["sequence"] == 4
