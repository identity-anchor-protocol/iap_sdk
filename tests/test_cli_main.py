from __future__ import annotations

import io
import json

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
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url

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
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url

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
