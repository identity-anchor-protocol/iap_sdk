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

    out = io.StringIO()
    err = io.StringIO()

    rc = main(["--config", str(config_path), "flow", "run"], stdout=out, stderr=err)
    assert rc == 2
    assert "flow run: coming soon" in out.getvalue()
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
