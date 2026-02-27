from __future__ import annotations

from iap_sdk.cli.config import load_cli_config


def test_default_registry_base_is_production(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("IAP_REGISTRY_BASE", raising=False)
    config_path = tmp_path / "missing.toml"
    config = load_cli_config(config_path)
    assert config.registry_base == "https://registry.ia-protocol.com"


def test_env_registry_base_overrides_config_file(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text('registry_base = "http://localhost:8080"\n', encoding="utf-8")
    monkeypatch.setenv("IAP_REGISTRY_BASE", "https://env.registry.example")
    config = load_cli_config(config_path)
    assert config.registry_base == "https://env.registry.example"


def test_file_registry_base_used_when_env_not_set(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text('registry_base = "http://localhost:8080"\n', encoding="utf-8")
    monkeypatch.delenv("IAP_REGISTRY_BASE", raising=False)
    config = load_cli_config(config_path)
    assert config.registry_base == "http://localhost:8080"


def test_file_agent_name_used_when_set(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text('agent_name = "Config Agent"\n', encoding="utf-8")
    monkeypatch.delenv("IAP_REGISTRY_BASE", raising=False)
    config = load_cli_config(config_path)
    assert config.agent_name == "Config Agent"
