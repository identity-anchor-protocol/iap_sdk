"""Configuration helpers for the iap-agent CLI."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path.home() / ".iap_agent" / "config.toml"
DEFAULT_REGISTRY_BASE = "https://registry.ia-protocol.com"
REGISTRY_BASE_ENV_VAR = "IAP_REGISTRY_BASE"


@dataclass(frozen=True)
class CLIConfig:
    beta_mode: bool = True
    maturity_level: str = "beta"
    registry_base: str = DEFAULT_REGISTRY_BASE
    agent_name: str = "Local Agent"
    amcs_db_path: str = "./amcs.db"
    sessions_dir: str = str(Path.home() / ".iap_agent" / "sessions")
    registry_public_key_b64: str | None = None


class ConfigError(ValueError):
    """Raised when CLI config is invalid."""


def _load_toml(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")

    try:  # Python 3.11+
        import tomllib  # type: ignore[attr-defined]
        try:
            return tomllib.loads(raw)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    except ModuleNotFoundError:
        try:
            import tomli
        except ModuleNotFoundError as exc:
            raise ConfigError("toml parser unavailable; install tomli for Python < 3.11") from exc
        try:
            return tomli.loads(raw)
        except tomli.TOMLDecodeError as exc:
            raise ConfigError(f"invalid TOML in {path}: {exc}") from exc


def _to_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    raise ConfigError(f"{field_name} must be a boolean")


def load_cli_config(path: str | Path | None = None) -> CLIConfig:
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return CLIConfig()

    parsed = _load_toml(config_path)
    section = parsed.get("cli")
    if isinstance(section, dict):
        source = section
    elif section is None:
        source = parsed
    else:
        raise ConfigError("[cli] must be a table")

    beta_mode = _to_bool(source.get("beta_mode", True), "beta_mode")
    maturity_level = str(source.get("maturity_level", "beta")).strip().lower()
    if maturity_level not in {"alpha", "beta", "stable"}:
        raise ConfigError("maturity_level must be one of: alpha, beta, stable")

    env_registry_base = os.getenv(REGISTRY_BASE_ENV_VAR)
    configured_registry_base = str(source.get("registry_base", DEFAULT_REGISTRY_BASE)).strip()
    registry_base = env_registry_base.strip() if env_registry_base else configured_registry_base
    if not registry_base:
        raise ConfigError("registry_base must not be empty")

    agent_name = str(source.get("agent_name", "Local Agent")).strip()
    if not agent_name:
        raise ConfigError("agent_name must not be empty")

    amcs_db_path = str(source.get("amcs_db_path", "./amcs.db")).strip()
    if not amcs_db_path:
        raise ConfigError("amcs_db_path must not be empty")

    default_sessions_dir = str(Path.home() / ".iap_agent" / "sessions")
    sessions_dir = str(source.get("sessions_dir", default_sessions_dir)).strip()
    if not sessions_dir:
        raise ConfigError("sessions_dir must not be empty")
    registry_public_key_b64_raw = source.get("registry_public_key_b64")
    if registry_public_key_b64_raw is None:
        registry_public_key_b64 = None
    else:
        registry_public_key_b64 = str(registry_public_key_b64_raw).strip() or None

    return CLIConfig(
        beta_mode=beta_mode,
        maturity_level=maturity_level,
        registry_base=registry_base,
        agent_name=agent_name,
        amcs_db_path=amcs_db_path,
        sessions_dir=sessions_dir,
        registry_public_key_b64=registry_public_key_b64,
    )
