"""Configuration helpers for the iap-agent CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path.home() / ".iap_agent" / "config.toml"


@dataclass(frozen=True)
class CLIConfig:
    beta_mode: bool = True
    maturity_level: str = "beta"
    registry_base: str = "http://localhost:8080"


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

    registry_base = str(source.get("registry_base", "http://localhost:8080")).strip()
    if not registry_base:
        raise ConfigError("registry_base must not be empty")

    return CLIConfig(
        beta_mode=beta_mode,
        maturity_level=maturity_level,
        registry_base=registry_base,
    )
