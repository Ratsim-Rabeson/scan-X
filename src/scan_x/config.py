"""TOML-based configuration system for scan-x."""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

logger = logging.getLogger(__name__)

_APP_NAME = "scan-x"
_CONFIG_FILENAME = "config.toml"


# ── Sub-models ──────────────────────────────────────────────────────────────


class ApiKeysConfig(BaseModel):
    nvd: str | None = None
    github: str | None = None
    snyk: str | None = None


class CacheConfig(BaseModel):
    enabled: bool = True
    ttl_hours: int = 1
    directory: Path = Path.home() / ".cache" / _APP_NAME


class DisplayConfig(BaseModel):
    theme: Literal["dark", "light"] = "dark"
    default_report_format: str = "html"
    show_severity: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]


class SourcesConfig(BaseModel):
    osv_enabled: bool = True
    nvd_enabled: bool = True
    github_enabled: bool = True
    snyk_enabled: bool = True


# ── Root model ──────────────────────────────────────────────────────────────


class ScanXConfig(BaseModel):
    api_keys: ApiKeysConfig = ApiKeysConfig()
    cache: CacheConfig = CacheConfig()
    display: DisplayConfig = DisplayConfig()
    sources: SourcesConfig = SourcesConfig()


# ── Helper functions ────────────────────────────────────────────────────────


def get_config_path() -> Path:
    """Return the path to the config file (~/.config/scan-x/config.toml)."""
    return Path.home() / ".config" / _APP_NAME / _CONFIG_FILENAME


def ensure_config_dir() -> Path:
    """Create the config directory if it doesn't exist and return its path."""
    config_dir = get_config_path().parent
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_default_config() -> ScanXConfig:
    """Return a config instance with all default values."""
    return ScanXConfig()


def load_config() -> ScanXConfig:
    """Load configuration from the TOML file.

    If the file doesn't exist a default config is written and returned.
    If the file is corrupt the defaults are returned with a warning.
    """
    path = get_config_path()

    if not path.exists():
        config = get_default_config()
        save_config(config)
        return config

    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
        return ScanXConfig.model_validate(data)
    except Exception:
        logger.warning(
            "Failed to parse config at %s – falling back to defaults.",
            path,
            exc_info=True,
        )
        return get_default_config()


def save_config(config: ScanXConfig) -> None:
    """Serialize *config* as TOML and write it to disk."""
    ensure_config_dir()
    get_config_path().write_text(_format_toml(config), encoding="utf-8")


# ── TOML formatter (no external dependency) ─────────────────────────────────


def _toml_value(value: object) -> str:
    """Format a single Python value as a TOML literal."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, Path):
        return _toml_value(str(value))
    if isinstance(value, list):
        items = ", ".join(_toml_value(item) for item in value)
        return f"[{items}]"
    return _toml_value(str(value))  # pragma: no cover


def _format_toml(config: ScanXConfig) -> str:
    """Produce a human-friendly TOML representation of *config*."""
    lines: list[str] = []

    def _section(header: str, model: BaseModel) -> None:
        lines.append(f"[{header}]")
        for field_name, field_value in model.model_dump().items():
            if field_value is None:
                continue
            lines.append(f"{field_name} = {_toml_value(field_value)}")
        lines.append("")

    _section("api_keys", config.api_keys)
    _section("cache", config.cache)
    _section("display", config.display)
    _section("sources", config.sources)

    return "\n".join(lines)
