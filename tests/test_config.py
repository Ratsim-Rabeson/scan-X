"""Tests for scan-X TOML configuration management."""

from __future__ import annotations

from pathlib import Path  # noqa: TC003 – used at runtime
from unittest.mock import patch

from scan_x.config import (
    ScanXConfig,
    get_default_config,
    load_config,
    save_config,
)


class TestGetDefaultConfig:
    def test_returns_scanx_config(self) -> None:
        config = get_default_config()
        assert isinstance(config, ScanXConfig)

    def test_default_cache_enabled(self) -> None:
        config = get_default_config()
        assert config.cache.enabled is True
        assert config.cache.ttl_hours == 1

    def test_default_sources_enabled(self) -> None:
        config = get_default_config()
        assert config.sources.osv_enabled is True
        assert config.sources.nvd_enabled is True

    def test_default_no_api_keys(self) -> None:
        config = get_default_config()
        assert config.api_keys.nvd is None
        assert config.api_keys.github is None
        assert config.api_keys.snyk is None

    def test_default_display(self) -> None:
        config = get_default_config()
        assert config.display.theme == "dark"
        assert config.display.default_report_format == "html"


class TestSaveAndLoadRoundTrip:
    def test_round_trip(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".config" / "scan-x" / "config.toml"

        with patch("scan_x.config.get_config_path", return_value=config_path):
            original = get_default_config()
            save_config(original)

            assert config_path.exists()

            loaded = load_config()
            assert loaded.cache.enabled == original.cache.enabled
            assert loaded.cache.ttl_hours == original.cache.ttl_hours
            assert loaded.display.theme == original.display.theme
            assert loaded.sources.osv_enabled == original.sources.osv_enabled

    def test_custom_values_round_trip(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".config" / "scan-x" / "config.toml"

        with patch("scan_x.config.get_config_path", return_value=config_path):
            config = ScanXConfig()
            config.cache.ttl_hours = 24
            config.display.theme = "light"
            config.sources.snyk_enabled = False

            save_config(config)
            loaded = load_config()

            assert loaded.cache.ttl_hours == 24
            assert loaded.display.theme == "light"
            assert loaded.sources.snyk_enabled is False


class TestLoadConfigMissingFile:
    def test_creates_default_on_missing(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".config" / "scan-x" / "config.toml"
        assert not config_path.exists()

        with patch("scan_x.config.get_config_path", return_value=config_path):
            config = load_config()

        assert isinstance(config, ScanXConfig)
        assert config_path.exists()


class TestLoadConfigCorruptFile:
    def test_falls_back_to_default(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".config" / "scan-x" / "config.toml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text("this is not valid toml {{{{", encoding="utf-8")

        with patch("scan_x.config.get_config_path", return_value=config_path):
            config = load_config()

        assert isinstance(config, ScanXConfig)
        assert config.cache.enabled is True

    def test_invalid_values_fall_back(self, tmp_path: Path) -> None:
        config_path = tmp_path / ".config" / "scan-x" / "config.toml"
        config_path.parent.mkdir(parents=True)
        # Valid TOML but invalid for the schema
        config_path.write_text(
            '[cache]\nenabled = "not-a-bool"\n', encoding="utf-8"
        )

        with patch("scan_x.config.get_config_path", return_value=config_path):
            config = load_config()

        assert isinstance(config, ScanXConfig)
