"""Settings screen for scan-X."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Select, Static, Switch

from scan_x.config import ScanXConfig, load_config, save_config

if TYPE_CHECKING:
    from textual.app import ComposeResult


class SettingsScreen(Screen[None]):
    """Configure API keys, sources, cache, and display settings."""

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._config: ScanXConfig = load_config()

    def compose(self) -> ComposeResult:
        cfg = self._config

        yield Header()
        with VerticalScroll(id="settings-container"):
            yield Static("[bold]Settings[/bold]", classes="section-title")

            # ── API Keys ────────────────────────────────────────────
            with Vertical(classes="settings-section"):
                yield Static("API Keys", classes="settings-section-title")

                with Horizontal(classes="setting-row"):
                    yield Label("NVD API Key", classes="setting-label")
                    yield Input(
                        value=cfg.api_keys.nvd or "",
                        password=True,
                        placeholder="Enter NVD API key…",
                        id="setting-nvd-key",
                    )

                with Horizontal(classes="setting-row"):
                    yield Label("GitHub Token", classes="setting-label")
                    yield Input(
                        value=cfg.api_keys.github or "",
                        password=True,
                        placeholder="Enter GitHub token…",
                        id="setting-github-key",
                    )

                with Horizontal(classes="setting-row"):
                    yield Label("Snyk API Key", classes="setting-label")
                    yield Input(
                        value=cfg.api_keys.snyk or "",
                        password=True,
                        placeholder="Enter Snyk API key…",
                        id="setting-snyk-key",
                    )

            # ── Source Toggles ──────────────────────────────────────
            with Vertical(classes="settings-section"):
                yield Static("Sources", classes="settings-section-title")

                with Horizontal(classes="setting-row"):
                    yield Label("OSV (no key required)", classes="setting-label")
                    yield Switch(value=cfg.sources.osv_enabled, id="setting-osv-enabled")

                with Horizontal(classes="setting-row"):
                    yield Label("NVD", classes="setting-label")
                    yield Switch(value=cfg.sources.nvd_enabled, id="setting-nvd-enabled")

                with Horizontal(classes="setting-row"):
                    yield Label("GitHub Advisory", classes="setting-label")
                    yield Switch(
                        value=cfg.sources.github_enabled, id="setting-github-enabled"
                    )

                with Horizontal(classes="setting-row"):
                    yield Label("Snyk", classes="setting-label")
                    yield Switch(value=cfg.sources.snyk_enabled, id="setting-snyk-enabled")

            # ── Cache ───────────────────────────────────────────────
            with Vertical(classes="settings-section"):
                yield Static("Cache", classes="settings-section-title")

                with Horizontal(classes="setting-row"):
                    yield Label("Enable Cache", classes="setting-label")
                    yield Switch(value=cfg.cache.enabled, id="setting-cache-enabled")

                with Horizontal(classes="setting-row", id="settings-cache-row"):
                    yield Label("TTL (hours)", classes="setting-label")
                    yield Input(
                        value=str(cfg.cache.ttl_hours),
                        type="integer",
                        id="setting-cache-ttl",
                    )
                    yield Button("Clear Cache", id="setting-clear-cache-btn", variant="warning")

            # ── Display ─────────────────────────────────────────────
            with Vertical(classes="settings-section"):
                yield Static("Display", classes="settings-section-title")

                with Horizontal(classes="setting-row", id="settings-theme-row"):
                    yield Label("Theme", classes="setting-label")
                    yield Select(
                        [("Dark", "dark"), ("Light", "light")],
                        value=cfg.display.theme,
                        id="setting-theme-select",
                    )

            yield Button("💾 Save Settings", id="settings-save-btn", variant="success")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "settings-save-btn":
            self._save_settings()
        elif event.button.id == "setting-clear-cache-btn":
            self._clear_cache()

    def _save_settings(self) -> None:
        cfg = self._config

        # API keys
        nvd_key = self.query_one("#setting-nvd-key", Input).value.strip()
        github_key = self.query_one("#setting-github-key", Input).value.strip()
        snyk_key = self.query_one("#setting-snyk-key", Input).value.strip()
        cfg.api_keys.nvd = nvd_key or None
        cfg.api_keys.github = github_key or None
        cfg.api_keys.snyk = snyk_key or None

        # Sources
        cfg.sources.osv_enabled = self.query_one("#setting-osv-enabled", Switch).value
        cfg.sources.nvd_enabled = self.query_one("#setting-nvd-enabled", Switch).value
        cfg.sources.github_enabled = self.query_one(
            "#setting-github-enabled", Switch
        ).value
        cfg.sources.snyk_enabled = self.query_one("#setting-snyk-enabled", Switch).value

        # Cache
        cfg.cache.enabled = self.query_one("#setting-cache-enabled", Switch).value
        ttl_str = self.query_one("#setting-cache-ttl", Input).value.strip()
        try:
            cfg.cache.ttl_hours = int(ttl_str) if ttl_str else 1
        except ValueError:
            cfg.cache.ttl_hours = 1

        # Display
        theme_select = self.query_one("#setting-theme-select", Select)
        theme_val = theme_select.value
        if theme_val in ("dark", "light"):
            cfg.display.theme = theme_val  # type: ignore[assignment]

        try:
            save_config(cfg)
            self.notify("Settings saved to config.toml ✓")
        except Exception as exc:
            self.notify(f"Failed to save settings: {exc}", severity="error")

    def _clear_cache(self) -> None:
        import shutil

        try:
            cache_dir = self._config.cache.directory
            if cache_dir.exists():
                shutil.rmtree(cache_dir)
                cache_dir.mkdir(parents=True, exist_ok=True)
                self.notify("Cache cleared ✓")
            else:
                self.notify("Cache directory does not exist.", severity="warning")
        except Exception as exc:
            self.notify(f"Failed to clear cache: {exc}", severity="error")
