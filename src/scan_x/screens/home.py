"""Home / dashboard screen for scan-X."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from scan_x.models.vulnerability import Vulnerability

SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "dark_orange",
    "MEDIUM": "yellow",
    "LOW": "green",
    "NONE": "dim",
}


class HomeScreen(Screen):
    """Main dashboard showing summary stats and quick actions."""

    BINDINGS = [
        ("s", "app.push_screen('search')", "Search"),
        ("p", "app.push_screen('scan')", "Scan Project"),
        ("r", "app.push_screen('report')", "Report"),
        ("c", "app.push_screen('settings')", "Config"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._vulns: list[Vulnerability] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="home-container"):
            yield Static(
                "[bold cyan]scan-X[/bold cyan]  ·  Terminal Vulnerability Scanner",
                id="home-banner",
            )

            with Horizontal(id="stats-row"):
                with Vertical(classes="stat-box"):
                    yield Label("0", id="stat-total", classes="stat-value")
                    yield Label("Total", classes="stat-label")
                with Vertical(classes="stat-box"):
                    yield Label("0", id="stat-critical", classes="stat-value")
                    yield Label("Critical", classes="stat-label")
                with Vertical(classes="stat-box"):
                    yield Label("0", id="stat-high", classes="stat-value")
                    yield Label("High", classes="stat-label")
                with Vertical(classes="stat-box"):
                    yield Label("0", id="stat-medium", classes="stat-value")
                    yield Label("Medium", classes="stat-label")
                with Vertical(classes="stat-box"):
                    yield Label("0", id="stat-low", classes="stat-value")
                    yield Label("Low", classes="stat-label")

            with Horizontal(id="actions-row"):
                yield Button("🔍 Search Vulns", id="btn-search", variant="primary")
                yield Button("📂 Scan Project", id="btn-scan", variant="primary")
                yield Button("📄 Generate Report", id="btn-report", variant="default")

            with Vertical(id="home-chart-container"):
                yield Static("Severity Distribution", classes="section-title")
                yield Static("No data yet — run a search or scan.", id="home-chart-placeholder")

            with Vertical(id="recent-scans-container"):
                yield Static("Recent Activity", classes="section-title")
                yield Static(
                    "No recent scans. Press [bold]s[/bold] to search or "
                    "[bold]p[/bold] to scan a project.",
                    id="recent-scans-placeholder",
                )

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_screen_map = {
            "btn-search": "search",
            "btn-scan": "scan",
            "btn-report": "report",
        }
        screen_name = button_screen_map.get(event.button.id or "")
        if screen_name:
            self.app.push_screen(screen_name)

    def update_stats(self, vulns: list[Vulnerability]) -> None:
        """Update dashboard statistics from a list of vulnerabilities."""
        self._vulns = vulns
        total = len(vulns)
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
        for v in vulns:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1

        self.query_one("#stat-total", Label).update(str(total))
        self.query_one("#stat-critical", Label).update(str(counts["CRITICAL"]))
        self.query_one("#stat-high", Label).update(str(counts["HIGH"]))
        self.query_one("#stat-medium", Label).update(str(counts["MEDIUM"]))
        self.query_one("#stat-low", Label).update(str(counts["LOW"]))

        # Update chart placeholder with a simple text-based chart
        if vulns:
            chart_lines: list[str] = []
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                count = counts[sev]
                color = SEVERITY_COLORS[sev]
                bar = "█" * min(count, 40)
                chart_lines.append(f"[{color}]{sev:>8}[/{color}] {bar} {count}")
            self.query_one("#home-chart-placeholder", Static).update("\n".join(chart_lines))
