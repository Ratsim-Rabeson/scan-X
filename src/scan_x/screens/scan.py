"""Project scan screen for scan-X."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, LoadingIndicator, Static
from textual.worker import Worker, WorkerState

if TYPE_CHECKING:
    from textual.app import ComposeResult
    from textual.widget import Widget

    from scan_x.models.project import ScanResult
    from scan_x.models.vulnerability import Vulnerability


def _try_import_vuln_table() -> type[Widget] | None:
    try:
        from scan_x.widgets.vuln_table import VulnTable

        return VulnTable
    except ImportError:
        return None


class ScanScreen(Screen[None]):
    """Scan a local project directory for vulnerabilities."""

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._scan_result: ScanResult | None = None
        self._vuln_table_cls = _try_import_vuln_table()

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="scan-container"):
            yield Static("[bold]Scan Project[/bold]", classes="section-title")

            with Horizontal(id="scan-input-row"):
                yield Input(
                    placeholder="Enter project path…",
                    id="scan-path-input",
                )
                yield Button("Scan", id="scan-start-btn", variant="primary")

            yield Static("", id="scan-detected-type")

            with Vertical(id="scan-progress"):
                yield LoadingIndicator()
                yield Label("Scanning project…", id="scan-progress-label")

            with Vertical(id="scan-summary"):
                yield Static("[bold]Scan Summary[/bold]", classes="section-title")
                with Horizontal(id="scan-summary-row"):
                    yield Label("", id="scan-summary-deps")
                    yield Label("", id="scan-summary-vulns")
                    yield Label("", id="scan-summary-severity")

            with Vertical(id="scan-results"):
                if self._vuln_table_cls is not None:
                    yield self._vuln_table_cls()
                else:
                    yield Static("", id="scan-results-fallback")

        yield Footer()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "scan-path-input":
            return
        path_str = event.value.strip()
        if not path_str:
            self.query_one("#scan-detected-type", Static).update("")
            return
        project_path = Path(path_str).expanduser()
        if not project_path.is_dir():
            self.query_one("#scan-detected-type", Static).update(
                f"[dim]Path not found: {path_str}[/dim]"
            )
            return
        self._detect_type(project_path)

    def _detect_type(self, project_path: Path) -> None:
        try:
            from scan_x.scanners.detector import ProjectDetector

            detector = ProjectDetector()
            types = detector.detect(project_path)
            if types:
                type_names = ", ".join(t.value for t in types)
                self.query_one("#scan-detected-type", Static).update(
                    f"[green]Detected:[/green] {type_names}"
                )
            else:
                self.query_one("#scan-detected-type", Static).update(
                    "[yellow]No known project type detected[/yellow]"
                )
        except Exception:
            self.query_one("#scan-detected-type", Static).update("")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scan-start-btn":
            self._start_scan()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "scan-path-input":
            self._start_scan()

    def _start_scan(self) -> None:
        path_str = self.query_one("#scan-path-input", Input).value.strip()
        if not path_str:
            self.notify("Please enter a project path.", severity="warning")
            return
        project_path = Path(path_str).expanduser()
        if not project_path.is_dir():
            self.notify(f"Directory not found: {path_str}", severity="error")
            return

        self._show_progress(True)
        self.query_one("#scan-summary").remove_class("visible")
        self.run_worker(self._scan_async(project_path), name="scan", exclusive=True)

    async def _scan_async(self, project_path: Path) -> ScanResult | None:
        from scan_x.config import load_config
        from scan_x.scanners.base import VulnerabilityAggregator as ScannerAggregator
        from scan_x.scanners.detector import ProjectDetector
        from scan_x.sources.aggregator import VulnerabilityAggregator

        config = load_config()
        agg = VulnerabilityAggregator(config)

        scanner_agg = ScannerAggregator(sources=agg.enabled_sources)
        detector = ProjectDetector()
        scanners = detector.get_scanners(project_path)

        if not scanners:
            return None

        # Run the first matching scanner
        scanner = scanners[0]
        return await scanner.scan(project_path, aggregator=scanner_agg)

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != "scan":
            return
        if event.state == WorkerState.SUCCESS:
            result: ScanResult | None = event.worker.result
            self._show_progress(False)
            if result is None:
                self.notify("No compatible scanner found for this project.", severity="warning")
                return
            self._scan_result = result
            self._display_results(result)
        elif event.state == WorkerState.ERROR:
            self._show_progress(False)
            self.notify("Scan failed — check the project path.", severity="error")

    def _show_progress(self, visible: bool) -> None:
        progress = self.query_one("#scan-progress")
        if visible:
            progress.add_class("visible")
        else:
            progress.remove_class("visible")

    def _display_results(self, result: ScanResult) -> None:
        # Summary
        self.query_one("#scan-summary").add_class("visible")
        self.query_one("#scan-summary-deps", Label).update(
            f"Dependencies: [bold]{result.total_deps}[/bold]"
        )
        self.query_one("#scan-summary-vulns", Label).update(
            f"Vulnerabilities: [bold]{result.vuln_count}[/bold]"
        )
        sev_parts: list[str] = []
        sev_colors = {
            "CRITICAL": "red",
            "HIGH": "dark_orange",
            "MEDIUM": "yellow",
            "LOW": "green",
        }
        for sev, count in result.severity_counts.items():
            if count > 0:
                color = sev_colors.get(sev.value, "white")
                sev_parts.append(f"[{color}]{sev.value}: {count}[/{color}]")
        self.query_one("#scan-summary-severity", Label).update(
            " | ".join(sev_parts) if sev_parts else "No vulnerabilities found"
        )

        # Table or fallback
        vulns: list[Vulnerability] = result.vulnerabilities
        try:
            table = self.query_one("VulnTable")
            table.update_data(vulns)  # type: ignore[attr-defined]
        except Exception:
            self._render_fallback(vulns)

        if vulns:
            self.notify(
                f"Found {len(vulns)} vulnerabilities in {result.total_deps} dependencies.",
                severity="warning" if result.vuln_count > 0 else "information",
            )

        # Update home screen stats
        try:
            home = self.app.get_screen("home")
            home.update_stats(vulns)  # type: ignore[attr-defined]
        except Exception:
            pass

    def _render_fallback(self, vulns: list[Vulnerability]) -> None:
        if not vulns:
            self.query_one("#scan-results-fallback", Static).update(
                "[green]No vulnerabilities found! ✓[/green]"
            )
            return
        lines: list[str] = []
        sev_colors = {
            "CRITICAL": "red",
            "HIGH": "dark_orange",
            "MEDIUM": "yellow",
            "LOW": "green",
            "NONE": "dim",
        }
        for v in vulns:
            color = sev_colors.get(v.severity.value, "white")
            score = f" ({v.cvss_score})" if v.cvss_score is not None else ""
            lines.append(
                f"[{color}]{v.severity.value:>8}[/{color}] "
                f"[bold]{v.id}[/bold]{score}  {v.title}"
            )
        import contextlib

        with contextlib.suppress(Exception):
            self.query_one("#scan-results-fallback", Static).update("\n".join(lines))

    def on_vuln_table_selected(self, event: object) -> None:
        """Handle VulnTable.Selected — push detail screen."""
        vuln = getattr(event, "vuln", None)
        if vuln is None:
            return
        from scan_x.screens.detail import DetailScreen

        self.app.push_screen(DetailScreen(vuln))
