"""Report generation screen for scan-X."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    LoadingIndicator,
    Select,
    Static,
    Switch,
)
from textual.worker import Worker, WorkerState

from scan_x.models.report import ReportConfig, ReportFormat

if TYPE_CHECKING:
    from textual.app import ComposeResult


class ReportScreen(Screen):
    """Configure and generate a vulnerability report."""

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="report-container"):
            yield Static("[bold]Generate Report[/bold]", classes="section-title")

            with Vertical(id="report-form"):
                # Format selection
                with Vertical(classes="form-group"):
                    yield Label("Report Format", classes="form-label")
                    yield Select(
                        [
                            ("HTML", ReportFormat.HTML),
                            ("PDF", ReportFormat.PDF),
                            ("JSON", ReportFormat.JSON),
                            ("CSV", ReportFormat.CSV),
                        ],
                        value=ReportFormat.HTML,
                        id="report-format-select",
                    )

                # Output path
                with Vertical(classes="form-group"):
                    yield Label("Output Path", classes="form-label")
                    yield Input(
                        placeholder="e.g. ./report.html",
                        value="./vulnerability-report.html",
                        id="report-output-input",
                    )

                # Title
                with Vertical(classes="form-group"):
                    yield Label("Report Title", classes="form-label")
                    yield Input(
                        value="scan-X Vulnerability Report",
                        id="report-title-input",
                    )

                # Options
                with Horizontal(id="report-options-row"):
                    with Vertical(classes="option-switch"), Horizontal():
                        yield Switch(value=True, id="report-charts-switch")
                        yield Label("Include Charts")
                    with Vertical(classes="option-switch"), Horizontal():
                        yield Switch(value=True, id="report-remediation-switch")
                        yield Label("Include Remediation")

                yield Button(
                    "📄 Generate Report",
                    id="report-generate-btn",
                    variant="primary",
                )

            with Vertical(id="report-progress"):
                yield LoadingIndicator()
                yield Label("Generating report…", id="report-progress-label")

            with Vertical(id="report-success"):
                yield Static("", id="report-success-msg")

        yield Footer()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Update the file extension when format changes."""
        if event.select.id != "report-format-select":
            return
        fmt = event.value
        if not isinstance(fmt, ReportFormat):
            return
        ext_map = {
            ReportFormat.HTML: ".html",
            ReportFormat.PDF: ".pdf",
            ReportFormat.JSON: ".json",
            ReportFormat.CSV: ".csv",
        }
        ext = ext_map.get(fmt, ".html")
        output_input = self.query_one("#report-output-input", Input)
        current = output_input.value
        stem = Path(current).stem if current else "vulnerability-report"
        output_input.value = f"./{stem}{ext}"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "report-generate-btn":
            self._generate_report()

    def _generate_report(self) -> None:
        fmt_select = self.query_one("#report-format-select", Select)
        fmt = fmt_select.value
        if not isinstance(fmt, ReportFormat):
            self.notify("Please select a report format.", severity="warning")
            return

        output_path = self.query_one("#report-output-input", Input).value.strip()
        if not output_path:
            self.notify("Please enter an output path.", severity="warning")
            return

        title = self.query_one("#report-title-input", Input).value.strip() or (
            "scan-X Vulnerability Report"
        )
        include_charts = self.query_one("#report-charts-switch", Switch).value
        include_remediation = self.query_one("#report-remediation-switch", Switch).value

        report_config = ReportConfig(
            format=fmt,
            output_path=Path(output_path),
            title=title,
            include_charts=include_charts,
            include_remediation=include_remediation,
        )

        self._show_progress(True)
        self.query_one("#report-success").remove_class("visible")
        self.run_worker(
            self._generate_async(report_config), name="report", exclusive=True
        )

    async def _generate_async(self, report_config: ReportConfig) -> str:
        """Generate the report asynchronously. Returns the output path."""
        # Ensure parent directory exists
        output = report_config.output_path.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)

        # Placeholder: write a minimal report file
        # The full report engine lives in scan_x.reports and will be wired later
        output.write_text(
            f"# {report_config.title}\n\n"
            f"Format: {report_config.format.value}\n"
            f"Generated by scan-X\n",
            encoding="utf-8",
        )
        return str(output)

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != "report":
            return
        if event.state == WorkerState.SUCCESS:
            path: str = event.worker.result or ""
            self._show_progress(False)
            success = self.query_one("#report-success")
            success.add_class("visible")
            self.query_one("#report-success-msg", Static).update(
                f"[green]✓ Report generated successfully![/green]\n\n"
                f"Saved to: [bold]{path}[/bold]"
            )
            self.notify(f"Report saved to {path}")
        elif event.state == WorkerState.ERROR:
            self._show_progress(False)
            self.notify("Report generation failed.", severity="error")

    def _show_progress(self, visible: bool) -> None:
        progress = self.query_one("#report-progress")
        if visible:
            progress.add_class("visible")
        else:
            progress.remove_class("visible")
