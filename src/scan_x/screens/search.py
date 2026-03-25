"""Vulnerability search screen for scan-X."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Input, Label, LoadingIndicator, Static
from textual.worker import Worker, WorkerState

if TYPE_CHECKING:
    from textual.app import ComposeResult
    from textual.widget import Widget

    from scan_x.models.vulnerability import Vulnerability
    from scan_x.sources.aggregator import VulnerabilityAggregator


def _try_import_widgets() -> (
    tuple[type[Widget] | None, type[Widget] | None, type[Widget] | None]
):
    """Attempt to import custom widgets; return None placeholders if unavailable."""
    search_bar_cls: type[Widget] | None = None
    filter_bar_cls: type[Widget] | None = None
    vuln_table_cls: type[Widget] | None = None
    try:
        from scan_x.widgets.search_bar import SearchBar

        search_bar_cls = SearchBar
    except ImportError:
        pass
    try:
        from scan_x.widgets.filter_bar import FilterBar

        filter_bar_cls = FilterBar
    except ImportError:
        pass
    try:
        from scan_x.widgets.vuln_table import VulnTable

        vuln_table_cls = VulnTable
    except ImportError:
        pass
    return search_bar_cls, filter_bar_cls, vuln_table_cls


class SearchScreen(Screen):
    """Search vulnerabilities across all configured sources."""

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._vulns: list[Vulnerability] = []
        self._aggregator: VulnerabilityAggregator | None = None
        self._search_bar_cls, self._filter_bar_cls, self._vuln_table_cls = (
            _try_import_widgets()
        )

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="search-container"):
            with Vertical(id="search-header"):
                if self._search_bar_cls is not None:
                    yield self._search_bar_cls()
                else:
                    yield Input(
                        placeholder="Search vulnerabilities (CVE ID or keyword)…",
                        id="search-input",
                    )
                if self._filter_bar_cls is not None:
                    yield self._filter_bar_cls()

            with Vertical(id="search-loading"):
                yield LoadingIndicator()
                yield Label("Searching…", id="search-loading-label")

            yield Static(
                "Enter a query above and press Enter to search.",
                id="search-empty",
            )

            with Vertical(id="search-results"):
                if self._vuln_table_cls is not None:
                    yield self._vuln_table_cls()
        yield Footer()

    def on_mount(self) -> None:
        self._init_aggregator()

    def _init_aggregator(self) -> None:
        """Lazily initialize the aggregator from app config."""
        if self._aggregator is not None:
            return
        try:
            from scan_x.config import load_config
            from scan_x.sources.aggregator import VulnerabilityAggregator

            config = load_config()
            self._aggregator = VulnerabilityAggregator(config)
        except Exception:
            self.notify("Failed to initialize sources", severity="error")

    # ── Search via custom SearchBar widget ──────────────────────────────

    def on_search_bar_submitted(self, event: object) -> None:
        """Handle SearchBar.Submitted message."""
        query = getattr(event, "query", "")
        if query:
            self._run_search(query)

    # ── Fallback: search via plain Input ────────────────────────────────

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "search-input" and event.value.strip():
            self._run_search(event.value.strip())

    # ── Filter changes ──────────────────────────────────────────────────

    def on_filter_bar_changed(self, event: object) -> None:
        """Handle FilterBar.Changed message."""
        filter_state = getattr(event, "filter_state", None)
        if filter_state is None:
            return
        try:
            table = self.query_one("VulnTable")
            table.apply_filter(filter_state)  # type: ignore[attr-defined]
        except Exception:
            pass

    # ── Table selection ─────────────────────────────────────────────────

    def on_vuln_table_selected(self, event: object) -> None:
        """Handle VulnTable.Selected — push detail screen."""
        vuln = getattr(event, "vuln", None)
        if vuln is None:
            return
        from scan_x.screens.detail import DetailScreen

        self.app.push_screen(DetailScreen(vuln))

    # ── Worker-based async search ───────────────────────────────────────

    def _run_search(self, query: str) -> None:
        self._show_loading(True)
        self.query_one("#search-empty", Static).display = False
        self.run_worker(self._search_async(query), name="search", exclusive=True)

    async def _search_async(self, query: str) -> list[Vulnerability]:
        if self._aggregator is None:
            return []
        return await self._aggregator.search(query)

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != "search":
            return
        if event.state == WorkerState.SUCCESS:
            vulns: list[Vulnerability] = event.worker.result or []
            self._vulns = vulns
            self._show_loading(False)
            self._update_results(vulns)
        elif event.state == WorkerState.ERROR:
            self._show_loading(False)
            self.notify("Search failed — check source configuration.", severity="error")

    def _show_loading(self, visible: bool) -> None:
        loading = self.query_one("#search-loading")
        if visible:
            loading.add_class("visible")
        else:
            loading.remove_class("visible")

    def _update_results(self, vulns: list[Vulnerability]) -> None:
        if not vulns:
            empty = self.query_one("#search-empty", Static)
            empty.update("No vulnerabilities found for this query.")
            empty.display = True
            return

        # Try custom VulnTable widget first
        try:
            table = self.query_one("VulnTable")
            table.update_data(vulns)  # type: ignore[attr-defined]
            return
        except Exception:
            pass

        # Fallback: render results as static text
        lines: list[str] = []
        for v in vulns:
            sev_colors = {
                "CRITICAL": "red",
                "HIGH": "dark_orange",
                "MEDIUM": "yellow",
                "LOW": "green",
                "NONE": "dim",
            }
            color = sev_colors.get(v.severity.value, "white")
            score = f" ({v.cvss_score})" if v.cvss_score is not None else ""
            lines.append(
                f"[{color}]{v.severity.value:>8}[/{color}] "
                f"[bold]{v.id}[/bold]{score}  {v.title}"
            )
        self.query_one("#search-empty", Static).update("\n".join(lines))
        self.query_one("#search-empty", Static).display = True

        # Update home screen stats if available
        try:
            home = self.app.get_screen("home")
            home.update_stats(vulns)  # type: ignore[attr-defined]
        except Exception:
            pass
