"""Sortable, filterable vulnerability DataTable widget."""

from __future__ import annotations

from operator import attrgetter
from typing import TYPE_CHECKING

from textual.message import Message
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import DataTable, Footer

if TYPE_CHECKING:
    from textual.app import ComposeResult

from scan_x.models import Vulnerability  # noqa: TC001 – used at runtime in method bodies
from scan_x.widgets.filter_bar import FilterState

_COLUMNS: list[tuple[str, str]] = [
    ("cve_id", "CVE ID"),
    ("title", "Title"),
    ("severity", "Severity"),
    ("cvss", "CVSS"),
    ("ecosystem", "Ecosystem"),
    ("source", "Source"),
]

_SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold #ff6600",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
    "NONE": "dim",
}

_TITLE_MAX = 50


class VulnTable(Widget):
    """DataTable displaying vulnerability records with sort and filter support."""

    DEFAULT_CSS = """
    VulnTable {
        height: 1fr;
        layout: vertical;
    }
    VulnTable DataTable {
        height: 1fr;
    }
    VulnTable Footer {
        height: 1;
    }
    """

    row_count: reactive[int] = reactive(0)

    # ── Messages ──────────────────────────────────────────────────────

    class Selected(Message):
        """Emitted when the user selects a row."""

        def __init__(self, vulnerability: Vulnerability) -> None:
            super().__init__()
            self.vulnerability = vulnerability

    class SortChanged(Message):
        """Emitted when the user clicks a column header to sort."""

        def __init__(self, column: str, reverse: bool) -> None:
            super().__init__()
            self.column = column
            self.reverse = reverse

    # ── Init ──────────────────────────────────────────────────────────

    def __init__(
        self,
        *,
        name: str | None = None,
        id: str | None = None,  # noqa: A002
        classes: str | None = None,
        disabled: bool = False,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes, disabled=disabled)
        self._all_vulns: list[Vulnerability] = []
        self._displayed: list[Vulnerability] = []
        self._filter: FilterState = FilterState()
        self._sort_key: str = "severity"
        self._sort_reverse: bool = False

    # ── Compose ───────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        table: DataTable[str] = DataTable(id="vuln-data-table")
        table.cursor_type = "row"
        yield table
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#vuln-data-table", DataTable)
        for col_key, col_label in _COLUMNS:
            table.add_column(col_label, key=col_key)

    # ── Public API ────────────────────────────────────────────────────

    def update_data(self, vulns: list[Vulnerability]) -> None:
        """Replace the full vulnerability list and refresh the table."""
        self._all_vulns = list(vulns)
        self._refresh_table()

    def apply_filter(self, filter_state: FilterState) -> None:
        """Apply a new filter and refresh visible rows."""
        self._filter = filter_state
        self._refresh_table()

    # ── Event handlers ────────────────────────────────────────────────

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_index = event.cursor_row
        if 0 <= row_index < len(self._displayed):
            self.post_message(self.Selected(self._displayed[row_index]))

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        col_key = str(event.column_key)
        if col_key == self._sort_key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_key = col_key
            self._sort_reverse = False
        self.post_message(self.SortChanged(self._sort_key, self._sort_reverse))
        self._refresh_table()

    # ── Internals ─────────────────────────────────────────────────────

    def _refresh_table(self) -> None:
        filtered = [v for v in self._all_vulns if self._filter.matches(v)]
        filtered = self._sort(filtered)
        self._displayed = filtered
        self.row_count = len(filtered)

        table = self.query_one("#vuln-data-table", DataTable)
        table.clear()
        for vuln in filtered:
            style = _SEVERITY_STYLE.get(vuln.severity.value, "")
            title = vuln.title[:_TITLE_MAX] + ("…" if len(vuln.title) > _TITLE_MAX else "")
            ecosystem = vuln.affected_packages[0].ecosystem if vuln.affected_packages else ""
            cvss = f"{vuln.cvss_score:.1f}" if vuln.cvss_score is not None else "—"
            table.add_row(
                f"[{style}]{vuln.id}[/]",
                title,
                f"[{style}]{vuln.severity.value}[/]",
                cvss,
                ecosystem,
                vuln.source.value,
            )

    def _sort(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        sort_attr_map: dict[str, str] = {
            "cve_id": "id",
            "title": "title",
            "severity": "severity",
            "cvss": "cvss_score",
            "source": "source",
        }
        attr = sort_attr_map.get(self._sort_key)
        if attr is None:
            return vulns
        if attr == "cvss_score":
            return sorted(vulns, key=lambda v: v.cvss_score or 0.0, reverse=self._sort_reverse)
        return sorted(vulns, key=attrgetter(attr), reverse=self._sort_reverse)
