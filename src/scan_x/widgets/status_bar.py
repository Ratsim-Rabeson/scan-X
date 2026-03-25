"""Bottom status bar widget for scan-X."""

from __future__ import annotations

from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Label


class StatusBar(Widget):
    """Bottom bar showing source health, result counts, and filter info."""

    DEFAULT_CSS = """
    StatusBar {
        height: 1;
        dock: bottom;
        layout: horizontal;
        background: $surface;
        color: $text;
        padding: 0 1;
    }
    StatusBar Label {
        width: auto;
        padding: 0 2 0 0;
    }
    StatusBar #sources-label {
        width: 1fr;
    }
    StatusBar #count-label {
        width: auto;
    }
    StatusBar #filter-label {
        width: auto;
    }
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)

    def compose(self):  # noqa: ANN201
        with Horizontal():
            yield Label("Sources: —", id="sources-label")
            yield Label("Results: 0", id="count-label")
            yield Label("", id="filter-label")

    # ── Public API ────────────────────────────────────────────────────

    def update_sources(self, health: dict[str, bool]) -> None:
        """Update the source connection indicators.

        *health* maps source name to ``True`` (connected) / ``False`` (down).
        """
        parts = [f"{'✓' if ok else '✗'} {name}" for name, ok in health.items()]
        label = self.query_one("#sources-label", Label)
        label.update(f"Sources: {' │ '.join(parts)}")

    def update_count(self, count: int, filtered: int) -> None:
        """Update the result / filtered counts."""
        count_label = self.query_one("#count-label", Label)
        count_label.update(f"Results: {filtered}/{count}")

    def update_filter_info(self, info: str) -> None:
        """Update the free-form filter description shown at the right."""
        filter_label = self.query_one("#filter-label", Label)
        filter_label.update(info)
