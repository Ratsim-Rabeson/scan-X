"""Terminal chart widgets using plotext for scan-X."""

from __future__ import annotations

import io
from contextlib import redirect_stdout

import plotext as plt
from textual.widgets import Static

from scan_x.models import Severity, Vulnerability

_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.NONE,
]

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.NONE: "gray",
}


class SeverityChart(Static):
    """Horizontal bar chart showing vulnerability counts by severity."""

    DEFAULT_CSS = """
    SeverityChart {
        height: auto;
        min-height: 12;
        width: 1fr;
        padding: 1;
    }
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__("", *args, **kwargs)
        self._counts: dict[Severity, int] = {s: 0 for s in _SEVERITY_ORDER}

    def update_data(self, vulns: list[Vulnerability]) -> None:
        """Recalculate counts from a vulnerability list and re-render."""
        self._counts = {s: 0 for s in _SEVERITY_ORDER}
        for v in vulns:
            if v.severity in self._counts:
                self._counts[v.severity] += 1
        self._render_chart()

    def _render_chart(self) -> None:
        labels = [s.value for s in _SEVERITY_ORDER]
        values = [self._counts[s] for s in _SEVERITY_ORDER]
        colors = [_SEVERITY_COLORS[s] for s in _SEVERITY_ORDER]

        plt.clear_figure()
        plt.theme("dark")
        plt.title("Vulnerabilities by Severity")
        plt.simple_bar(labels, values, color=colors, width=60)

        buf = io.StringIO()
        with redirect_stdout(buf):
            plt.show()
        self.update(buf.getvalue())
