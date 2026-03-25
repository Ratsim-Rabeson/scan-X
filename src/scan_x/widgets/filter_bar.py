"""Horizontal filter bar for severity and source filtering."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from textual import on
from textual.containers import Horizontal
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Checkbox, Label

if TYPE_CHECKING:
    from textual.app import ComposeResult

from scan_x.models import Severity, Vulnerability, VulnerabilitySource


@dataclass
class FilterState:
    """Current filter configuration."""

    severities: set[Severity] = field(
        default_factory=lambda: {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW}
    )
    sources: set[VulnerabilitySource] | None = None

    def matches(self, vuln: Vulnerability) -> bool:
        """Return True if *vuln* passes all active filters."""
        if vuln.severity not in self.severities:
            return False
        return not (self.sources is not None and vuln.source not in self.sources)


_SEVERITY_OPTIONS: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
]

_SOURCE_OPTIONS: list[VulnerabilitySource] = list(VulnerabilitySource)


class FilterBar(Widget):
    """Horizontal bar with severity and source toggle filters."""

    DEFAULT_CSS = """
    FilterBar {
        height: auto;
        padding: 0 1;
        layout: horizontal;
    }
    FilterBar Horizontal {
        height: auto;
        width: auto;
        padding: 0 1;
    }
    FilterBar Label {
        width: auto;
        padding: 0 1 0 0;
        text-style: bold;
    }
    FilterBar Checkbox {
        width: auto;
        height: 1;
        padding: 0 1 0 0;
    }
    """

    class Changed(Message):
        """Emitted whenever a filter toggle changes."""

        def __init__(self, filter_state: FilterState) -> None:
            super().__init__()
            self.filter_state = filter_state

    def __init__(
        self,
        *,
        show_sources: bool = False,
        name: str | None = None,
        id: str | None = None,  # noqa: A002
        classes: str | None = None,
        disabled: bool = False,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes, disabled=disabled)
        self._show_sources = show_sources
        self._state = FilterState()

    # ── Compose ───────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        with Horizontal(id="severity-filters"):
            yield Label("Severity:")
            for sev in _SEVERITY_OPTIONS:
                yield Checkbox(
                    sev.value,
                    value=True,
                    id=f"sev-{sev.value.lower()}",
                )

        if self._show_sources:
            with Horizontal(id="source-filters"):
                yield Label("Source:")
                for src in _SOURCE_OPTIONS:
                    yield Checkbox(
                        src.value,
                        value=True,
                        id=f"src-{src.value.lower()}",
                    )

    # ── Event handling ────────────────────────────────────────────────

    @on(Checkbox.Changed)
    def _on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        event.stop()
        self._rebuild_state()
        self.post_message(self.Changed(self._state))

    # ── Public API ────────────────────────────────────────────────────

    @property
    def filter_state(self) -> FilterState:
        """Return the current filter state."""
        return self._state

    # ── Internals ─────────────────────────────────────────────────────

    def _rebuild_state(self) -> None:
        severities: set[Severity] = set()
        for sev in _SEVERITY_OPTIONS:
            try:
                cb = self.query_one(f"#sev-{sev.value.lower()}", Checkbox)
            except Exception:  # noqa: BLE001
                continue
            if cb.value:
                severities.add(sev)
        self._state.severities = severities

        if self._show_sources:
            sources: set[VulnerabilitySource] = set()
            for src in _SOURCE_OPTIONS:
                try:
                    cb = self.query_one(f"#src-{src.value.lower()}", Checkbox)
                except Exception:  # noqa: BLE001
                    continue
                if cb.value:
                    sources.add(src)
            self._state.sources = sources
        else:
            self._state.sources = None
