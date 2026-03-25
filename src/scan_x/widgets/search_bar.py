"""Search input widget with history for scan-X."""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

from textual import on
from textual.containers import Horizontal
from textual.message import Message
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Input, LoadingIndicator

if TYPE_CHECKING:
    from textual.app import ComposeResult

_MAX_HISTORY = 20


class SearchBar(Widget):
    """Search bar with live search, submit, and loading indicator."""

    DEFAULT_CSS = """
    SearchBar {
        height: 3;
        layout: horizontal;
    }
    SearchBar Horizontal {
        width: 1fr;
        height: 3;
    }
    SearchBar Input {
        width: 1fr;
    }
    SearchBar LoadingIndicator {
        width: 4;
        height: 3;
    }
    SearchBar .hidden {
        display: none;
    }
    """

    loading: reactive[bool] = reactive(False)

    # ── Messages ──────────────────────────────────────────────────────

    class Submitted(Message):
        """Posted when the user presses Enter in the search bar."""

        def __init__(self, query: str) -> None:
            super().__init__()
            self.query = query

    class Changed(Message):
        """Posted on every keystroke while typing."""

        def __init__(self, query: str) -> None:
            super().__init__()
            self.query = query

    # ── Widget lifecycle ──────────────────────────────────────────────

    def __init__(
        self,
        *,
        name: str | None = None,
        id: str | None = None,  # noqa: A002
        classes: str | None = None,
        disabled: bool = False,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes, disabled=disabled)
        self._history: deque[str] = deque(maxlen=_MAX_HISTORY)

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Input(placeholder="Search CVEs, packages, keywords...", id="search-input")
            yield LoadingIndicator(id="search-loading", classes="hidden")

    # ── Reactive watchers ─────────────────────────────────────────────

    def watch_loading(self, value: bool) -> None:
        try:
            indicator = self.query_one("#search-loading", LoadingIndicator)
        except Exception:  # noqa: BLE001
            return
        if value:
            indicator.remove_class("hidden")
        else:
            indicator.add_class("hidden")

    # ── Event handlers ────────────────────────────────────────────────

    @on(Input.Submitted, "#search-input")
    def _on_submit(self, event: Input.Submitted) -> None:
        event.stop()
        query = event.value.strip()
        if query:
            self._add_to_history(query)
            self.post_message(self.Submitted(query))

    @on(Input.Changed, "#search-input")
    def _on_changed(self, event: Input.Changed) -> None:
        event.stop()
        self.post_message(self.Changed(event.value))

    # ── History helpers ───────────────────────────────────────────────

    @property
    def history(self) -> list[str]:
        """Return the search history (most recent last)."""
        return list(self._history)

    def _add_to_history(self, query: str) -> None:
        if query in self._history:
            self._history.remove(query)
        self._history.append(query)
