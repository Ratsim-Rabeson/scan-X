"""Color-coded severity badge widget for scan-X."""

from __future__ import annotations

from textual.widgets import Static

from scan_x.models import Severity


class SeverityBadge(Static):
    """A small label that renders a severity level with matching colors."""

    DEFAULT_CSS = """
    SeverityBadge {
        width: auto;
        height: 1;
        padding: 0 1;
        text-style: bold;
    }
    SeverityBadge.severity-critical {
        color: white;
        background: red;
    }
    SeverityBadge.severity-high {
        color: white;
        background: #ff6600;
    }
    SeverityBadge.severity-medium {
        color: black;
        background: yellow;
    }
    SeverityBadge.severity-low {
        color: white;
        background: blue;
    }
    SeverityBadge.severity-none {
        color: white;
        background: gray;
    }
    """

    _CSS_CLASS_MAP: dict[Severity, str] = {
        Severity.CRITICAL: "severity-critical",
        Severity.HIGH: "severity-high",
        Severity.MEDIUM: "severity-medium",
        Severity.LOW: "severity-low",
        Severity.NONE: "severity-none",
    }

    def __init__(
        self,
        severity: Severity,
        *,
        name: str | None = None,
        id: str | None = None,  # noqa: A002
        classes: str | None = None,
        disabled: bool = False,
    ) -> None:
        super().__init__(severity.value, name=name, id=id, classes=classes, disabled=disabled)
        self._severity = severity
        self.add_class(self._CSS_CLASS_MAP[severity])

    @property
    def severity(self) -> Severity:
        """The severity level displayed by this badge."""
        return self._severity

    @severity.setter
    def severity(self, value: Severity) -> None:
        self.remove_class(self._CSS_CLASS_MAP[self._severity])
        self._severity = value
        self.add_class(self._CSS_CLASS_MAP[value])
        self.update(value.value)
