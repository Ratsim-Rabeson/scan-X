"""Vulnerability detail screen for scan-X."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult
    from textual.widget import Widget

    from scan_x.models.vulnerability import Vulnerability

SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "dark_orange",
    "MEDIUM": "yellow",
    "LOW": "green",
    "NONE": "dim",
}


def _try_import_severity_badge() -> type[Widget] | None:
    try:
        from scan_x.widgets.severity_badge import SeverityBadge

        return SeverityBadge
    except ImportError:
        return None


class DetailScreen(Screen):
    """Full detail view for a single vulnerability."""

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, vuln: Vulnerability) -> None:
        super().__init__()
        self._vuln = vuln

    def compose(self) -> ComposeResult:
        vuln = self._vuln
        badge_cls = _try_import_severity_badge()

        yield Header()
        with VerticalScroll(id="detail-container"):
            # ── Header: ID + severity + CVSS ────────────────────────
            with Vertical(id="detail-header"):
                with Horizontal(id="detail-header-row"):
                    yield Static(f"[bold]{vuln.id}[/bold]", id="detail-id")
                    if badge_cls is not None:
                        yield badge_cls(vuln.severity)
                    else:
                        color = SEVERITY_COLORS.get(vuln.severity.value, "white")
                        yield Static(
                            f"[{color} bold] {vuln.severity.value} [/{color} bold]",
                            id="detail-severity",
                        )
                    if vuln.cvss_score is not None:
                        score_label = f"CVSS: {vuln.cvss_score}"
                        if vuln.cvss_vector:
                            score_label += f"  ({vuln.cvss_vector})"
                        yield Static(score_label, id="detail-score")

                # Aliases
                if vuln.aliases:
                    aliases_text = "Aliases: " + ", ".join(vuln.aliases)
                    yield Static(aliases_text, id="detail-aliases")

                # Title
                yield Static(f"[bold]{vuln.title}[/bold]")

            # ── Description ─────────────────────────────────────────
            with Vertical(id="detail-description-box"):
                yield Static("Description", classes="section-title")
                yield Static(vuln.description or "No description available.")

            # ── Affected packages ───────────────────────────────────
            if vuln.affected_packages:
                with Vertical(id="detail-packages-box"):
                    yield Static("Affected Packages", classes="section-title")
                    for pkg in vuln.affected_packages:
                        affected = (
                            ", ".join(pkg.affected_versions) if pkg.affected_versions else "—"
                        )
                        fixed = ", ".join(pkg.fixed_versions) if pkg.fixed_versions else "none"
                        yield Static(
                            f"  [bold]{pkg.name}[/bold] ({pkg.ecosystem})\n"
                            f"    Affected: {affected}\n"
                            f"    Fixed:    {fixed}"
                        )

            # ── References ──────────────────────────────────────────
            if vuln.references:
                with Vertical(id="detail-references-box"):
                    yield Static("References", classes="section-title")
                    for ref in vuln.references:
                        yield Static(
                            f"  [{ref.type}] [cyan]{ref.url}[/cyan]",
                            classes="reference-link",
                        )

            # ── Remediation ─────────────────────────────────────────
            if vuln.remediation:
                with Vertical(id="detail-remediation-box"):
                    yield Static("Remediation", classes="section-title")
                    yield Static(vuln.remediation)

            # ── Source attribution ──────────────────────────────────
            source_text = f"Source: [bold]{vuln.source.value}[/bold]"
            if vuln.source_url:
                source_text += f"  [cyan]{vuln.source_url}[/cyan]"
            if vuln.published_date:
                source_text += f"\nPublished: {vuln.published_date:%Y-%m-%d}"
            if vuln.modified_date:
                source_text += f"  |  Modified: {vuln.modified_date:%Y-%m-%d}"
            yield Static(source_text)

            yield Button("← Back", id="detail-back-btn", variant="default")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "detail-back-btn":
            self.app.pop_screen()
