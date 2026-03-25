"""Main Textual application for scan-X."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import Screen

from scan_x.screens.home import HomeScreen
from scan_x.screens.report import ReportScreen
from scan_x.screens.scan import ScanScreen
from scan_x.screens.search import SearchScreen
from scan_x.screens.settings import SettingsScreen


class ScanXApp(App):
    """scan-X: Terminal vulnerability scanner."""

    TITLE = "scan-X"
    CSS_PATH = "app.tcss"

    BINDINGS = [
        Binding("s", "push_screen('search')", "Search"),
        Binding("p", "push_screen('scan')", "Scan Project"),
        Binding("r", "push_screen('report')", "Report"),
        Binding("c", "push_screen('settings')", "Config"),
        Binding("question_mark", "push_screen('help')", "Help"),
        Binding("q", "quit", "Quit"),
    ]

    SCREENS = {
        "home": HomeScreen,
        "search": SearchScreen,
        "scan": ScanScreen,
        "report": ReportScreen,
        "settings": SettingsScreen,
    }

    def compose(self) -> ComposeResult:
        """The app uses HomeScreen as its default screen via on_mount."""
        yield from ()

    def on_mount(self) -> None:
        """Push the home screen on startup."""
        self.push_screen("home")

    def action_push_screen(self, screen_name: str) -> None:
        """Handle keybinding screen navigation."""
        if screen_name == "help":
            self.push_screen(HelpScreen())
            return
        if screen_name in self.SCREENS:
            self.push_screen(screen_name)


class HelpScreen(Screen):
    """Quick help overlay."""

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("question_mark", "app.pop_screen", "Close"),
    ]

    def compose(self) -> ComposeResult:
        from textual.containers import VerticalScroll
        from textual.widgets import Footer, Header, Static

        yield Header()
        with VerticalScroll():
            yield Static(
                "[bold cyan]scan-X Help[/bold cyan]\n\n"
                "[bold]Keyboard Shortcuts[/bold]\n"
                "  [bold]s[/bold]  Search vulnerabilities\n"
                "  [bold]p[/bold]  Scan a project\n"
                "  [bold]r[/bold]  Generate a report\n"
                "  [bold]c[/bold]  Open settings\n"
                "  [bold]?[/bold]  Show this help\n"
                "  [bold]q[/bold]  Quit\n\n"
                "[bold]Navigation[/bold]\n"
                "  [bold]Escape[/bold]  Go back to previous screen\n"
                "  [bold]Tab[/bold]    Move focus to next widget\n"
                "  [bold]Enter[/bold]  Activate focused button / submit input\n\n"
                "[bold]Search Screen[/bold]\n"
                "  Type a CVE ID (e.g. CVE-2023-1234) or keyword and press Enter.\n"
                "  Use filters to narrow by severity.\n"
                "  Click a result to see full details.\n\n"
                "[bold]Scan Screen[/bold]\n"
                "  Enter a project directory path and press Scan.\n"
                "  The project type is auto-detected.\n\n"
                "[bold]Report Screen[/bold]\n"
                "  Choose format, output path, and options.\n"
                "  Press Generate to create the report.\n\n"
                "[bold]Settings[/bold]\n"
                "  Configure API keys, toggle sources, adjust cache, and theme.\n"
                "  Settings are saved to ~/.config/scan-x/config.toml.\n"
            )
        yield Footer()
