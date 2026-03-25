"""Tests for the scan-X Click CLI."""

from __future__ import annotations

from click.testing import CliRunner

from scan_x.cli import main


class TestCLI:
    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan-X" in result.output

    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["version"])
        assert result.exit_code == 0
        assert "scan-X v" in result.output

    def test_config_command(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["config"])
        assert result.exit_code == 0

    def test_search_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["search", "--help"])
        assert result.exit_code == 0
        assert "--source" in result.output
        assert "--severity" in result.output

    def test_scan_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output

    def test_report_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["report", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output

    def test_tui_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["tui", "--help"])
        assert result.exit_code == 0
