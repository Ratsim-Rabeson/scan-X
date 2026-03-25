"""Tests for PDF report generation."""

from __future__ import annotations

from pathlib import Path  # noqa: TC003 – used at runtime
from unittest.mock import patch

import pytest

from scan_x.models.report import ReportConfig, ReportFormat, ReportMetadata
from scan_x.models.vulnerability import Vulnerability  # noqa: TC001 – used at runtime
from scan_x.reports.html import render_html


@pytest.fixture
def report_config(tmp_path: Path) -> ReportConfig:
    return ReportConfig(
        format=ReportFormat.PDF,
        output_path=tmp_path / "report.pdf",
    )


@pytest.fixture
def report_metadata() -> ReportMetadata:
    return ReportMetadata(
        scan_x_version="0.1.0",
        total_vulnerabilities=1,
    )


class TestPdfFallback:
    async def test_import_error_when_weasyprint_missing(
        self,
        sample_vulnerability: Vulnerability,
        report_config: ReportConfig,
        report_metadata: ReportMetadata,
    ) -> None:
        """PDF generation raises ImportError when WeasyPrint is not installed."""
        from scan_x.reports.pdf import generate_pdf

        with (
            patch.dict("sys.modules", {"weasyprint": None}),
            pytest.raises(ImportError, match="WeasyPrint"),
        ):
            await generate_pdf([sample_vulnerability], report_config, report_metadata)


class TestHtmlRenderForPdf:
    """PDF generation uses render_html internally — test that path."""

    def test_render_html_returns_string(
        self,
        sample_vulnerabilities: list[Vulnerability],
        report_config: ReportConfig,
        report_metadata: ReportMetadata,
    ) -> None:
        html = render_html(sample_vulnerabilities, report_config, report_metadata)
        assert isinstance(html, str)
        assert len(html) > 0

    def test_html_contains_vuln_ids(
        self,
        sample_vulnerabilities: list[Vulnerability],
        report_config: ReportConfig,
        report_metadata: ReportMetadata,
    ) -> None:
        html = render_html(sample_vulnerabilities, report_config, report_metadata)
        assert "CVE-2024-1234" in html
        assert "CVE-2024-5678" in html

    def test_html_contains_severity(
        self,
        sample_vulnerability: Vulnerability,
        report_config: ReportConfig,
        report_metadata: ReportMetadata,
    ) -> None:
        html = render_html([sample_vulnerability], report_config, report_metadata)
        assert "CRITICAL" in html

    def test_empty_vulns_produces_html(
        self,
        report_config: ReportConfig,
        report_metadata: ReportMetadata,
    ) -> None:
        html = render_html([], report_config, report_metadata)
        assert isinstance(html, str)
        assert "<html" in html.lower() or "<!doctype" in html.lower() or "<table" in html.lower()
