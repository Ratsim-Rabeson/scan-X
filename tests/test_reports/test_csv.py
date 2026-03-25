"""Tests for CSV report generation."""

from __future__ import annotations

import csv
import io
from pathlib import Path  # noqa: TC003 – used at runtime

import pytest

from scan_x.models.report import ReportConfig, ReportFormat, ReportMetadata
from scan_x.models.vulnerability import (
    AffectedPackage,
    Severity,
    Vulnerability,
    VulnerabilitySource,
)
from scan_x.reports.csv_report import COLUMNS, generate_csv


@pytest.fixture
def report_config(tmp_path: Path) -> ReportConfig:
    return ReportConfig(
        format=ReportFormat.CSV,
        output_path=tmp_path / "report.csv",
    )


@pytest.fixture
def report_metadata() -> ReportMetadata:
    return ReportMetadata(
        scan_x_version="0.1.0",
        total_vulnerabilities=3,
    )


class TestCsvGeneration:
    async def test_generates_file(
        self,
        sample_vulnerabilities: list[Vulnerability],
        report_config: ReportConfig,
        report_metadata: ReportMetadata,
    ) -> None:
        path = await generate_csv(sample_vulnerabilities, report_config, report_metadata)
        assert path.exists()
        assert path.suffix == ".csv"

    async def test_correct_columns(
        self,
        sample_vulnerabilities: list[Vulnerability],
        report_config: ReportConfig,
        report_metadata: ReportMetadata,
    ) -> None:
        path = await generate_csv(sample_vulnerabilities, report_config, report_metadata)
        content = path.read_text(encoding="utf-8")
        reader = csv.reader(io.StringIO(content))
        header = next(reader)
        assert header == COLUMNS

    async def test_row_count_matches(
        self,
        sample_vulnerabilities: list[Vulnerability],
        report_config: ReportConfig,
        report_metadata: ReportMetadata,
    ) -> None:
        path = await generate_csv(sample_vulnerabilities, report_config, report_metadata)
        content = path.read_text(encoding="utf-8")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        # Header + 1 row per affected package (each sample vuln has 1 package)
        expected_data_rows = sum(
            max(len(v.affected_packages), 1) for v in sample_vulnerabilities
        )
        assert len(rows) == expected_data_rows + 1

    async def test_vuln_with_multiple_packages(
        self,
        report_config: ReportConfig,
        report_metadata: ReportMetadata,
    ) -> None:
        vuln = Vulnerability(
            id="CVE-2024-MULTI",
            title="Multi-package vuln",
            description="Affects multiple packages.",
            severity=Severity.HIGH,
            cvss_score=8.0,
            source=VulnerabilitySource.NVD,
            affected_packages=[
                AffectedPackage(name="pkg-a", ecosystem="npm", affected_versions=["<1.0"]),
                AffectedPackage(name="pkg-b", ecosystem="npm", affected_versions=["<2.0"]),
                AffectedPackage(name="pkg-c", ecosystem="pypi", affected_versions=["<3.0"]),
            ],
        )
        path = await generate_csv([vuln], report_config, report_metadata)
        content = path.read_text(encoding="utf-8")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        # Header + 3 rows (one per package)
        assert len(rows) == 4

        packages = {row[5] for row in rows[1:]}
        assert packages == {"pkg-a", "pkg-b", "pkg-c"}

    async def test_vuln_without_packages(
        self,
        report_config: ReportConfig,
        report_metadata: ReportMetadata,
    ) -> None:
        vuln = Vulnerability(
            id="CVE-2024-NOPKG",
            title="No package info",
            description="No packages.",
            severity=Severity.LOW,
            source=VulnerabilitySource.OSV,
        )
        path = await generate_csv([vuln], report_config, report_metadata)
        content = path.read_text(encoding="utf-8")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        # Header + 1 row (even without packages)
        assert len(rows) == 2
        assert rows[1][0] == "CVE-2024-NOPKG"

    async def test_empty_vulns_only_header(
        self,
        report_config: ReportConfig,
        report_metadata: ReportMetadata,
    ) -> None:
        path = await generate_csv([], report_config, report_metadata)
        content = path.read_text(encoding="utf-8")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0] == COLUMNS

    async def test_severity_and_source_values(
        self,
        sample_vulnerability: Vulnerability,
        report_config: ReportConfig,
        report_metadata: ReportMetadata,
    ) -> None:
        path = await generate_csv([sample_vulnerability], report_config, report_metadata)
        content = path.read_text(encoding="utf-8")
        reader = csv.reader(io.StringIO(content))
        _header = next(reader)
        row = next(reader)
        assert row[2] == "CRITICAL"
        assert row[8] == "NVD"
