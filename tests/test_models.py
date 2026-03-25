"""Tests for scan-X Pydantic models."""

from __future__ import annotations

from pathlib import Path  # noqa: TC003 – used at runtime

import pytest
from pydantic import ValidationError

from scan_x.models.project import Dependency, ProjectType, ScanResult, ScanStatus
from scan_x.models.report import ReportConfig, ReportFormat
from scan_x.models.vulnerability import (
    AffectedPackage,
    Reference,
    Severity,
    Vulnerability,
    VulnerabilitySource,
)

# -- Vulnerability model validation ------------------------------------------


class TestVulnerabilityModel:
    def test_valid_vulnerability(self, sample_vulnerability: Vulnerability) -> None:
        assert sample_vulnerability.id == "CVE-2024-1234"
        assert sample_vulnerability.severity == Severity.CRITICAL
        assert sample_vulnerability.cvss_score == 9.8

    def test_minimal_vulnerability(self) -> None:
        v = Vulnerability(
            id="CVE-2024-0001",
            title="Test",
            description="A test.",
            severity=Severity.LOW,
            source=VulnerabilitySource.OSV,
        )
        assert v.aliases == []
        assert v.affected_packages == []
        assert v.references == []
        assert v.cvss_score is None

    def test_cvss_score_out_of_range_high(self) -> None:
        with pytest.raises(ValidationError):
            Vulnerability(
                id="CVE-BAD",
                title="Bad",
                description="Bad",
                severity=Severity.LOW,
                source=VulnerabilitySource.OSV,
                cvss_score=11.0,
            )

    def test_cvss_score_out_of_range_negative(self) -> None:
        with pytest.raises(ValidationError):
            Vulnerability(
                id="CVE-BAD",
                title="Bad",
                description="Bad",
                severity=Severity.LOW,
                source=VulnerabilitySource.OSV,
                cvss_score=-1.0,
            )

    def test_missing_required_fields(self) -> None:
        with pytest.raises(ValidationError):
            Vulnerability(id="CVE-BAD")  # type: ignore[call-arg]

    def test_affected_package_model(self) -> None:
        pkg = AffectedPackage(
            name="lodash",
            ecosystem="npm",
            affected_versions=["<4.17.21"],
            fixed_versions=["4.17.21"],
        )
        assert pkg.name == "lodash"

    def test_reference_defaults(self) -> None:
        ref = Reference(url="https://example.com")
        assert ref.type == "WEB"


# -- Severity enum -----------------------------------------------------------


class TestSeverityEnum:
    def test_all_values_exist(self) -> None:
        expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
        assert {s.value for s in Severity} == expected

    def test_string_comparison(self) -> None:
        assert Severity.CRITICAL == "CRITICAL"
        assert Severity.HIGH == "HIGH"


# -- VulnerabilitySource enum ------------------------------------------------


class TestVulnerabilitySourceEnum:
    def test_all_sources(self) -> None:
        assert VulnerabilitySource.OSV == "OSV"
        assert VulnerabilitySource.NVD == "NVD"
        assert VulnerabilitySource.GITHUB_ADVISORY == "GITHUB_ADVISORY"
        assert VulnerabilitySource.SNYK == "SNYK"


# -- ScanResult computed fields ----------------------------------------------


class TestScanResult:
    def test_total_deps(self) -> None:
        result = ScanResult(
            project_path=Path("/test"),
            project_type=ProjectType.PYTHON,
            dependencies=[
                Dependency(name="flask", version="3.0", ecosystem="PyPI"),
                Dependency(name="click", version="8.1", ecosystem="PyPI"),
            ],
        )
        assert result.total_deps == 2

    def test_vuln_count(self, sample_vulnerabilities: list[Vulnerability]) -> None:
        result = ScanResult(
            project_path=Path("/test"),
            project_type=ProjectType.NODEJS,
            vulnerabilities=sample_vulnerabilities,
        )
        assert result.vuln_count == 3

    def test_severity_counts(self, sample_vulnerabilities: list[Vulnerability]) -> None:
        result = ScanResult(
            project_path=Path("/test"),
            project_type=ProjectType.NODEJS,
            vulnerabilities=sample_vulnerabilities,
        )
        counts = result.severity_counts
        assert counts[Severity.CRITICAL] == 1
        assert counts[Severity.HIGH] == 1
        assert counts[Severity.MEDIUM] == 1
        assert counts[Severity.LOW] == 0
        assert counts[Severity.NONE] == 0

    def test_empty_result(self) -> None:
        result = ScanResult(
            project_path=Path("/test"),
            project_type=ProjectType.UNKNOWN,
        )
        assert result.total_deps == 0
        assert result.vuln_count == 0
        assert result.scan_status == ScanStatus.PENDING

    def test_scan_status_values(self) -> None:
        assert ScanStatus.PENDING == "PENDING"
        assert ScanStatus.SCANNING == "SCANNING"
        assert ScanStatus.COMPLETED == "COMPLETED"
        assert ScanStatus.FAILED == "FAILED"


# -- ReportConfig defaults ---------------------------------------------------


class TestReportConfig:
    def test_default_title(self) -> None:
        config = ReportConfig(format=ReportFormat.HTML, output_path=Path("out.html"))
        assert config.title == "scan-X Vulnerability Report"

    def test_defaults(self) -> None:
        config = ReportConfig(format=ReportFormat.JSON, output_path=Path("out.json"))
        assert config.include_charts is True
        assert config.include_remediation is True
        assert config.severity_filter is None

    def test_report_format_values(self) -> None:
        assert ReportFormat.PDF == "PDF"
        assert ReportFormat.HTML == "HTML"
        assert ReportFormat.JSON == "JSON"
        assert ReportFormat.CSV == "CSV"
