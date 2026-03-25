"""Shared test fixtures for scan-X."""

from __future__ import annotations

import pytest

from scan_x.models.vulnerability import (
    AffectedPackage,
    Reference,
    Severity,
    Vulnerability,
    VulnerabilitySource,
)


@pytest.fixture
def sample_vulnerability() -> Vulnerability:
    """A sample vulnerability for testing."""
    return Vulnerability(
        id="CVE-2024-1234",
        aliases=["GHSA-abcd-1234-efgh"],
        title="Remote Code Execution in example-package",
        description=(
            "A critical RCE vulnerability in example-package"
            " allows attackers to execute arbitrary code."
        ),
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        affected_packages=[
            AffectedPackage(
                name="example-package",
                ecosystem="npm",
                affected_versions=["<2.0.0"],
                fixed_versions=["2.0.0"],
            )
        ],
        references=[
            Reference(url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234", type="ADVISORY"),
            Reference(url="https://github.com/example/fix/commit/abc123", type="FIX"),
        ],
        source=VulnerabilitySource.NVD,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        remediation="Upgrade example-package to version 2.0.0 or later.",
    )


@pytest.fixture
def sample_vulnerabilities(sample_vulnerability: Vulnerability) -> list[Vulnerability]:
    """A list of sample vulnerabilities with varying severities."""
    return [
        sample_vulnerability,
        Vulnerability(
            id="CVE-2024-5678",
            title="XSS in web-lib",
            description="Cross-site scripting vulnerability.",
            severity=Severity.HIGH,
            cvss_score=7.5,
            affected_packages=[
                AffectedPackage(
                    name="web-lib",
                    ecosystem="npm",
                    affected_versions=["<3.1.0"],
                    fixed_versions=["3.1.0"],
                )
            ],
            references=[],
            source=VulnerabilitySource.OSV,
        ),
        Vulnerability(
            id="CVE-2024-9999",
            title="Information Disclosure in data-pkg",
            description="Sensitive data exposure through error messages.",
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            affected_packages=[
                AffectedPackage(
                    name="data-pkg",
                    ecosystem="pypi",
                    affected_versions=[">=1.0.0,<1.5.0"],
                    fixed_versions=["1.5.0"],
                )
            ],
            references=[],
            source=VulnerabilitySource.GITHUB_ADVISORY,
        ),
    ]
