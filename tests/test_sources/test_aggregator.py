"""Tests for the VulnerabilityAggregator."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from scan_x.models.vulnerability import (
    AffectedPackage,
    Reference,
    Severity,
    Vulnerability,
    VulnerabilitySource,
)
from scan_x.sources.aggregator import (
    VulnerabilityAggregator,
    _canonical_id,
    _deduplicate,
    _merge_vulnerabilities,
)

# -- Helpers -----------------------------------------------------------------


def _make_vuln(
    *,
    vuln_id: str = "CVE-2024-1000",
    aliases: list[str] | None = None,
    title: str = "Test vuln",
    description: str = "A test vulnerability.",
    severity: Severity = Severity.HIGH,
    cvss_score: float | None = 7.5,
    source: VulnerabilitySource = VulnerabilitySource.OSV,
    packages: list[AffectedPackage] | None = None,
    references: list[Reference] | None = None,
    remediation: str | None = None,
) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        aliases=aliases or [],
        title=title,
        description=description,
        severity=severity,
        cvss_score=cvss_score,
        source=source,
        affected_packages=packages or [],
        references=references or [],
        remediation=remediation,
    )


# -- Deduplication tests -----------------------------------------------------


class TestDeduplication:
    def test_same_cve_from_two_sources_merged(self) -> None:
        v1 = _make_vuln(source=VulnerabilitySource.OSV, description="short")
        v2 = _make_vuln(source=VulnerabilitySource.NVD, description="a much longer description")

        result = _deduplicate([v1, v2])
        assert len(result) == 1
        assert result[0].id == "CVE-2024-1000"

    def test_alias_based_dedup(self) -> None:
        v1 = _make_vuln(vuln_id="GHSA-xxxx-yyyy-zzzz", aliases=["CVE-2024-1000"])
        v2 = _make_vuln(vuln_id="CVE-2024-1000")

        result = _deduplicate([v1, v2])
        assert len(result) == 1

    def test_different_cves_not_merged(self) -> None:
        v1 = _make_vuln(vuln_id="CVE-2024-1000")
        v2 = _make_vuln(vuln_id="CVE-2024-2000")

        result = _deduplicate([v1, v2])
        assert len(result) == 2

    def test_canonical_id_prefers_cve(self) -> None:
        v = _make_vuln(vuln_id="GHSA-xxxx", aliases=["CVE-2024-5555"])
        assert _canonical_id(v) == "CVE-2024-5555"

    def test_canonical_id_fallback(self) -> None:
        v = _make_vuln(vuln_id="GHSA-xxxx", aliases=[])
        assert _canonical_id(v) == "GHSA-XXXX"


# -- Merge logic tests -------------------------------------------------------


class TestMerge:
    def test_longest_description_wins(self) -> None:
        v1 = _make_vuln(description="short")
        v2 = _make_vuln(description="a much longer and more detailed description here")

        merged = _merge_vulnerabilities([v1, v2])
        assert merged.description == "a much longer and more detailed description here"

    def test_highest_cvss_wins(self) -> None:
        v1 = _make_vuln(cvss_score=5.0, severity=Severity.MEDIUM)
        v2 = _make_vuln(cvss_score=9.8, severity=Severity.CRITICAL)

        merged = _merge_vulnerabilities([v1, v2])
        assert merged.cvss_score == 9.8

    def test_highest_severity_wins(self) -> None:
        v1 = _make_vuln(severity=Severity.LOW)
        v2 = _make_vuln(severity=Severity.CRITICAL)

        merged = _merge_vulnerabilities([v1, v2])
        assert merged.severity == Severity.CRITICAL

    def test_longest_title_wins(self) -> None:
        v1 = _make_vuln(title="Short")
        v2 = _make_vuln(title="A much more descriptive title for the vulnerability")

        merged = _merge_vulnerabilities([v1, v2])
        assert merged.title == "A much more descriptive title for the vulnerability"

    def test_references_unioned_by_url(self) -> None:
        ref_a = Reference(url="https://a.com")
        ref_b = Reference(url="https://b.com")
        ref_dup = Reference(url="https://a.com", type="FIX")

        v1 = _make_vuln(references=[ref_a])
        v2 = _make_vuln(references=[ref_b, ref_dup])

        merged = _merge_vulnerabilities([v1, v2])
        urls = {r.url for r in merged.references}
        assert urls == {"https://a.com", "https://b.com"}

    def test_affected_packages_merged(self) -> None:
        pkg_a = AffectedPackage(
            name="lib", ecosystem="npm", affected_versions=["1.0"], fixed_versions=["2.0"]
        )
        pkg_b = AffectedPackage(
            name="lib", ecosystem="npm", affected_versions=["1.1"], fixed_versions=["2.1"]
        )

        v1 = _make_vuln(packages=[pkg_a])
        v2 = _make_vuln(packages=[pkg_b])

        merged = _merge_vulnerabilities([v1, v2])
        assert len(merged.affected_packages) == 1
        assert set(merged.affected_packages[0].affected_versions) == {"1.0", "1.1"}
        assert set(merged.affected_packages[0].fixed_versions) == {"2.0", "2.1"}

    def test_aliases_merged_and_primary_id_excluded(self) -> None:
        v1 = _make_vuln(vuln_id="CVE-2024-1000", aliases=["GHSA-aaaa"])
        v2 = _make_vuln(vuln_id="CVE-2024-1000", aliases=["GHSA-bbbb"])

        merged = _merge_vulnerabilities([v1, v2])
        assert "GHSA-aaaa" in merged.aliases
        assert "GHSA-bbbb" in merged.aliases
        assert "CVE-2024-1000" not in merged.aliases

    def test_longest_remediation_wins(self) -> None:
        v1 = _make_vuln(remediation="Upgrade.")
        v2 = _make_vuln(remediation="Upgrade to version 3.0 or later for a full fix.")

        merged = _merge_vulnerabilities([v1, v2])
        assert merged.remediation == "Upgrade to version 3.0 or later for a full fix."

    def test_single_vuln_returned_as_is(self) -> None:
        v = _make_vuln()
        merged = _merge_vulnerabilities([v])
        assert merged is v

    def test_primary_source_nvd_for_cve(self) -> None:
        v1 = _make_vuln(source=VulnerabilitySource.OSV)
        v2 = _make_vuln(source=VulnerabilitySource.NVD)

        merged = _merge_vulnerabilities([v1, v2])
        assert merged.source == VulnerabilitySource.NVD


# -- Aggregator parallel query tests -----------------------------------------


class TestAggregatorSearch:
    @patch("scan_x.sources.aggregator.SnykSource")
    @patch("scan_x.sources.aggregator.GitHubAdvisorySource")
    @patch("scan_x.sources.aggregator.NVDSource")
    @patch("scan_x.sources.aggregator.OSVSource")
    async def test_parallel_search_merges_results(
        self, mock_osv_cls, mock_nvd_cls, mock_gh_cls, mock_snyk_cls
    ) -> None:
        osv_vuln = _make_vuln(
            vuln_id="CVE-2024-1000", source=VulnerabilitySource.OSV, description="short"
        )
        nvd_vuln = _make_vuln(
            vuln_id="CVE-2024-1000", source=VulnerabilitySource.NVD, description="longer desc"
        )

        mock_osv = AsyncMock()
        mock_osv.enabled = True
        mock_osv.source_type = VulnerabilitySource.OSV
        mock_osv.search = AsyncMock(return_value=[osv_vuln])
        mock_osv_cls.return_value = mock_osv

        mock_nvd = AsyncMock()
        mock_nvd.enabled = True
        mock_nvd.source_type = VulnerabilitySource.NVD
        mock_nvd.search = AsyncMock(return_value=[nvd_vuln])
        mock_nvd_cls.return_value = mock_nvd

        mock_gh = AsyncMock()
        mock_gh.enabled = False
        mock_gh.source_type = VulnerabilitySource.GITHUB_ADVISORY
        mock_gh_cls.return_value = mock_gh

        mock_snyk = AsyncMock()
        mock_snyk.enabled = False
        mock_snyk.source_type = VulnerabilitySource.SNYK
        mock_snyk_cls.return_value = mock_snyk

        agg = VulnerabilityAggregator()
        results = await agg.search("test")

        assert len(results) == 1
        assert results[0].description == "longer desc"

    @patch("scan_x.sources.aggregator.SnykSource")
    @patch("scan_x.sources.aggregator.GitHubAdvisorySource")
    @patch("scan_x.sources.aggregator.NVDSource")
    @patch("scan_x.sources.aggregator.OSVSource")
    async def test_source_failure_does_not_crash(
        self, mock_osv_cls, mock_nvd_cls, mock_gh_cls, mock_snyk_cls
    ) -> None:
        good_vuln = _make_vuln(vuln_id="CVE-2024-9999", source=VulnerabilitySource.NVD)

        mock_osv = AsyncMock()
        mock_osv.enabled = True
        mock_osv.source_type = VulnerabilitySource.OSV
        mock_osv.search = AsyncMock(side_effect=RuntimeError("network down"))
        mock_osv_cls.return_value = mock_osv

        mock_nvd = AsyncMock()
        mock_nvd.enabled = True
        mock_nvd.source_type = VulnerabilitySource.NVD
        mock_nvd.search = AsyncMock(return_value=[good_vuln])
        mock_nvd_cls.return_value = mock_nvd

        mock_gh = AsyncMock()
        mock_gh.enabled = False
        mock_gh.source_type = VulnerabilitySource.GITHUB_ADVISORY
        mock_gh_cls.return_value = mock_gh

        mock_snyk = AsyncMock()
        mock_snyk.enabled = False
        mock_snyk.source_type = VulnerabilitySource.SNYK
        mock_snyk_cls.return_value = mock_snyk

        agg = VulnerabilityAggregator()
        results = await agg.search("test")

        assert len(results) == 1
        assert results[0].id == "CVE-2024-9999"


class TestAggregatorHealthCheck:
    @patch("scan_x.sources.aggregator.SnykSource")
    @patch("scan_x.sources.aggregator.GitHubAdvisorySource")
    @patch("scan_x.sources.aggregator.NVDSource")
    @patch("scan_x.sources.aggregator.OSVSource")
    async def test_health_check(
        self, mock_osv_cls, mock_nvd_cls, mock_gh_cls, mock_snyk_cls
    ) -> None:
        mock_osv = AsyncMock()
        mock_osv.enabled = True
        mock_osv.source_type = VulnerabilitySource.OSV
        mock_osv.health_check = AsyncMock(return_value=True)
        mock_osv_cls.return_value = mock_osv

        mock_nvd = AsyncMock()
        mock_nvd.enabled = True
        mock_nvd.source_type = VulnerabilitySource.NVD
        mock_nvd.health_check = AsyncMock(return_value=False)
        mock_nvd_cls.return_value = mock_nvd

        mock_gh = AsyncMock()
        mock_gh.enabled = False
        mock_gh.source_type = VulnerabilitySource.GITHUB_ADVISORY
        mock_gh.health_check = AsyncMock(return_value=False)
        mock_gh_cls.return_value = mock_gh

        mock_snyk = AsyncMock()
        mock_snyk.enabled = False
        mock_snyk.source_type = VulnerabilitySource.SNYK
        mock_snyk.health_check = AsyncMock(return_value=False)
        mock_snyk_cls.return_value = mock_snyk

        agg = VulnerabilityAggregator()
        result = await agg.health_check()

        assert result["OSV"] is True
        assert result["NVD"] is False
