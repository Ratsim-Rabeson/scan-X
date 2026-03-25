"""Tests for the OSV vulnerability data source."""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from scan_x.models.vulnerability import Severity, Vulnerability, VulnerabilitySource
from scan_x.sources.osv import OSVSource

_BASE = "https://api.osv.dev/v1"


# -- Fixtures ----------------------------------------------------------------


@pytest.fixture
def osv_source() -> OSVSource:
    return OSVSource()


@pytest.fixture
def osv_source_with_cache() -> OSVSource:
    cache = AsyncMock()
    cache.get = AsyncMock(return_value=None)
    cache.set = AsyncMock()
    return OSVSource(cache=cache)


@pytest.fixture
def raw_osv_vuln() -> dict:
    """Minimal OSV JSON record."""
    return {
        "id": "GHSA-abcd-1234-efgh",
        "aliases": ["CVE-2024-1111"],
        "summary": "XSS in example-lib",
        "details": "A cross-site scripting flaw in example-lib < 2.0.",
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
        "affected": [
            {
                "package": {"name": "example-lib", "ecosystem": "npm"},
                "versions": ["1.0.0", "1.1.0"],
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }
        ],
        "references": [
            {"url": "https://github.com/advisory/GHSA-abcd", "type": "ADVISORY"},
        ],
        "published": "2024-01-15T10:00:00Z",
        "modified": "2024-02-01T12:00:00Z",
    }


# -- _map_vulnerability tests ------------------------------------------------


class TestMapVulnerability:
    def test_basic_mapping(self, raw_osv_vuln: dict) -> None:
        vuln = OSVSource._map_vulnerability(raw_osv_vuln)

        assert vuln.id == "GHSA-abcd-1234-efgh"
        assert vuln.aliases == ["CVE-2024-1111"]
        assert vuln.title == "XSS in example-lib"
        assert "cross-site scripting" in vuln.description
        assert vuln.source == VulnerabilitySource.OSV
        assert vuln.source_url == "https://osv.dev/vulnerability/GHSA-abcd-1234-efgh"

    def test_severity_from_cvss_score(self, raw_osv_vuln: dict) -> None:
        vuln = OSVSource._map_vulnerability(raw_osv_vuln)
        assert vuln.severity == Severity.HIGH
        assert vuln.cvss_score == 7.5

    def test_affected_packages(self, raw_osv_vuln: dict) -> None:
        vuln = OSVSource._map_vulnerability(raw_osv_vuln)
        assert len(vuln.affected_packages) == 1
        pkg = vuln.affected_packages[0]
        assert pkg.name == "example-lib"
        assert pkg.ecosystem == "npm"
        assert "1.0.0" in pkg.affected_versions
        assert "2.0.0" in pkg.fixed_versions

    def test_references_mapped(self, raw_osv_vuln: dict) -> None:
        vuln = OSVSource._map_vulnerability(raw_osv_vuln)
        assert len(vuln.references) == 1
        assert vuln.references[0].type == "ADVISORY"

    def test_dates_parsed(self, raw_osv_vuln: dict) -> None:
        vuln = OSVSource._map_vulnerability(raw_osv_vuln)
        assert vuln.published_date is not None
        assert vuln.published_date.year == 2024
        assert vuln.modified_date is not None

    def test_missing_summary_uses_id_as_title(self) -> None:
        raw = {"id": "OSV-2024-999", "details": "some details"}
        vuln = OSVSource._map_vulnerability(raw)
        assert vuln.title == "OSV-2024-999"

    def test_no_severity_defaults_to_none(self) -> None:
        raw = {"id": "OSV-2024-888", "summary": "Low-impact bug"}
        vuln = OSVSource._map_vulnerability(raw)
        assert vuln.severity == Severity.NONE
        assert vuln.cvss_score is None

    def test_database_specific_severity_fallback(self) -> None:
        raw = {
            "id": "OSV-2024-777",
            "summary": "Test",
            "database_specific": {"severity": "HIGH"},
        }
        vuln = OSVSource._map_vulnerability(raw)
        assert vuln.severity == Severity.HIGH

    def test_database_specific_cvss_score_fallback(self) -> None:
        raw = {
            "id": "OSV-2024-666",
            "summary": "Test",
            "database_specific": {"cvss_score": 9.1},
        }
        vuln = OSVSource._map_vulnerability(raw)
        assert vuln.severity == Severity.CRITICAL
        assert vuln.cvss_score == 9.1


# -- search / get_by_id / get_by_package with mocked HTTP -------------------


class TestOSVSearch:
    @respx.mock
    async def test_search_returns_vulns(self, raw_osv_vuln: dict) -> None:
        respx.post(f"{_BASE}/query").mock(
            return_value=httpx.Response(200, json={"vulns": [raw_osv_vuln]})
        )
        source = OSVSource()
        results = await source.search("example-lib")

        assert len(results) == 1
        assert isinstance(results[0], Vulnerability)
        assert results[0].id == "GHSA-abcd-1234-efgh"

    @respx.mock
    async def test_search_empty_response(self) -> None:
        respx.post(f"{_BASE}/query").mock(
            return_value=httpx.Response(200, json={})
        )
        source = OSVSource()
        results = await source.search("nonexistent")
        assert results == []

    @respx.mock
    async def test_search_respects_limit(self, raw_osv_vuln: dict) -> None:
        many = [raw_osv_vuln.copy() for _ in range(10)]
        respx.post(f"{_BASE}/query").mock(
            return_value=httpx.Response(200, json={"vulns": many})
        )
        source = OSVSource()
        results = await source.search("example", limit=3)
        assert len(results) == 3


class TestOSVGetById:
    @respx.mock
    async def test_get_by_id_found(self, raw_osv_vuln: dict) -> None:
        respx.get(f"{_BASE}/vulns/GHSA-abcd-1234-efgh").mock(
            return_value=httpx.Response(200, json=raw_osv_vuln)
        )
        source = OSVSource()
        vuln = await source.get_by_id("GHSA-abcd-1234-efgh")

        assert vuln is not None
        assert vuln.id == "GHSA-abcd-1234-efgh"

    @respx.mock
    async def test_get_by_id_not_found(self) -> None:
        respx.get(f"{_BASE}/vulns/CVE-9999-0000").mock(
            return_value=httpx.Response(404)
        )
        source = OSVSource()
        vuln = await source.get_by_id("CVE-9999-0000")
        assert vuln is None


class TestOSVGetByPackage:
    @respx.mock
    async def test_get_by_package(self, raw_osv_vuln: dict) -> None:
        respx.post(f"{_BASE}/query").mock(
            return_value=httpx.Response(200, json={"vulns": [raw_osv_vuln]})
        )
        source = OSVSource()
        results = await source.get_by_package("example-lib", "npm")

        assert len(results) == 1
        assert results[0].id == "GHSA-abcd-1234-efgh"

    @respx.mock
    async def test_get_by_package_with_version(self, raw_osv_vuln: dict) -> None:
        respx.post(f"{_BASE}/query").mock(
            return_value=httpx.Response(200, json={"vulns": [raw_osv_vuln]})
        )
        source = OSVSource()
        results = await source.get_by_package("example-lib", "npm", "1.0.0")
        assert len(results) == 1


# -- Error handling ----------------------------------------------------------


class TestOSVErrorHandling:
    @respx.mock
    async def test_search_http_error_returns_empty(self) -> None:
        respx.post(f"{_BASE}/query").mock(
            return_value=httpx.Response(500)
        )
        source = OSVSource()
        results = await source.search("test")
        assert results == []

    @respx.mock
    async def test_get_by_id_http_error_returns_none(self) -> None:
        respx.get(f"{_BASE}/vulns/BAD").mock(
            return_value=httpx.Response(503)
        )
        source = OSVSource()
        assert await source.get_by_id("BAD") is None

    @respx.mock
    async def test_health_check_success(self) -> None:
        respx.get(f"{_BASE}/vulns/CVE-2021-44228").mock(
            return_value=httpx.Response(200, json={})
        )
        source = OSVSource()
        assert await source.health_check() is True

    @respx.mock
    async def test_health_check_failure(self) -> None:
        respx.get(f"{_BASE}/vulns/CVE-2021-44228").mock(
            return_value=httpx.Response(500)
        )
        source = OSVSource()
        assert await source.health_check() is False


# -- Caching -----------------------------------------------------------------


class TestOSVCaching:
    @respx.mock
    async def test_search_stores_in_cache(self, raw_osv_vuln: dict) -> None:
        respx.post(f"{_BASE}/query").mock(
            return_value=httpx.Response(200, json={"vulns": [raw_osv_vuln]})
        )
        cache = AsyncMock()
        cache.get = AsyncMock(return_value=None)
        cache.set = AsyncMock()
        source = OSVSource(cache=cache)

        await source.search("example-lib")
        cache.set.assert_called_once()

    async def test_search_returns_cached_data(self, raw_osv_vuln: dict) -> None:
        vuln = OSVSource._map_vulnerability(raw_osv_vuln)
        cached_data = [vuln.model_dump(mode="json")]

        cache = AsyncMock()
        cache.get = AsyncMock(return_value=cached_data)
        source = OSVSource(cache=cache)

        results = await source.search("example-lib")
        assert len(results) == 1
        assert results[0].id == "GHSA-abcd-1234-efgh"

    async def test_get_by_id_returns_cached_data(self, raw_osv_vuln: dict) -> None:
        vuln = OSVSource._map_vulnerability(raw_osv_vuln)
        cached_data = vuln.model_dump(mode="json")

        cache = AsyncMock()
        cache.get = AsyncMock(return_value=cached_data)
        source = OSVSource(cache=cache)

        result = await source.get_by_id("GHSA-abcd-1234-efgh")
        assert result is not None
        assert result.id == "GHSA-abcd-1234-efgh"
