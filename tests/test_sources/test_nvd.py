"""Tests for the NVD vulnerability data source."""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from scan_x.models.vulnerability import Severity, Vulnerability, VulnerabilitySource
from scan_x.sources.nvd import NVDSource

_BASE = "https://services.nvd.nist.gov/rest/json"


# -- Fixtures ----------------------------------------------------------------


@pytest.fixture
def raw_cve() -> dict:
    """Minimal NVD CVE 2.0 response item."""
    return {
        "id": "CVE-2024-1234",
        "descriptions": [
            {"lang": "en", "value": "A critical buffer overflow in libfoo allows RCE."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 9.8,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }
            ],
        },
        "references": [
            {"url": "https://example.com/advisory", "tags": ["Vendor Advisory"]},
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": "cpe:2.3:a:vendor:libfoo:*:*:*:*:*:*:*:*",
                                "versionEndExcluding": "2.0.0",
                            }
                        ]
                    }
                ]
            }
        ],
        "published": "2024-01-10T08:00:00Z",
        "lastModified": "2024-01-20T12:00:00Z",
    }


@pytest.fixture
def nvd_api_response(raw_cve: dict) -> dict:
    """Full NVD API wrapper around a CVE item."""
    return {
        "resultsPerPage": 1,
        "totalResults": 1,
        "vulnerabilities": [{"cve": raw_cve}],
    }


# -- _map_cve_item tests ----------------------------------------------------


class TestMapCveItem:
    def test_basic_mapping(self, raw_cve: dict) -> None:
        vuln = NVDSource._map_cve_item(raw_cve)

        assert vuln.id == "CVE-2024-1234"
        assert "buffer overflow" in vuln.description
        assert vuln.source == VulnerabilitySource.NVD
        assert vuln.source_url == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"

    def test_severity_critical(self, raw_cve: dict) -> None:
        vuln = NVDSource._map_cve_item(raw_cve)
        assert vuln.severity == Severity.CRITICAL
        assert vuln.cvss_score == 9.8
        assert vuln.cvss_vector is not None

    def test_references_mapped(self, raw_cve: dict) -> None:
        vuln = NVDSource._map_cve_item(raw_cve)
        assert len(vuln.references) == 1
        assert vuln.references[0].url == "https://example.com/advisory"
        assert vuln.references[0].type == "Vendor Advisory"

    def test_affected_packages_from_cpe(self, raw_cve: dict) -> None:
        vuln = NVDSource._map_cve_item(raw_cve)
        assert len(vuln.affected_packages) == 1
        pkg = vuln.affected_packages[0]
        assert pkg.name == "libfoo"
        assert pkg.ecosystem == "vendor"

    def test_dates_parsed(self, raw_cve: dict) -> None:
        vuln = NVDSource._map_cve_item(raw_cve)
        assert vuln.published_date is not None
        assert vuln.published_date.year == 2024
        assert vuln.modified_date is not None


# -- Severity mapping --------------------------------------------------------


class TestSeverityMapping:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (10.0, Severity.CRITICAL),
            (9.0, Severity.CRITICAL),
            (8.5, Severity.HIGH),
            (7.0, Severity.HIGH),
            (5.0, Severity.MEDIUM),
            (4.0, Severity.MEDIUM),
            (2.0, Severity.LOW),
            (0.1, Severity.LOW),
            (0.0, Severity.NONE),
        ],
    )
    def test_cvss_to_severity(self, score: float, expected: Severity, raw_cve: dict) -> None:
        raw_cve["metrics"] = {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {"baseScore": score, "vectorString": "CVSS:3.1/AV:N"},
                }
            ]
        }
        vuln = NVDSource._map_cve_item(raw_cve)
        assert vuln.severity == expected

    def test_v30_fallback(self, raw_cve: dict) -> None:
        raw_cve["metrics"] = {
            "cvssMetricV30": [
                {
                    "type": "Primary",
                    "cvssData": {"baseScore": 6.5, "vectorString": "CVSS:3.0/AV:N"},
                }
            ]
        }
        vuln = NVDSource._map_cve_item(raw_cve)
        assert vuln.severity == Severity.MEDIUM

    def test_v2_fallback(self, raw_cve: dict) -> None:
        raw_cve["metrics"] = {
            "cvssMetricV2": [
                {"cvssData": {"baseScore": 8.0, "vectorString": "AV:N/AC:L/Au:N"}}
            ]
        }
        vuln = NVDSource._map_cve_item(raw_cve)
        assert vuln.severity == Severity.HIGH

    def test_no_metrics_defaults_none(self, raw_cve: dict) -> None:
        raw_cve["metrics"] = {}
        vuln = NVDSource._map_cve_item(raw_cve)
        assert vuln.severity == Severity.NONE


# -- API key header ----------------------------------------------------------


class TestApiKeyHeader:
    def test_header_included_when_key_provided(self) -> None:
        source = NVDSource(api_key="my-secret-key")
        assert source._client.headers["apiKey"] == "my-secret-key"

    def test_no_header_when_no_key(self) -> None:
        source = NVDSource()
        assert "apiKey" not in source._client.headers


# -- search with mocked responses -------------------------------------------


class TestNVDSearch:
    @respx.mock
    async def test_search_returns_vulns(self, nvd_api_response: dict) -> None:
        respx.get(f"{_BASE}/cves/2.0").mock(
            return_value=httpx.Response(200, json=nvd_api_response)
        )
        source = NVDSource()
        results = await source.search("libfoo")

        assert len(results) == 1
        assert isinstance(results[0], Vulnerability)
        assert results[0].id == "CVE-2024-1234"

    @respx.mock
    async def test_search_empty_result(self) -> None:
        respx.get(f"{_BASE}/cves/2.0").mock(
            return_value=httpx.Response(200, json={"vulnerabilities": []})
        )
        source = NVDSource()
        results = await source.search("nonexistent")
        assert results == []

    @respx.mock
    async def test_search_http_error(self) -> None:
        respx.get(f"{_BASE}/cves/2.0").mock(
            return_value=httpx.Response(500)
        )
        source = NVDSource()
        results = await source.search("test")
        assert results == []

    @respx.mock
    async def test_get_by_id_found(self, nvd_api_response: dict) -> None:
        respx.get(f"{_BASE}/cves/2.0").mock(
            return_value=httpx.Response(200, json=nvd_api_response)
        )
        source = NVDSource()
        vuln = await source.get_by_id("CVE-2024-1234")
        assert vuln is not None
        assert vuln.id == "CVE-2024-1234"

    @respx.mock
    async def test_get_by_id_not_found(self) -> None:
        respx.get(f"{_BASE}/cves/2.0").mock(
            return_value=httpx.Response(200, json={"vulnerabilities": []})
        )
        source = NVDSource()
        vuln = await source.get_by_id("CVE-0000-0000")
        assert vuln is None

    @respx.mock
    async def test_get_by_package(self, nvd_api_response: dict) -> None:
        respx.get(f"{_BASE}/cves/2.0").mock(
            return_value=httpx.Response(200, json=nvd_api_response)
        )
        source = NVDSource()
        results = await source.get_by_package("libfoo", "npm")
        assert len(results) == 1

    @respx.mock
    async def test_health_check_ok(self) -> None:
        respx.get(f"{_BASE}/cves/2.0").mock(
            return_value=httpx.Response(200, json={})
        )
        source = NVDSource()
        assert await source.health_check() is True

    @respx.mock
    async def test_health_check_fail(self) -> None:
        respx.get(f"{_BASE}/cves/2.0").mock(
            return_value=httpx.Response(503)
        )
        source = NVDSource()
        assert await source.health_check() is False


# -- Caching -----------------------------------------------------------------


class TestNVDCaching:
    @respx.mock
    async def test_search_stores_in_cache(self, nvd_api_response: dict) -> None:
        respx.get(f"{_BASE}/cves/2.0").mock(
            return_value=httpx.Response(200, json=nvd_api_response)
        )
        cache = AsyncMock()
        cache.get = AsyncMock(return_value=None)
        cache.set = AsyncMock()
        source = NVDSource(cache=cache)

        await source.search("libfoo")
        cache.set.assert_called_once()

    async def test_search_returns_cached(self, raw_cve: dict) -> None:
        vuln = NVDSource._map_cve_item(raw_cve)
        cached_data = [vuln.model_dump(mode="json")]

        cache = AsyncMock()
        cache.get = AsyncMock(return_value=cached_data)
        source = NVDSource(cache=cache)

        results = await source.search("libfoo")
        assert len(results) == 1
        assert results[0].id == "CVE-2024-1234"
