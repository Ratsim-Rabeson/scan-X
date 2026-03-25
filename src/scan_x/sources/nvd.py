"""NVD (National Vulnerability Database) data source."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any

import httpx

from scan_x.models.vulnerability import (
    AffectedPackage,
    Reference,
    Severity,
    Vulnerability,
    VulnerabilitySource,
)
from scan_x.sources.base import VulnerabilitySourceBase

if TYPE_CHECKING:
    from scan_x.utils.cache import ResponseCache
    from scan_x.utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

_BASE_URL = "https://services.nvd.nist.gov/rest/json"
_TIMEOUT = 30.0


class NVDSource(VulnerabilitySourceBase):
    """Client for the `NVD 2.0 <https://nvd.nist.gov/developers>`_ API."""

    source_type = VulnerabilitySource.NVD

    def __init__(
        self,
        api_key: str | None = None,
        cache: ResponseCache | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        super().__init__(api_key=api_key)
        self._cache = cache
        self._rate_limiter = rate_limiter

        headers: dict[str, str] = {}
        if api_key:
            headers["apiKey"] = api_key

        self._client = httpx.AsyncClient(
            base_url=_BASE_URL,
            timeout=_TIMEOUT,
            headers=headers,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def search(self, query: str, limit: int = 20) -> list[Vulnerability]:
        """Keyword search via ``/cves/2.0?keywordSearch=``."""
        cache_key = f"search:{query}:{limit}"
        cached = await self._cache_get(cache_key)
        if cached is not None:
            return [Vulnerability(**v) for v in cached]

        params: dict[str, str | int] = {
            "keywordSearch": query,
            "resultsPerPage": limit,
        }
        data = await self._get("/cves/2.0", params=params)
        if data is None:
            return []

        vulns = [
            self._map_cve_item(item["cve"])
            for item in data.get("vulnerabilities", [])
            if "cve" in item
        ]
        await self._cache_set(cache_key, [v.model_dump(mode="json") for v in vulns])
        return vulns

    async def get_by_id(self, vuln_id: str) -> Vulnerability | None:
        """Fetch a single CVE by its ID."""
        cache_key = f"id:{vuln_id}"
        cached = await self._cache_get(cache_key)
        if cached is not None:
            return Vulnerability(**cached)

        data = await self._get("/cves/2.0", params={"cveId": vuln_id})
        if data is None:
            return None

        items = data.get("vulnerabilities", [])
        if not items:
            return None

        cve = items[0].get("cve")
        if cve is None:
            return None

        vuln = self._map_cve_item(cve)
        await self._cache_set(cache_key, vuln.model_dump(mode="json"))
        return vuln

    async def get_by_package(
        self,
        package_name: str,
        ecosystem: str,
        version: str | None = None,
    ) -> list[Vulnerability]:
        """Search NVD by package keyword (NVD has no native package query)."""
        query = f"{package_name} {ecosystem}"
        if version:
            query += f" {version}"

        cache_key = f"pkg:{ecosystem}:{package_name}:{version}"
        cached = await self._cache_get(cache_key)
        if cached is not None:
            return [Vulnerability(**v) for v in cached]

        params: dict[str, str | int] = {
            "keywordSearch": query,
            "resultsPerPage": 50,
        }
        data = await self._get("/cves/2.0", params=params)
        if data is None:
            return []

        vulns = [
            self._map_cve_item(item["cve"])
            for item in data.get("vulnerabilities", [])
            if "cve" in item
        ]
        await self._cache_set(cache_key, [v.model_dump(mode="json") for v in vulns])
        return vulns

    async def health_check(self) -> bool:
        """Return *True* if the NVD API is reachable."""
        try:
            resp = await self._client.get(
                "/cves/2.0",
                params={"resultsPerPage": 1},
            )
            return resp.status_code == 200  # noqa: PLR2004
        except httpx.HTTPError:
            return False

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    async def _get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        await self._acquire_rate_limit()
        try:
            resp = await self._client.get(path, params=params)
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]
        except httpx.HTTPError as exc:
            logger.warning("NVD GET %s failed: %s", path, exc)
            return None

    # ------------------------------------------------------------------
    # Mapping helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _map_cve_item(cve: dict[str, Any]) -> Vulnerability:
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        description = _english_description(descriptions)
        title = description[:120] + "…" if len(description) > 120 else description

        severity, cvss_score, cvss_vector = _extract_cvss(cve.get("metrics", {}))
        references = _map_references(cve.get("references", []))
        affected_packages = _map_configurations(cve.get("configurations", []))

        published = _parse_iso(cve.get("published"))
        modified = _parse_iso(cve.get("lastModified"))

        return Vulnerability(
            id=cve_id,
            aliases=[],
            title=title or cve_id,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_packages=affected_packages,
            references=references,
            source=VulnerabilitySource.NVD,
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            published_date=published,
            modified_date=modified,
        )

    # ------------------------------------------------------------------
    # Cache / rate-limit helpers
    # ------------------------------------------------------------------

    async def _cache_get(self, key: str) -> Any | None:
        if self._cache is None:
            return None
        return await self._cache.get("nvd", key)

    async def _cache_set(self, key: str, data: Any) -> None:
        if self._cache is None:
            return
        await self._cache.set("nvd", key, data)

    async def _acquire_rate_limit(self) -> None:
        if self._rate_limiter is not None:
            await self._rate_limiter.acquire()


# ------------------------------------------------------------------
# Module-level mapping utilities
# ------------------------------------------------------------------


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:  # noqa: PLR2004
        return Severity.CRITICAL
    if score >= 7.0:  # noqa: PLR2004
        return Severity.HIGH
    if score >= 4.0:  # noqa: PLR2004
        return Severity.MEDIUM
    if score >= 0.1:  # noqa: PLR2004
        return Severity.LOW
    return Severity.NONE


def _extract_cvss(
    metrics: dict[str, Any],
) -> tuple[Severity, float | None, str | None]:
    """Return ``(severity, score, vector)`` from NVD metrics.

    Prefers CVSS v3.1, falls back to v3.0 then v2.0.
    """
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key, [])
        if not metric_list:
            continue
        # Use the primary metric (type = "Primary") if available.
        primary = next(
            (m for m in metric_list if m.get("type") == "Primary"),
            metric_list[0],
        )
        cvss_data = primary.get("cvssData", {})
        score = cvss_data.get("baseScore")
        vector = cvss_data.get("vectorString")
        if score is not None:
            return _cvss_to_severity(float(score)), float(score), vector

    # Fallback to CVSS v2
    for entry in metrics.get("cvssMetricV2", []):
        cvss_data = entry.get("cvssData", {})
        score = cvss_data.get("baseScore")
        vector = cvss_data.get("vectorString")
        if score is not None:
            return _cvss_to_severity(float(score)), float(score), vector

    return Severity.NONE, None, None


def _english_description(descriptions: list[dict[str, str]]) -> str:
    for desc in descriptions:
        if desc.get("lang", "").startswith("en"):
            return desc.get("value", "")
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


def _map_references(refs: list[dict[str, Any]]) -> list[Reference]:
    results: list[Reference] = []
    for ref in refs:
        url = ref.get("url")
        if not url:
            continue
        tags = ref.get("tags", [])
        ref_type = tags[0] if tags else "WEB"
        results.append(Reference(url=url, type=ref_type))
    return results


def _map_configurations(configs: list[dict[str, Any]]) -> list[AffectedPackage]:
    """Best-effort extraction of affected packages from NVD CPE matches."""
    packages: list[AffectedPackage] = []
    seen: set[str] = set()

    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) < 5:  # noqa: PLR2004
                    continue

                vendor = parts[3]
                product = parts[4]
                key = f"{vendor}/{product}"
                if key in seen:
                    continue
                seen.add(key)

                affected_versions: list[str] = []
                version_start = match.get(
                    "versionStartIncluding"
                ) or match.get("versionStartExcluding")
                version_end = match.get(
                    "versionEndIncluding"
                ) or match.get("versionEndExcluding")
                if version_start and version_end:
                    affected_versions.append(f"{version_start} - {version_end}")
                elif version_start:
                    affected_versions.append(f">= {version_start}")
                elif version_end:
                    affected_versions.append(f"<= {version_end}")

                packages.append(
                    AffectedPackage(
                        name=product,
                        ecosystem=vendor,
                        affected_versions=affected_versions,
                    )
                )
    return packages


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
