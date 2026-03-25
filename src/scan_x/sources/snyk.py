"""Snyk vulnerability database client."""

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

_REST_BASE = "https://api.snyk.io/rest"
_V1_BASE = "https://snyk.io/api/v1"
_API_VERSION = "2024-06-21"

# Snyk ecosystem slugs used in their v1 API paths
_ECOSYSTEM_SLUGS: dict[str, str] = {
    "npm": "npm",
    "pypi": "pip",
    "pip": "pip",
    "python": "pip",
    "maven": "maven",
    "nuget": "nuget",
    "dotnet": "nuget",
    "go": "golang",
    "golang": "golang",
    "rubygems": "rubygems",
    "ruby": "rubygems",
    "rust": "cocoapods",  # Snyk doesn't have a dedicated Rust slug; fallback
    "composer": "composer",
    "php": "composer",
}

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": Severity.NONE,
}


class SnykSource(VulnerabilitySourceBase):
    """Fetch vulnerability data from Snyk."""

    source_type = VulnerabilitySource.SNYK

    def __init__(
        self,
        api_key: str | None = None,
        cache: ResponseCache | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        super().__init__(api_key=api_key)
        self._cache = cache
        self._rate_limiter = rate_limiter
        if not api_key:
            self._enabled = False
            logger.warning("SnykSource: no API key — source disabled")

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _v1_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"token {self.api_key}",
            "Content-Type": "application/json",
        }

    def _rest_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"token {self.api_key}",
            "Content-Type": "application/vnd.api+json",
        }

    async def _get_json(self, url: str, *, rest: bool = False) -> Any:
        if self._rate_limiter:
            await self._rate_limiter.acquire()

        headers = self._rest_headers() if rest else self._v1_headers()
        params: dict[str, str] = {}
        if rest:
            params["version"] = _API_VERSION

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            return resp.json()

    async def _post_json(self, url: str, payload: dict[str, Any]) -> Any:
        if self._rate_limiter:
            await self._rate_limiter.acquire()

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=self._v1_headers(), json=payload)
            resp.raise_for_status()
            return resp.json()

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _map_severity(raw: str | None) -> Severity:
        if not raw:
            return Severity.NONE
        return _SEVERITY_MAP.get(raw.lower(), Severity.NONE)

    def _parse_vuln(self, data: dict[str, Any]) -> Vulnerability:
        """Parse a single vulnerability object from the Snyk v1 API."""
        vuln_id: str = data.get("id", "")
        title: str = data.get("title", "")
        description: str = data.get("description", "")
        severity_raw: str = data.get("severity", "")
        cvss_score: float | None = data.get("cvssScore")
        cvss_vector: str | None = data.get("CVSSv3")

        identifiers = data.get("identifiers", {})
        cve_list: list[str] = identifiers.get("CVE", [])
        cwe_list: list[str] = identifiers.get("CWE", [])

        # Use the first CVE as primary ID when available
        primary_id = cve_list[0] if cve_list else vuln_id
        aliases = cve_list[1:] + [vuln_id] if cve_list and primary_id == cve_list[0] else cve_list

        # References
        refs: list[Reference] = []
        for ref_url in data.get("references", []):
            if isinstance(ref_url, dict):
                refs.append(Reference(url=ref_url.get("url", ""), type="ADVISORY"))
            elif isinstance(ref_url, str):
                refs.append(Reference(url=ref_url, type="ADVISORY"))
        if vuln_id:
            refs.append(
                Reference(url=f"https://security.snyk.io/vuln/{vuln_id}", type="ADVISORY")
            )

        # Affected packages
        affected: list[AffectedPackage] = []
        pkg_name: str = data.get("packageName", "")
        pkg_ecosystem: str = data.get("language", data.get("packageManager", ""))
        version_ranges: list[str] = data.get("semver", {}).get("vulnerable", [])
        if isinstance(version_ranges, str):
            version_ranges = [version_ranges]

        patches: list[str] = []
        for patch in data.get("patches", []):
            if isinstance(patch, dict) and patch.get("version"):
                patches.append(patch["version"])

        if pkg_name:
            affected.append(
                AffectedPackage(
                    name=pkg_name,
                    ecosystem=pkg_ecosystem.lower() if pkg_ecosystem else "unknown",
                    affected_versions=version_ranges,
                    fixed_versions=patches,
                )
            )

        remediation: str | None = None
        if data.get("fixedIn"):
            fixed_versions = data["fixedIn"]
            if isinstance(fixed_versions, list) and fixed_versions:
                remediation = f"Upgrade to {', '.join(str(v) for v in fixed_versions)}"
                if affected:
                    affected[0].fixed_versions = [str(v) for v in fixed_versions]

        # Build CWE note
        if cwe_list:
            cwe_note = "Related CWEs: " + ", ".join(cwe_list)
            description = f"{description}\n\n{cwe_note}" if description else cwe_note

        return Vulnerability(
            id=primary_id,
            aliases=aliases,
            title=title,
            description=description,
            severity=self._map_severity(severity_raw),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_packages=affected,
            references=refs,
            source=VulnerabilitySource.SNYK,
            source_url=f"https://security.snyk.io/vuln/{vuln_id}" if vuln_id else None,
            published_date=self._parse_datetime(data.get("publicationTime")),
            modified_date=self._parse_datetime(data.get("modificationTime")),
            remediation=remediation,
        )

    def _parse_test_response(self, data: dict[str, Any]) -> list[Vulnerability]:
        """Parse the response from the Snyk test endpoint."""
        issues = data.get("issues", {})
        vulns_data: list[dict[str, Any]] = issues.get("vulnerabilities", [])
        return [self._parse_vuln(v) for v in vulns_data]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def search(self, query: str, limit: int = 20) -> list[Vulnerability]:
        if not self._enabled:
            return []

        cache_key = f"search:{query}:{limit}"
        if self._cache:
            cached = await self._cache.get("snyk", cache_key)
            if cached is not None:
                return [Vulnerability.model_validate(v) for v in cached]

        # Snyk has no free-text search endpoint.  We attempt a vuln-by-id
        # lookup when the query looks like a Snyk ID or CVE, and fall back to
        # a package-based lookup otherwise.
        results: list[Vulnerability] = []
        try:
            if query.upper().startswith("SNYK-") or query.upper().startswith("CVE-"):
                vuln = await self.get_by_id(query)
                if vuln:
                    results = [vuln]
            else:
                # Treat query as "ecosystem/package" or just "package"
                parts = query.split("/", maxsplit=1)
                if len(parts) == 2:
                    ecosystem, package = parts
                else:
                    ecosystem, package = "npm", parts[0]
                results = await self.get_by_package(package, ecosystem)
                results = results[:limit]
        except httpx.HTTPError:
            logger.exception("Snyk search failed for query=%r", query)

        if self._cache and results:
            await self._cache.set("snyk", cache_key, [v.model_dump(mode="json") for v in results])
        return results

    async def get_by_id(self, vuln_id: str) -> Vulnerability | None:
        if not self._enabled:
            return None

        cache_key = f"id:{vuln_id}"
        if self._cache:
            cached = await self._cache.get("snyk", cache_key)
            if cached is not None:
                return Vulnerability.model_validate(cached)

        try:
            # Snyk v1 vuln endpoint
            url = f"{_V1_BASE}/vuln/{vuln_id}"
            data: dict[str, Any] = await self._get_json(url)
            result = self._parse_vuln(data)
            if self._cache:
                await self._cache.set("snyk", cache_key, result.model_dump(mode="json"))
            return result
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                logger.debug("Snyk vuln not found: %s", vuln_id)
            else:
                logger.exception("Snyk get_by_id failed for id=%r", vuln_id)
        except httpx.HTTPError:
            logger.exception("Snyk get_by_id failed for id=%r", vuln_id)

        return None

    async def get_by_package(
        self, package_name: str, ecosystem: str, version: str | None = None
    ) -> list[Vulnerability]:
        if not self._enabled:
            return []

        cache_key = f"pkg:{ecosystem}:{package_name}:{version or '*'}"
        if self._cache:
            cached = await self._cache.get("snyk", cache_key)
            if cached is not None:
                return [Vulnerability.model_validate(v) for v in cached]

        slug = _ECOSYSTEM_SLUGS.get(ecosystem.lower(), ecosystem.lower())
        target = f"{package_name}@{version}" if version else package_name

        try:
            url = f"{_V1_BASE}/test/{slug}"
            payload: dict[str, Any] = {
                "encoding": "plain",
                "files": {"target": {"contents": target}},
            }
            data: dict[str, Any] = await self._post_json(url, payload)
            results = self._parse_test_response(data)

            if self._cache:
                await self._cache.set(
                    "snyk", cache_key, [v.model_dump(mode="json") for v in results]
                )
            return results
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                logger.debug("Snyk package not found: %s/%s", ecosystem, package_name)
            else:
                logger.exception(
                    "Snyk get_by_package failed for %s/%s", ecosystem, package_name
                )
        except httpx.HTTPError:
            logger.exception("Snyk get_by_package failed for %s/%s", ecosystem, package_name)

        return []

    async def health_check(self) -> bool:
        if not self._enabled:
            return False
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{_REST_BASE}/self",
                    headers=self._rest_headers(),
                    params={"version": _API_VERSION},
                )
                return resp.status_code == 200
        except httpx.HTTPError:
            logger.exception("Snyk health check failed")
            return False
