"""OSV.dev vulnerability data source."""

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

_BASE_URL = "https://api.osv.dev/v1"
_TIMEOUT = 30.0


class OSVSource(VulnerabilitySourceBase):
    """Client for the `OSV.dev <https://osv.dev/>`_ API."""

    source_type = VulnerabilitySource.OSV

    def __init__(
        self,
        cache: ResponseCache | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        super().__init__(api_key=None)
        self._cache = cache
        self._rate_limiter = rate_limiter
        self._client = httpx.AsyncClient(base_url=_BASE_URL, timeout=_TIMEOUT)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def search(self, query: str, limit: int = 20) -> list[Vulnerability]:
        """Search OSV by package keyword."""
        cache_key = f"search:{query}:{limit}"
        cached = await self._cache_get(cache_key)
        if cached is not None:
            return [Vulnerability(**v) for v in cached]

        payload: dict[str, Any] = {"query": query}
        data = await self._post("/query", payload)
        if data is None:
            return []

        vulns = [self._map_vulnerability(v) for v in data.get("vulns", [])][:limit]
        await self._cache_set(cache_key, [v.model_dump(mode="json") for v in vulns])
        return vulns

    async def get_by_id(self, vuln_id: str) -> Vulnerability | None:
        """Fetch a single vulnerability by its OSV / CVE ID."""
        cache_key = f"id:{vuln_id}"
        cached = await self._cache_get(cache_key)
        if cached is not None:
            return Vulnerability(**cached)

        data = await self._get(f"/vulns/{vuln_id}")
        if data is None:
            return None

        vuln = self._map_vulnerability(data)
        await self._cache_set(cache_key, vuln.model_dump(mode="json"))
        return vuln

    async def get_by_package(
        self,
        package_name: str,
        ecosystem: str,
        version: str | None = None,
    ) -> list[Vulnerability]:
        """Query OSV for vulnerabilities affecting a package."""
        cache_key = f"pkg:{ecosystem}:{package_name}:{version}"
        cached = await self._cache_get(cache_key)
        if cached is not None:
            return [Vulnerability(**v) for v in cached]

        package_obj: dict[str, str] = {
            "name": package_name,
            "ecosystem": ecosystem,
        }
        payload: dict[str, Any] = {"package": package_obj}
        if version:
            payload["package"]["version"] = version

        data = await self._post("/query", payload)
        if data is None:
            return []

        vulns = [self._map_vulnerability(v) for v in data.get("vulns", [])]
        await self._cache_set(cache_key, [v.model_dump(mode="json") for v in vulns])
        return vulns

    async def health_check(self) -> bool:
        """Return *True* if the OSV API is reachable."""
        try:
            resp = await self._client.get("/vulns/CVE-2021-44228")
            return resp.status_code == 200  # noqa: PLR2004
        except httpx.HTTPError:
            return False

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        await self._acquire_rate_limit()
        try:
            resp = await self._client.post(path, json=payload)
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]
        except httpx.HTTPError as exc:
            logger.warning("OSV POST %s failed: %s", path, exc)
            return None

    async def _get(self, path: str) -> dict[str, Any] | None:
        await self._acquire_rate_limit()
        try:
            resp = await self._client.get(path)
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]
        except httpx.HTTPError as exc:
            logger.warning("OSV GET %s failed: %s", path, exc)
            return None

    # ------------------------------------------------------------------
    # Mapping helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _map_vulnerability(raw: dict[str, Any]) -> Vulnerability:
        vuln_id = raw.get("id", "")
        aliases = raw.get("aliases", [])
        summary = raw.get("summary", "")
        details = raw.get("details", "")

        severity, cvss_score, cvss_vector = _extract_severity(raw)
        affected_packages = _map_affected(raw.get("affected", []))
        references = _map_references(raw.get("references", []))

        published = _parse_iso(raw.get("published"))
        modified = _parse_iso(raw.get("modified"))
        withdrawn = _parse_iso(raw.get("withdrawn"))

        return Vulnerability(
            id=vuln_id,
            aliases=aliases,
            title=summary or vuln_id,
            description=details or summary or "",
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_packages=affected_packages,
            references=references,
            source=VulnerabilitySource.OSV,
            source_url=f"https://osv.dev/vulnerability/{vuln_id}",
            published_date=published,
            modified_date=modified,
            withdrawn_date=withdrawn,
        )

    # ------------------------------------------------------------------
    # Cache / rate-limit helpers
    # ------------------------------------------------------------------

    async def _cache_get(self, key: str) -> Any | None:
        if self._cache is None:
            return None
        return await self._cache.get("osv", key)

    async def _cache_set(self, key: str, data: Any) -> None:
        if self._cache is None:
            return
        await self._cache.set("osv", key, data)

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


def _extract_severity(
    raw: dict[str, Any],
) -> tuple[Severity, float | None, str | None]:
    """Return ``(severity, cvss_score, cvss_vector)`` from an OSV record."""
    for entry in raw.get("severity", []):
        if entry.get("type") == "CVSS_V3":
            vector = entry.get("score", "")
            score = _parse_cvss_score(vector)
            if score is not None:
                return _cvss_to_severity(score), score, vector

    # Fallback: inspect database_specific for a CVSS score.
    db_specific = raw.get("database_specific", {})
    score = db_specific.get("cvss_score") or db_specific.get("severity_score")
    if isinstance(score, (int, float)):
        return _cvss_to_severity(float(score)), float(score), None

    severity_str = db_specific.get("severity", "").upper()
    if severity_str in Severity.__members__:
        return Severity(severity_str), None, None

    return Severity.NONE, None, None


def _parse_cvss_score(vector: str) -> float | None:
    """Extract the base score from a CVSS v3 vector string if embedded, or
    attempt to read the *score* field that some OSV entries provide directly as
    a float-like string."""
    if not vector:
        return None
    try:
        return float(vector)
    except ValueError:
        pass
    # Some vectors are just the vector string; we can't compute a score from
    # the vector alone without a CVSS library, so return None.
    return None


def _map_affected(affected_list: list[dict[str, Any]]) -> list[AffectedPackage]:
    packages: list[AffectedPackage] = []
    for entry in affected_list:
        pkg = entry.get("package", {})
        name = pkg.get("name", "")
        ecosystem = pkg.get("ecosystem", "")
        if not name:
            continue

        affected_versions: list[str] = entry.get("versions", [])
        fixed_versions: list[str] = []
        for rng in entry.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed_versions.append(event["fixed"])

        packages.append(
            AffectedPackage(
                name=name,
                ecosystem=ecosystem,
                affected_versions=affected_versions,
                fixed_versions=fixed_versions,
            )
        )
    return packages


def _map_references(refs: list[dict[str, Any]]) -> list[Reference]:
    return [
        Reference(url=r["url"], type=r.get("type", "WEB"))
        for r in refs
        if r.get("url")
    ]


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
