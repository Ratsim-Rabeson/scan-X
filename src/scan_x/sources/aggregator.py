"""Multi-source vulnerability aggregator.

Queries multiple vulnerability sources in parallel, deduplicates results,
and merges records that share a CVE ID or alias.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scan_x.config import ScanXConfig, get_default_config
from scan_x.models.vulnerability import (
    AffectedPackage,
    Reference,
    Vulnerability,
    VulnerabilitySource,
)
from scan_x.sources.github_advisory import GitHubAdvisorySource
from scan_x.sources.nvd import NVDSource
from scan_x.sources.osv import OSVSource
from scan_x.sources.snyk import SnykSource
from scan_x.utils.cache import ResponseCache
from scan_x.utils.rate_limiter import RateLimiterRegistry

if TYPE_CHECKING:
    from datetime import datetime

    from scan_x.sources.base import VulnerabilitySourceBase

logger = logging.getLogger(__name__)

# Preferred source ordering when choosing the "primary" source for a merged
# vulnerability.  NVD is authoritative for CVE-prefixed IDs; OSV for the rest.
_CVE_SOURCE_PRIORITY: list[VulnerabilitySource] = [
    VulnerabilitySource.NVD,
    VulnerabilitySource.GITHUB_ADVISORY,
    VulnerabilitySource.SNYK,
    VulnerabilitySource.OSV,
]
_DEFAULT_SOURCE_PRIORITY: list[VulnerabilitySource] = [
    VulnerabilitySource.OSV,
    VulnerabilitySource.NVD,
    VulnerabilitySource.GITHUB_ADVISORY,
    VulnerabilitySource.SNYK,
]


def _pick_primary_source(
    vuln_id: str,
    sources: set[VulnerabilitySource],
) -> VulnerabilitySource:
    """Return the most authoritative source for *vuln_id*."""
    priority = _CVE_SOURCE_PRIORITY if vuln_id.startswith("CVE-") else _DEFAULT_SOURCE_PRIORITY
    for src in priority:
        if src in sources:
            return src
    return next(iter(sources))


def _merge_vulnerabilities(vulns: list[Vulnerability]) -> Vulnerability:
    """Merge several :class:`Vulnerability` records into the richest one."""
    assert vulns  # noqa: S101

    if len(vulns) == 1:
        return vulns[0]

    # Collect contributing sources for primary-source selection.
    contributing_sources: set[VulnerabilitySource] = {v.source for v in vulns}

    # --- merge simple scalar fields -----------------------------------------
    best_description = max(vulns, key=lambda v: len(v.description)).description
    best_title = max(vulns, key=lambda v: len(v.title)).title
    best_cvss = max(
        (v.cvss_score for v in vulns if v.cvss_score is not None),
        default=None,
    )
    best_cvss_vector = next(
        (v.cvss_vector for v in vulns if v.cvss_vector and v.cvss_score == best_cvss),
        None,
    )

    # Earliest published date.
    pub_dates = [v.published_date for v in vulns if v.published_date is not None]
    earliest_published: datetime | None = min(pub_dates) if pub_dates else None

    # Latest modified date.
    mod_dates = [v.modified_date for v in vulns if v.modified_date is not None]
    latest_modified: datetime | None = max(mod_dates) if mod_dates else None

    # Most specific remediation (longest text).
    remediations = [v.remediation for v in vulns if v.remediation]
    best_remediation: str | None = max(remediations, key=len) if remediations else None

    # Highest severity.
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    best_severity = min(vulns, key=lambda v: severity_order.index(v.severity)).severity

    # --- merge collections ---------------------------------------------------
    # Affected packages – union keyed on (name, ecosystem).
    seen_packages: dict[tuple[str, str], AffectedPackage] = {}
    for v in vulns:
        for pkg in v.affected_packages:
            key = (pkg.name, pkg.ecosystem)
            if key not in seen_packages:
                seen_packages[key] = pkg.model_copy(deep=True)
            else:
                existing = seen_packages[key]
                merged_affected = sorted(
                    set(existing.affected_versions) | set(pkg.affected_versions),
                )
                merged_fixed = sorted(
                    set(existing.fixed_versions) | set(pkg.fixed_versions),
                )
                seen_packages[key] = existing.model_copy(
                    update={
                        "affected_versions": merged_affected,
                        "fixed_versions": merged_fixed,
                    },
                )

    # References – union by URL.
    seen_urls: set[str] = set()
    merged_refs: list[Reference] = []
    for v in vulns:
        for ref in v.references:
            if ref.url not in seen_urls:
                seen_urls.add(ref.url)
                merged_refs.append(ref)

    # Aliases – union.
    all_aliases: set[str] = set()
    for v in vulns:
        all_aliases.update(v.aliases)
    # Exclude the primary id from aliases.
    primary_id = vulns[0].id
    all_aliases.discard(primary_id)

    primary_source = _pick_primary_source(primary_id, contributing_sources)
    source_url = next(
        (v.source_url for v in vulns if v.source == primary_source and v.source_url),
        vulns[0].source_url,
    )

    return Vulnerability(
        id=primary_id,
        aliases=sorted(all_aliases),
        title=best_title,
        description=best_description,
        severity=best_severity,
        cvss_score=best_cvss,
        cvss_vector=best_cvss_vector,
        affected_packages=list(seen_packages.values()),
        references=merged_refs,
        source=primary_source,
        source_url=source_url,
        published_date=earliest_published,
        modified_date=latest_modified,
        withdrawn_date=next(
            (v.withdrawn_date for v in vulns if v.withdrawn_date is not None),
            None,
        ),
        remediation=best_remediation,
    )


def _canonical_id(vuln: Vulnerability) -> str:
    """Return the CVE ID if present, otherwise the vulnerability's own id."""
    vid = vuln.id.upper()
    if vid.startswith("CVE-"):
        return vid
    for alias in vuln.aliases:
        if alias.upper().startswith("CVE-"):
            return alias.upper()
    return vid


def _deduplicate(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Group by canonical ID and merge duplicates."""
    groups: dict[str, list[Vulnerability]] = {}
    for v in vulns:
        cid = _canonical_id(v)
        groups.setdefault(cid, []).append(v)
    return [_merge_vulnerabilities(group) for group in groups.values()]


class VulnerabilityAggregator:
    """Queries multiple vulnerability sources and merges results."""

    def __init__(self, config: ScanXConfig | None = None) -> None:
        cfg = config or get_default_config()

        self._cache = ResponseCache(
            cache_dir=cfg.cache.directory if cfg.cache.enabled else None,
            ttl_hours=cfg.cache.ttl_hours,
        )
        self._rate_limiters = RateLimiterRegistry()

        self._sources: list[VulnerabilitySourceBase] = []

        # OSV – no API key needed.
        osv = OSVSource(
            cache=self._cache,
            rate_limiter=self._rate_limiters.get("osv"),
        )
        osv.enabled = cfg.sources.osv_enabled
        self._sources.append(osv)

        # NVD – optional API key unlocks higher rate limits.
        nvd = NVDSource(
            api_key=cfg.api_keys.nvd,
            cache=self._cache,
            rate_limiter=self._rate_limiters.get(
                "nvd_keyed" if cfg.api_keys.nvd else "nvd",
            ),
        )
        nvd.enabled = cfg.sources.nvd_enabled
        self._sources.append(nvd)

        # GitHub Advisory – requires API key.
        github = GitHubAdvisorySource(
            api_key=cfg.api_keys.github,
            cache=self._cache,
            rate_limiter=self._rate_limiters.get("github"),
        )
        github.enabled = cfg.sources.github_enabled and github.enabled
        self._sources.append(github)

        # Snyk – requires API key.
        snyk = SnykSource(
            api_key=cfg.api_keys.snyk,
            cache=self._cache,
            rate_limiter=self._rate_limiters.get("snyk"),
        )
        snyk.enabled = cfg.sources.snyk_enabled and snyk.enabled
        self._sources.append(snyk)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def enabled_sources(self) -> list[VulnerabilitySourceBase]:
        """Return only enabled sources with valid config."""
        return [s for s in self._sources if s.enabled]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def search(self, query: str, limit: int = 20) -> list[Vulnerability]:
        """Search all enabled sources in parallel, deduplicate results."""
        results = await self._gather_from_sources("search", query, limit)
        deduped = _deduplicate(results)
        deduped.sort(key=lambda v: v.cvss_score or 0.0, reverse=True)
        return deduped[:limit]

    async def get_by_id(self, vuln_id: str) -> Vulnerability | None:
        """Get a vulnerability by ID from all sources, merge into richest record."""
        results = await self._gather_from_sources("get_by_id", vuln_id)
        if not results:
            return None
        return _merge_vulnerabilities(results)

    async def get_by_package(
        self,
        package_name: str,
        ecosystem: str,
        version: str | None = None,
    ) -> list[Vulnerability]:
        """Get vulnerabilities for a package from all sources."""
        results = await self._gather_from_sources(
            "get_by_package",
            package_name,
            ecosystem,
            version,
        )
        return _deduplicate(results)

    async def health_check(self) -> dict[str, bool]:
        """Check all sources, return ``{source_name: is_healthy}``."""
        tasks = {
            source.source_type.value: source.health_check() for source in self._sources
        }
        raw = await asyncio.gather(*tasks.values(), return_exceptions=True)
        return {
            name: isinstance(result, bool) and result
            for name, result in zip(tasks.keys(), raw, strict=True)
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _gather_from_sources(
        self,
        method_name: str,
        *args: object,
    ) -> list[Vulnerability]:
        """Call *method_name* on every enabled source and flatten results."""
        sources = self.enabled_sources
        if not sources:
            logger.warning("No enabled sources — returning empty results")
            return []

        tasks = [getattr(src, method_name)(*args) for src in sources]
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        results: list[Vulnerability] = []
        for source, outcome in zip(sources, outcomes, strict=True):
            if isinstance(outcome, BaseException):
                logger.warning(
                    "Source %s failed for %s: %s",
                    source.source_type.value,
                    method_name,
                    outcome,
                )
                continue

            if outcome is None:
                continue

            if isinstance(outcome, list):
                results.extend(outcome)
            else:
                # Single Vulnerability (e.g. get_by_id).
                results.append(outcome)

        return results
