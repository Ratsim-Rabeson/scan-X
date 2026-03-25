"""Abstract base class for project scanners and vulnerability aggregation."""

from __future__ import annotations

import abc
import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from scan_x.models.project import Dependency, ProjectType, ScanResult
    from scan_x.models.vulnerability import Vulnerability
    from scan_x.sources.base import VulnerabilitySourceBase

logger = logging.getLogger(__name__)


class VulnerabilityAggregator:
    """Aggregates vulnerability lookups across multiple data sources."""

    def __init__(self, sources: list[VulnerabilitySourceBase] | None = None) -> None:
        self.sources: list[VulnerabilitySourceBase] = sources or []

    async def get_vulnerabilities(
        self,
        package_name: str,
        ecosystem: str,
        version: str | None = None,
    ) -> list[Vulnerability]:
        """Query all enabled sources for vulnerabilities affecting a package."""
        enabled = [s for s in self.sources if s.enabled]
        if not enabled:
            return []

        tasks = [
            s.get_by_package(package_name, ecosystem, version) for s in enabled
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        vulns: list[Vulnerability] = []
        seen_ids: set[str] = set()
        for result in results:
            if isinstance(result, BaseException):
                logger.warning("Source query failed: %s", result)
                continue
            for vuln in result:
                if vuln.id not in seen_ids:
                    seen_ids.add(vuln.id)
                    vulns.append(vuln)
        return vulns

    async def scan_dependencies(
        self,
        dependencies: list[Dependency],
    ) -> list[Vulnerability]:
        """Scan a list of dependencies and return all discovered vulnerabilities."""
        all_vulns: list[Vulnerability] = []
        seen_ids: set[str] = set()
        for dep in dependencies:
            vulns = await self.get_vulnerabilities(dep.name, dep.ecosystem, dep.version)
            for vuln in vulns:
                if vuln.id not in seen_ids:
                    seen_ids.add(vuln.id)
                    all_vulns.append(vuln)
        return all_vulns


class ScannerBase(abc.ABC):
    """Abstract base class for project scanners."""

    project_type: ProjectType

    @abc.abstractmethod
    async def scan(
        self,
        project_path: Path,
        aggregator: VulnerabilityAggregator | None = None,
    ) -> ScanResult:
        """Scan a project directory for vulnerabilities."""
        ...

    @abc.abstractmethod
    def can_scan(self, project_path: Path) -> bool:
        """Check if this scanner can handle the given project."""
        ...

    @abc.abstractmethod
    async def parse_dependencies(self, project_path: Path) -> list[Dependency]:
        """Parse project dependencies from lockfiles/manifests."""
        ...

    async def _run_scan(
        self,
        project_path: Path,
        aggregator: VulnerabilityAggregator | None = None,
    ) -> ScanResult:
        """Shared scan logic: parse deps, optionally look up vulns, build result."""
        from datetime import UTC, datetime

        from scan_x.models.project import ScanResult, ScanStatus

        result = ScanResult(
            project_path=project_path,
            project_type=self.project_type,
            scan_status=ScanStatus.SCANNING,
        )
        try:
            deps = await self.parse_dependencies(project_path)
            result.dependencies = deps

            vulns: list[Vulnerability] = []
            if aggregator is not None:
                vulns = await aggregator.scan_dependencies(deps)
            result.vulnerabilities = vulns
            result.scan_status = ScanStatus.COMPLETED
        except Exception:
            logger.exception("Scan failed for %s", project_path)
            result.scan_status = ScanStatus.FAILED
            result.error = f"Scan failed for {project_path}"
        finally:
            result.completed_at = datetime.now(UTC)
        return result
