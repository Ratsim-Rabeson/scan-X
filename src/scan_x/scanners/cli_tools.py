"""External CLI tool scanners (Trivy, Grype)."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import TYPE_CHECKING, Any

from scan_x.models.project import Dependency, ProjectType, ScanResult, ScanStatus

if TYPE_CHECKING:
    from pathlib import Path
from scan_x.models.vulnerability import (
    AffectedPackage,
    Severity,
    Vulnerability,
    VulnerabilitySource,
)
from scan_x.scanners.base import ScannerBase, VulnerabilityAggregator

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "negligible": Severity.NONE,
    "unknown": Severity.NONE,
}


class TrivyScanner(ScannerBase):
    """Scanner using the Trivy CLI tool."""

    project_type = ProjectType.UNKNOWN

    def can_scan(self, project_path: Path) -> bool:
        return shutil.which("trivy") is not None

    async def parse_dependencies(self, project_path: Path) -> list[Dependency]:
        # Trivy handles dependency extraction internally
        return []

    async def scan(
        self,
        project_path: Path,
        aggregator: VulnerabilityAggregator | None = None,
    ) -> ScanResult:
        from datetime import UTC, datetime

        result = ScanResult(
            project_path=project_path,
            project_type=self.project_type,
            scan_status=ScanStatus.SCANNING,
        )

        if not shutil.which("trivy"):
            logger.info("trivy not found on PATH – skipping")
            result.scan_status = ScanStatus.COMPLETED
            result.completed_at = datetime.now(UTC)
            return result

        try:
            proc = await asyncio.create_subprocess_exec(
                "trivy", "fs", "--format", "json", "--quiet", str(project_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except TimeoutError:
            logger.warning("trivy scan timed out")
            result.scan_status = ScanStatus.FAILED
            result.error = "trivy scan timed out"
            result.completed_at = datetime.now(UTC)
            return result
        except OSError:
            logger.exception("Failed to run trivy")
            result.scan_status = ScanStatus.FAILED
            result.error = "Failed to execute trivy"
            result.completed_at = datetime.now(UTC)
            return result

        try:
            data = json.loads(stdout.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.warning("Failed to parse trivy JSON output")
            result.scan_status = ScanStatus.FAILED
            result.error = "Invalid trivy output"
            result.completed_at = datetime.now(UTC)
            return result

        vulns, deps = _parse_trivy_results(data)
        result.dependencies = deps
        result.vulnerabilities = vulns
        result.scan_status = ScanStatus.COMPLETED
        result.completed_at = datetime.now(UTC)
        return result


class GrypeScanner(ScannerBase):
    """Scanner using the Grype CLI tool."""

    project_type = ProjectType.UNKNOWN

    def can_scan(self, project_path: Path) -> bool:
        return shutil.which("grype") is not None

    async def parse_dependencies(self, project_path: Path) -> list[Dependency]:
        # Grype handles dependency extraction internally
        return []

    async def scan(
        self,
        project_path: Path,
        aggregator: VulnerabilityAggregator | None = None,
    ) -> ScanResult:
        from datetime import UTC, datetime

        result = ScanResult(
            project_path=project_path,
            project_type=self.project_type,
            scan_status=ScanStatus.SCANNING,
        )

        if not shutil.which("grype"):
            logger.info("grype not found on PATH – skipping")
            result.scan_status = ScanStatus.COMPLETED
            result.completed_at = datetime.now(UTC)
            return result

        try:
            proc = await asyncio.create_subprocess_exec(
                "grype", f"dir:{project_path}", "--output", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except TimeoutError:
            logger.warning("grype scan timed out")
            result.scan_status = ScanStatus.FAILED
            result.error = "grype scan timed out"
            result.completed_at = datetime.now(UTC)
            return result
        except OSError:
            logger.exception("Failed to run grype")
            result.scan_status = ScanStatus.FAILED
            result.error = "Failed to execute grype"
            result.completed_at = datetime.now(UTC)
            return result

        try:
            data = json.loads(stdout.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.warning("Failed to parse grype JSON output")
            result.scan_status = ScanStatus.FAILED
            result.error = "Invalid grype output"
            result.completed_at = datetime.now(UTC)
            return result

        vulns, deps = _parse_grype_results(data)
        result.dependencies = deps
        result.vulnerabilities = vulns
        result.scan_status = ScanStatus.COMPLETED
        result.completed_at = datetime.now(UTC)
        return result


# ------------------------------------------------------------------
# Output parsers
# ------------------------------------------------------------------


def _parse_trivy_results(
    data: dict[str, Any],
) -> tuple[list[Vulnerability], list[Dependency]]:
    vulns: list[Vulnerability] = []
    deps: list[Dependency] = []
    seen_vulns: set[str] = set()
    seen_deps: set[str] = set()

    for target in data.get("Results", []):
        ecosystem = _trivy_class_to_ecosystem(target.get("Class", ""))
        for pkg in target.get("Packages", []):
            pkg_name = pkg.get("Name", "")
            pkg_version = pkg.get("Version", "")
            if pkg_name:
                dep_key = f"{pkg_name}@{pkg_version}"
                if dep_key not in seen_deps:
                    seen_deps.add(dep_key)
                    deps.append(
                        Dependency(
                            name=pkg_name,
                            version=pkg_version or "unknown",
                            ecosystem=ecosystem,
                        )
                    )

        for vuln_data in target.get("Vulnerabilities", []):
            vuln_id = vuln_data.get("VulnerabilityID", "")
            if not vuln_id or vuln_id in seen_vulns:
                continue
            seen_vulns.add(vuln_id)

            sev = _SEVERITY_MAP.get(
                vuln_data.get("Severity", "").lower(), Severity.MEDIUM
            )

            vulns.append(
                Vulnerability(
                    id=vuln_id,
                    title=vuln_data.get("Title", vuln_id),
                    description=vuln_data.get("Description", ""),
                    severity=sev,
                    cvss_score=_extract_cvss_score(vuln_data),
                    source=VulnerabilitySource.TRIVY,
                    affected_packages=[
                        AffectedPackage(
                            name=vuln_data.get("PkgName", ""),
                            ecosystem=ecosystem,
                            affected_versions=[vuln_data.get("InstalledVersion", "")],
                            fixed_versions=[vuln_data.get("FixedVersion", "")]
                            if vuln_data.get("FixedVersion")
                            else [],
                        )
                    ],
                )
            )
    return vulns, deps


def _parse_grype_results(
    data: dict[str, Any],
) -> tuple[list[Vulnerability], list[Dependency]]:
    vulns: list[Vulnerability] = []
    deps: list[Dependency] = []
    seen_vulns: set[str] = set()
    seen_deps: set[str] = set()

    for match in data.get("matches", []):
        artifact = match.get("artifact", {})
        pkg_name = artifact.get("name", "")
        pkg_version = artifact.get("version", "")
        ecosystem = artifact.get("type", "unknown")

        if pkg_name:
            dep_key = f"{pkg_name}@{pkg_version}"
            if dep_key not in seen_deps:
                seen_deps.add(dep_key)
                deps.append(
                    Dependency(
                        name=pkg_name,
                        version=pkg_version or "unknown",
                        ecosystem=ecosystem,
                    )
                )

        vuln_data = match.get("vulnerability", {})
        vuln_id = vuln_data.get("id", "")
        if not vuln_id or vuln_id in seen_vulns:
            continue
        seen_vulns.add(vuln_id)

        sev = _SEVERITY_MAP.get(
            vuln_data.get("severity", "").lower(), Severity.MEDIUM
        )

        fixed_versions: list[str] = []
        fix = vuln_data.get("fix", {})
        if fix and fix.get("versions"):
            fixed_versions = fix["versions"]

        vulns.append(
            Vulnerability(
                id=vuln_id,
                title=vuln_data.get("id", vuln_id),
                description=vuln_data.get("description", ""),
                severity=sev,
                source=VulnerabilitySource.GRYPE,
                affected_packages=[
                    AffectedPackage(
                        name=pkg_name,
                        ecosystem=ecosystem,
                        affected_versions=[pkg_version] if pkg_version else [],
                        fixed_versions=fixed_versions,
                    )
                ],
            )
        )
    return vulns, deps


def _trivy_class_to_ecosystem(trivy_class: str) -> str:
    mapping = {
        "lang-pkgs": "unknown",
        "os-pkgs": "os",
    }
    return mapping.get(trivy_class, trivy_class or "unknown")


def _extract_cvss_score(vuln_data: dict[str, Any]) -> float | None:
    cvss = vuln_data.get("CVSS", {})
    for _source, scores in cvss.items():
        v3 = scores.get("V3Score")
        if v3 is not None:
            return float(v3)
    return None
