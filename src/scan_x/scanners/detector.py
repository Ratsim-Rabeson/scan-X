"""Auto-detect project type(s) from directory contents."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from scan_x.models.project import ProjectType

if TYPE_CHECKING:
    from pathlib import Path

    from scan_x.scanners.base import ScannerBase

logger = logging.getLogger(__name__)

_INDICATOR_MAP: dict[ProjectType, list[str]] = {
    ProjectType.NODEJS: ["package-lock.json", "yarn.lock", "package.json"],
    ProjectType.MAVEN: ["pom.xml"],
    ProjectType.GRADLE: ["build.gradle", "build.gradle.kts"],
    ProjectType.PYTHON: ["requirements.txt", "poetry.lock", "Pipfile.lock", "pyproject.toml"],
    ProjectType.DOTNET: ["packages.config"],
}

_GLOB_INDICATORS: dict[ProjectType, list[str]] = {
    ProjectType.DOTNET: ["*.csproj"],
}


class ProjectDetector:
    """Detects project type(s) from directory contents."""

    def detect(self, project_path: Path) -> list[ProjectType]:
        """Detect all project types present in a directory."""
        detected: list[ProjectType] = []

        for ptype, filenames in _INDICATOR_MAP.items():
            for fname in filenames:
                if (project_path / fname).exists():
                    if (
                        ptype == ProjectType.PYTHON
                        and fname == "pyproject.toml"
                        and not self._has_python_indicators(project_path / fname)
                    ):
                        continue
                    if ptype not in detected:
                        detected.append(ptype)
                    break

        for ptype, patterns in _GLOB_INDICATORS.items():
            if ptype in detected:
                continue
            for pattern in patterns:
                if any(project_path.glob(pattern)):
                    detected.append(ptype)
                    break

        if not detected:
            logger.info("No known project type detected in %s", project_path)

        return detected

    @staticmethod
    def _has_python_indicators(pyproject_path: Path) -> bool:
        """Check whether a pyproject.toml is actually a Python project."""
        try:
            content = pyproject_path.read_text(encoding="utf-8")
            return (
                "[tool.poetry" in content
                or "[project]" in content
                or "[build-system]" in content
            )
        except OSError:
            return False

    def get_scanners(self, project_path: Path) -> list[ScannerBase]:
        """Return appropriate scanner instances for detected project types."""
        from scan_x.scanners.dotnet import DotNetScanner
        from scan_x.scanners.gradle import GradleScanner
        from scan_x.scanners.maven import MavenScanner
        from scan_x.scanners.npm import NpmScanner
        from scan_x.scanners.python_scanner import PythonScanner

        scanner_map: dict[ProjectType, type[ScannerBase]] = {
            ProjectType.NODEJS: NpmScanner,
            ProjectType.MAVEN: MavenScanner,
            ProjectType.GRADLE: GradleScanner,
            ProjectType.PYTHON: PythonScanner,
            ProjectType.DOTNET: DotNetScanner,
        }

        detected = self.detect(project_path)
        scanners: list[ScannerBase] = []
        for ptype in detected:
            scanner_cls = scanner_map.get(ptype)
            if scanner_cls is not None:
                scanners.append(scanner_cls())
        return scanners
