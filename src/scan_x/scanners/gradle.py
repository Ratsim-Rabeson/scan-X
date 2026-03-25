"""Gradle (build.gradle / build.gradle.kts) project scanner."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from scan_x.models.project import Dependency, ProjectType, ScanResult

if TYPE_CHECKING:
    from pathlib import Path
from scan_x.scanners.base import ScannerBase, VulnerabilityAggregator

logger = logging.getLogger(__name__)

# Configurations that declare dependencies
_DEP_CONFIGS = (
    "implementation",
    "api",
    "compile",
    "compileOnly",
    "runtimeOnly",
    "testImplementation",
    "testCompile",
    "testRuntimeOnly",
    "classpath",
    "annotationProcessor",
    "kapt",
)

_CONFIGS_PATTERN = "|".join(_DEP_CONFIGS)

# Pattern: implementation 'group:name:version' or implementation "group:name:version"
_STRING_NOTATION_RE = re.compile(
    rf'(?:{_CONFIGS_PATTERN})\s*[\(]?\s*["\']([^"\']+):([^"\']+):([^"\']+)["\']',
    re.IGNORECASE,
)

# Pattern: implementation group: 'x', name: 'y', version: 'z'
_MAP_NOTATION_RE = re.compile(
    rf'(?:{_CONFIGS_PATTERN})\s*(?:\(?\s*)'
    r"""group\s*[:=]\s*['"]([^'"]+)['"]\s*,\s*"""
    r"""name\s*[:=]\s*['"]([^'"]+)['"]\s*,\s*"""
    r"""version\s*[:=]\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


class GradleScanner(ScannerBase):
    """Scanner for Gradle projects."""

    project_type = ProjectType.GRADLE

    def can_scan(self, project_path: Path) -> bool:
        return (project_path / "build.gradle").exists() or (
            project_path / "build.gradle.kts"
        ).exists()

    async def scan(
        self,
        project_path: Path,
        aggregator: VulnerabilityAggregator | None = None,
    ) -> ScanResult:
        return await self._run_scan(project_path, aggregator)

    async def parse_dependencies(self, project_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        seen: set[str] = set()

        for filename in ("build.gradle", "build.gradle.kts"):
            build_file = project_path / filename
            if build_file.exists():
                deps.extend(self._parse_gradle_file(build_file, seen))

        return deps

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_gradle_file(build_file: Path, seen: set[str]) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            content = build_file.read_text(encoding="utf-8")
        except OSError:
            logger.exception("Failed to read %s", build_file)
            return deps

        # String notation: implementation 'group:name:version'
        for match in _STRING_NOTATION_RE.finditer(content):
            group, name, version = match.group(1), match.group(2), match.group(3)
            dep_name = f"{group}:{name}"
            key = f"{dep_name}:{version}"
            if key in seen:
                continue
            seen.add(key)
            deps.append(
                Dependency(name=dep_name, version=version, ecosystem="Maven")
            )

        # Map notation: implementation group: 'x', name: 'y', version: 'z'
        for match in _MAP_NOTATION_RE.finditer(content):
            group, name, version = match.group(1), match.group(2), match.group(3)
            dep_name = f"{group}:{name}"
            key = f"{dep_name}:{version}"
            if key in seen:
                continue
            seen.add(key)
            deps.append(
                Dependency(name=dep_name, version=version, ecosystem="Maven")
            )

        return deps
