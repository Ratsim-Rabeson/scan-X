""".NET project scanner (*.csproj, packages.config)."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from scan_x.models.project import Dependency, ProjectType, ScanResult

if TYPE_CHECKING:
    from pathlib import Path
from scan_x.scanners.base import ScannerBase, VulnerabilityAggregator

logger = logging.getLogger(__name__)


class DotNetScanner(ScannerBase):
    """Scanner for .NET projects."""

    project_type = ProjectType.DOTNET

    def can_scan(self, project_path: Path) -> bool:
        if (project_path / "packages.config").exists():
            return True
        return any(project_path.glob("*.csproj"))

    async def scan(
        self,
        project_path: Path,
        aggregator: VulnerabilityAggregator | None = None,
    ) -> ScanResult:
        return await self._run_scan(project_path, aggregator)

    async def parse_dependencies(self, project_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        seen: set[str] = set()

        for csproj in project_path.glob("*.csproj"):
            deps.extend(self._parse_csproj(csproj, seen))

        pkg_config = project_path / "packages.config"
        if pkg_config.exists():
            deps.extend(self._parse_packages_config(pkg_config, seen))

        return deps

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_csproj(csproj_path: Path, seen: set[str]) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            tree = ET.parse(csproj_path)  # noqa: S314
        except ET.ParseError:
            logger.exception("Failed to parse %s", csproj_path)
            return deps

        root = tree.getroot()
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        for ref in root.iter(f"{ns}PackageReference"):
            name = ref.get("Include") or ref.get("include") or ""
            version = ref.get("Version") or ref.get("version") or ""
            if not version:
                ver_el = ref.find(f"{ns}Version")
                if ver_el is not None and ver_el.text:
                    version = ver_el.text.strip()
            if not name:
                continue
            key = f"{name}@{version}"
            if key in seen:
                continue
            seen.add(key)
            deps.append(
                Dependency(name=name, version=version or "unknown", ecosystem="NuGet")
            )

        return deps

    @staticmethod
    def _parse_packages_config(config_path: Path, seen: set[str]) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            tree = ET.parse(config_path)  # noqa: S314
        except ET.ParseError:
            logger.exception("Failed to parse %s", config_path)
            return deps

        for pkg in tree.getroot().findall("package"):
            name = pkg.get("id", "")
            version = pkg.get("version", "")
            if not name:
                continue
            key = f"{name}@{version}"
            if key in seen:
                continue
            seen.add(key)
            deps.append(
                Dependency(name=name, version=version or "unknown", ecosystem="NuGet")
            )

        return deps
