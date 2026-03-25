"""Maven (pom.xml) project scanner."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from scan_x.models.project import Dependency, ProjectType, ScanResult

if TYPE_CHECKING:
    from pathlib import Path
from scan_x.scanners.base import ScannerBase, VulnerabilityAggregator

logger = logging.getLogger(__name__)

_POM_NS = "{http://maven.apache.org/POM/4.0.0}"
_PROP_RE_PATTERN = r"\$\{(.+?)\}"


class MavenScanner(ScannerBase):
    """Scanner for Maven projects using pom.xml."""

    project_type = ProjectType.MAVEN

    def can_scan(self, project_path: Path) -> bool:
        return (project_path / "pom.xml").exists()

    async def scan(
        self,
        project_path: Path,
        aggregator: VulnerabilityAggregator | None = None,
    ) -> ScanResult:
        return await self._run_scan(project_path, aggregator)

    async def parse_dependencies(self, project_path: Path) -> list[Dependency]:
        pom_path = project_path / "pom.xml"
        if not pom_path.exists():
            return []
        return self._parse_pom(pom_path)

    # ------------------------------------------------------------------
    # POM parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_pom(pom_path: Path) -> list[Dependency]:
        import re

        deps: list[Dependency] = []
        try:
            tree = ET.parse(pom_path)  # noqa: S314
        except ET.ParseError:
            logger.exception("Failed to parse %s", pom_path)
            return deps

        root = tree.getroot()
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        # Resolve properties -------------------------------------------
        props: dict[str, str] = {}
        props_el = root.find(f"{ns}properties")
        if props_el is not None:
            for child in props_el:
                tag = child.tag.replace(ns, "")
                if child.text:
                    props[tag] = child.text.strip()

        # Add implicit project properties
        for tag in ("version", "groupId", "artifactId"):
            el = root.find(f"{ns}{tag}")
            if el is not None and el.text:
                props[f"project.{tag}"] = el.text.strip()

        def resolve(value: str | None) -> str:
            if not value:
                return ""
            resolved = value
            for match in re.finditer(_PROP_RE_PATTERN, value):
                prop_name = match.group(1)
                replacement = props.get(prop_name, match.group(0))
                resolved = resolved.replace(match.group(0), replacement)
            return resolved

        # Extract dependencies -----------------------------------------
        seen: set[str] = set()
        for dep_section_tag in (
            f"{ns}dependencies",
            f"{ns}dependencyManagement/{ns}dependencies",
        ):
            dep_section = root.find(dep_section_tag)
            if dep_section is None:
                continue
            for dep_el in dep_section.findall(f"{ns}dependency"):
                group_id = resolve(_text(dep_el, f"{ns}groupId"))
                artifact_id = resolve(_text(dep_el, f"{ns}artifactId"))
                version = resolve(_text(dep_el, f"{ns}version"))
                if not group_id or not artifact_id:
                    continue
                name = f"{group_id}:{artifact_id}"
                key = f"{name}:{version}"
                if key in seen:
                    continue
                seen.add(key)
                scope = _text(dep_el, f"{ns}scope") or "compile"
                deps.append(
                    Dependency(
                        name=name,
                        version=version or "unknown",
                        ecosystem="Maven",
                        dev=scope in ("test", "provided"),
                    )
                )
        return deps


def _text(element: ET.Element, tag: str) -> str | None:
    child = element.find(tag)
    return child.text.strip() if child is not None and child.text else None
