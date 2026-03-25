"""Python project scanner (requirements.txt, poetry.lock, Pipfile.lock)."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
from typing import TYPE_CHECKING

from scan_x.models.project import Dependency, ProjectType, ScanResult

if TYPE_CHECKING:
    from pathlib import Path

    from scan_x.models.vulnerability import Vulnerability
from scan_x.scanners.base import ScannerBase, VulnerabilityAggregator

logger = logging.getLogger(__name__)


class PythonScanner(ScannerBase):
    """Scanner for Python projects."""

    project_type = ProjectType.PYTHON

    def can_scan(self, project_path: Path) -> bool:
        if any(
            (project_path / f).exists()
            for f in ("requirements.txt", "poetry.lock", "Pipfile.lock")
        ):
            return True
        pyproject = project_path / "pyproject.toml"
        if pyproject.exists():
            try:
                content = pyproject.read_text(encoding="utf-8")
                return "[tool.poetry" in content or "[project]" in content
            except OSError:
                pass
        return False

    async def scan(
        self,
        project_path: Path,
        aggregator: VulnerabilityAggregator | None = None,
    ) -> ScanResult:
        result = await self._run_scan(project_path, aggregator)

        audit_vulns = await self._run_pip_audit(project_path)
        if audit_vulns:
            seen = {v.id for v in result.vulnerabilities}
            for v in audit_vulns:
                if v.id not in seen:
                    seen.add(v.id)
                    result.vulnerabilities.append(v)

        return result

    async def parse_dependencies(self, project_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        seen: set[str] = set()

        poetry_lock = project_path / "poetry.lock"
        if poetry_lock.exists():
            deps.extend(self._parse_poetry_lock(poetry_lock, seen))

        pipfile_lock = project_path / "Pipfile.lock"
        if pipfile_lock.exists():
            deps.extend(self._parse_pipfile_lock(pipfile_lock, seen))

        req_txt = project_path / "requirements.txt"
        if req_txt.exists():
            deps.extend(self._parse_requirements_txt(req_txt, seen, project_path))

        return deps

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_requirements_txt(
        req_path: Path, seen: set[str], base_dir: Path | None = None
    ) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            lines = req_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            logger.exception("Failed to read %s", req_path)
            return deps

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Handle -r / -c includes
            if line.startswith(("-r ", "-c ")):
                include_path = line.split(None, 1)[1].strip()
                resolved = (base_dir or req_path.parent) / include_path
                if resolved.exists():
                    deps.extend(
                        PythonScanner._parse_requirements_txt(resolved, seen, resolved.parent)
                    )
                continue

            # Skip options like --index-url
            if line.startswith("-"):
                continue

            # Remove environment markers / extras
            line = re.split(r"\s*;\s*", line)[0]
            line = re.split(r"\[", line)[0]

            match = re.match(r"^([A-Za-z0-9_.-]+)\s*([~=!<>]+)\s*(.+)$", line)
            if match:
                name = match.group(1).lower()
                version = match.group(3).strip().split(",")[0].strip()
                key = f"{name}@{version}"
                if key not in seen:
                    seen.add(key)
                    deps.append(Dependency(name=name, version=version, ecosystem="PyPI"))
            else:
                # Bare package name without version
                name = re.split(r"[@\s]", line)[0].strip().lower()
                if name and name not in seen:
                    seen.add(name)
                    deps.append(Dependency(name=name, version="*", ecosystem="PyPI"))

        return deps

    @staticmethod
    def _parse_poetry_lock(lock_path: Path, seen: set[str]) -> list[Dependency]:
        """Parse poetry.lock (TOML with [[package]] sections)."""
        deps: list[Dependency] = []
        try:
            import tomllib

            data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        except ImportError:
            # Fallback regex parsing for Python < 3.11 (shouldn't happen with >=3.11)
            return _parse_poetry_lock_regex(lock_path, seen)
        except Exception:
            logger.exception("Failed to parse %s", lock_path)
            return deps

        for pkg in data.get("package", []):
            name = pkg.get("name", "").lower()
            version = pkg.get("version", "")
            if not name or not version:
                continue
            key = f"{name}@{version}"
            if key in seen:
                continue
            seen.add(key)
            deps.append(Dependency(name=name, version=version, ecosystem="PyPI"))
        return deps

    @staticmethod
    def _parse_pipfile_lock(lock_path: Path, seen: set[str]) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            data = json.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception("Failed to parse %s", lock_path)
            return deps

        for section, is_dev in [("default", False), ("develop", True)]:
            for name, info in data.get(section, {}).items():
                version = info.get("version", "").lstrip("=")
                if not version:
                    continue
                key = f"{name.lower()}@{version}"
                if key in seen:
                    continue
                seen.add(key)
                deps.append(
                    Dependency(name=name.lower(), version=version, ecosystem="PyPI", dev=is_dev)
                )
        return deps

    # ------------------------------------------------------------------
    # Optional CLI audit
    # ------------------------------------------------------------------

    @staticmethod
    async def _run_pip_audit(project_path: Path) -> list[Vulnerability]:
        from scan_x.models.vulnerability import (
            AffectedPackage,
            Severity,
            Vulnerability,
            VulnerabilitySource,
        )

        if not shutil.which("pip-audit"):
            logger.info("pip-audit not found on PATH – skipping")
            return []

        try:
            proc = await asyncio.create_subprocess_exec(
                "pip-audit", "--format=json", "--desc",
                cwd=str(project_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        except (TimeoutError, OSError):
            logger.warning("pip-audit timed out or failed")
            return []

        try:
            data = json.loads(stdout.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []

        vulns: list[Vulnerability] = []
        for entry in data.get("dependencies", []):
            for vuln_info in entry.get("vulns", []):
                vulns.append(
                    Vulnerability(
                        id=vuln_info.get("id", "UNKNOWN"),
                        title=vuln_info.get("id", "Unknown vulnerability"),
                        description=vuln_info.get("description", ""),
                        severity=Severity.MEDIUM,
                        source=VulnerabilitySource.CUSTOM,
                        affected_packages=[
                            AffectedPackage(
                                name=entry.get("name", ""),
                                ecosystem="PyPI",
                                affected_versions=[entry.get("version", "")],
                                fixed_versions=[vuln_info.get("fix_versions", [""])[0]]
                                if vuln_info.get("fix_versions")
                                else [],
                            )
                        ],
                    )
                )
        return vulns


def _parse_poetry_lock_regex(lock_path: Path, seen: set[str]) -> list[Dependency]:
    """Fallback regex parser for poetry.lock."""
    deps: list[Dependency] = []
    try:
        content = lock_path.read_text(encoding="utf-8")
    except OSError:
        return deps

    name_re = re.compile(r'^name\s*=\s*"(.+?)"', re.MULTILINE)
    ver_re = re.compile(r'^version\s*=\s*"(.+?)"', re.MULTILINE)

    blocks = content.split("[[package]]")
    for block in blocks[1:]:
        nm = name_re.search(block)
        vm = ver_re.search(block)
        if nm and vm:
            name = nm.group(1).lower()
            version = vm.group(1)
            key = f"{name}@{version}"
            if key not in seen:
                seen.add(key)
                deps.append(Dependency(name=name, version=version, ecosystem="PyPI"))
    return deps
