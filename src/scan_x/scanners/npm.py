"""Node.js / npm / Yarn project scanner."""

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
from scan_x.scanners.base import ScannerBase, VulnerabilityAggregator

logger = logging.getLogger(__name__)


class NpmScanner(ScannerBase):
    """Scanner for Node.js projects using npm or Yarn."""

    project_type = ProjectType.NODEJS

    def can_scan(self, project_path: Path) -> bool:
        return (
            (project_path / "package-lock.json").exists()
            or (project_path / "yarn.lock").exists()
            or (project_path / "package.json").exists()
        )

    async def scan(
        self,
        project_path: Path,
        aggregator: VulnerabilityAggregator | None = None,
    ) -> ScanResult:
        result = await self._run_scan(project_path, aggregator)

        audit_vulns = await self._run_npm_audit(project_path)
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

        lockfile = project_path / "package-lock.json"
        if lockfile.exists():
            deps.extend(self._parse_package_lock(lockfile, seen))

        yarn_lock = project_path / "yarn.lock"
        if yarn_lock.exists():
            deps.extend(self._parse_yarn_lock(yarn_lock, seen))

        if not deps:
            pkg_json = project_path / "package.json"
            if pkg_json.exists():
                deps.extend(self._parse_package_json(pkg_json, seen))

        return deps

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_package_lock(lockfile: Path, seen: set[str]) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            data = json.loads(lockfile.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception("Failed to parse %s", lockfile)
            return deps

        # npm v7+ "packages" key
        packages = data.get("packages", {})
        for pkg_path, info in packages.items():
            if not pkg_path:  # root entry
                continue
            name = info.get("name") or pkg_path.rsplit("node_modules/", 1)[-1]
            version = info.get("version", "")
            if not version:
                continue
            key = f"{name}@{version}"
            if key in seen:
                continue
            seen.add(key)
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    dev=info.get("dev", False),
                )
            )

        # npm v5/v6 fallback "dependencies" key
        if not deps:
            for name, info in data.get("dependencies", {}).items():
                version = info.get("version", "")
                if not version:
                    continue
                key = f"{name}@{version}"
                if key in seen:
                    continue
                seen.add(key)
                deps.append(
                    Dependency(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        dev=info.get("dev", False),
                    )
                )

        return deps

    @staticmethod
    def _parse_yarn_lock(yarn_lock: Path, seen: set[str]) -> list[Dependency]:
        """Parse yarn.lock v1 format (line-based, not YAML)."""
        deps: list[Dependency] = []
        header_re = re.compile(r'^"?(@?[^@\s"]+)@')
        version_re = re.compile(r'^\s+version\s+"?([^"\s]+)"?')
        try:
            content = yarn_lock.read_text(encoding="utf-8")
        except OSError:
            logger.exception("Failed to read %s", yarn_lock)
            return deps

        current_name: str | None = None
        for line in content.splitlines():
            hm = header_re.match(line)
            if hm:
                current_name = hm.group(1)
                continue
            if current_name:
                vm = version_re.match(line)
                if vm:
                    version = vm.group(1)
                    key = f"{current_name}@{version}"
                    if key not in seen:
                        seen.add(key)
                        deps.append(
                            Dependency(name=current_name, version=version, ecosystem="npm")
                        )
                    current_name = None
        return deps

    @staticmethod
    def _parse_package_json(pkg_json: Path, seen: set[str]) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception("Failed to parse %s", pkg_json)
            return deps

        for section, is_dev in [("dependencies", False), ("devDependencies", True)]:
            for name, version_spec in data.get(section, {}).items():
                version = version_spec.lstrip("^~>=<! ")
                key = f"{name}@{version}"
                if key in seen:
                    continue
                seen.add(key)
                deps.append(Dependency(name=name, version=version, ecosystem="npm", dev=is_dev))
        return deps

    # ------------------------------------------------------------------
    # Optional CLI audit
    # ------------------------------------------------------------------

    @staticmethod
    async def _run_npm_audit(project_path: Path) -> list:
        """Run ``npm audit --json`` and return parsed vulnerability objects."""
        from scan_x.models.vulnerability import (
            AffectedPackage,
            Severity,
            Vulnerability,
            VulnerabilitySource,
        )

        if not shutil.which("npm"):
            logger.info("npm not found on PATH – skipping npm audit")
            return []

        if not (project_path / "package-lock.json").exists():
            return []

        try:
            proc = await asyncio.create_subprocess_exec(
                "npm", "audit", "--json",
                cwd=str(project_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        except (TimeoutError, OSError):
            logger.warning("npm audit timed out or failed")
            return []

        try:
            data = json.loads(stdout.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []

        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "moderate": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.NONE,
        }

        vulns: list[Vulnerability] = []
        advisories = data.get("advisories") or data.get("vulnerabilities") or {}
        for _key, adv in advisories.items():
            sev_str = (adv.get("severity") or "low").lower()
            vulns.append(
                Vulnerability(
                    id=str(adv.get("id", adv.get("name", _key))),
                    title=adv.get("title", adv.get("name", str(_key))),
                    description=adv.get("overview", adv.get("title", "")),
                    severity=severity_map.get(sev_str, Severity.MEDIUM),
                    source=VulnerabilitySource.CUSTOM,
                    affected_packages=[
                        AffectedPackage(
                            name=adv.get("module_name", adv.get("name", "")),
                            ecosystem="npm",
                            affected_versions=[adv.get("vulnerable_versions", "")],
                            fixed_versions=[adv.get("patched_versions", "")],
                        )
                    ],
                )
            )
        return vulns
