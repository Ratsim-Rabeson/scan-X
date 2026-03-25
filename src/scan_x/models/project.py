"""Project and scan result data models for scan-X."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path  # noqa: TC003 – needed at runtime by Pydantic

from pydantic import BaseModel, Field, computed_field

from scan_x.models.vulnerability import Severity, Vulnerability


class ProjectType(StrEnum):
    """Supported project ecosystems."""

    NODEJS = "NODEJS"
    PYTHON = "PYTHON"
    MAVEN = "MAVEN"
    GRADLE = "GRADLE"
    DOTNET = "DOTNET"
    UNKNOWN = "UNKNOWN"


class Dependency(BaseModel):
    """A single project dependency."""

    name: str
    version: str
    ecosystem: str
    dev: bool = False


class ScanStatus(StrEnum):
    """Lifecycle status of a scan operation."""

    PENDING = "PENDING"
    SCANNING = "SCANNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScanResult(BaseModel):
    """Result of scanning a project for vulnerabilities."""

    project_path: Path
    project_type: ProjectType
    dependencies: list[Dependency] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    scan_status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    error: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_deps(self) -> int:
        """Total number of scanned dependencies."""
        return len(self.dependencies)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def vuln_count(self) -> int:
        """Total number of discovered vulnerabilities."""
        return len(self.vulnerabilities)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity_counts(self) -> dict[Severity, int]:
        """Vulnerability counts grouped by severity level."""
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for vuln in self.vulnerabilities:
            counts[vuln.severity] += 1
        return counts
