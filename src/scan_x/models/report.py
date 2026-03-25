"""Report configuration and metadata models for scan-X."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path  # noqa: TC003 – needed at runtime by Pydantic

from pydantic import BaseModel, Field

from scan_x.models.vulnerability import Severity  # noqa: TC001 – needed at runtime by Pydantic


class ReportFormat(StrEnum):
    """Supported report output formats."""

    PDF = "PDF"
    HTML = "HTML"
    JSON = "JSON"
    CSV = "CSV"


class ReportConfig(BaseModel):
    """Configuration for generating a vulnerability report."""

    format: ReportFormat
    output_path: Path
    title: str = "scan-X Vulnerability Report"
    include_charts: bool = True
    include_remediation: bool = True
    severity_filter: list[Severity] | None = None


class ReportMetadata(BaseModel):
    """Metadata embedded in a generated report."""

    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    scan_x_version: str
    source_query: str | None = None
    project_path: Path | None = None
    total_vulnerabilities: int
    severity_summary: dict[Severity, int] = Field(default_factory=dict)
