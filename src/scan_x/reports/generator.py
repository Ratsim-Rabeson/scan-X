"""Report orchestrator for scan-X."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from scan_x.models.report import ReportFormat
from scan_x.reports.csv_report import generate_csv
from scan_x.reports.html import generate_html
from scan_x.reports.json_report import generate_json
from scan_x.reports.pdf import generate_pdf

if TYPE_CHECKING:
    from pathlib import Path

    from scan_x.models.report import ReportConfig, ReportMetadata
    from scan_x.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Facade for generating vulnerability reports in any supported format."""

    async def generate(
        self,
        vulnerabilities: list[Vulnerability],
        config: ReportConfig,
        metadata: ReportMetadata,
    ) -> Path:
        """Generate a report in the format specified by *config*.

        Returns the path the report was written to.
        """
        match config.format:
            case ReportFormat.JSON:
                return await generate_json(vulnerabilities, config, metadata)
            case ReportFormat.CSV:
                return await generate_csv(vulnerabilities, config, metadata)
            case ReportFormat.HTML:
                return await generate_html(vulnerabilities, config, metadata)
            case ReportFormat.PDF:
                return await generate_pdf(vulnerabilities, config, metadata)

    async def generate_multiple(
        self,
        vulnerabilities: list[Vulnerability],
        configs: list[ReportConfig],
        metadata: ReportMetadata,
    ) -> list[Path]:
        """Generate reports in multiple formats.

        Returns a list of paths, one per config.
        """
        paths: list[Path] = []
        for cfg in configs:
            path = await self.generate(vulnerabilities, cfg, metadata)
            paths.append(path)
        return paths
