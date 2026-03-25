"""JSON report generator for scan-X."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from scan_x.models.report import ReportConfig, ReportMetadata
    from scan_x.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


async def generate_json(
    vulns: list[Vulnerability],
    config: ReportConfig,
    metadata: ReportMetadata,
) -> Path:
    """Generate a structured JSON vulnerability report.

    The output follows the schema::

        {"metadata": {...}, "vulnerabilities": [...]}

    Returns the path the report was written to.
    """
    report = {
        "metadata": metadata.model_dump(mode="json"),
        "vulnerabilities": [v.model_dump(mode="json") for v in vulns],
    }

    output = config.output_path
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    logger.info("JSON report written to %s", output)
    return output
