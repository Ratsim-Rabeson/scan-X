"""PDF report generator for scan-X."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scan_x.reports.html import render_html

if TYPE_CHECKING:
    from pathlib import Path

    from scan_x.models.report import ReportConfig, ReportMetadata
    from scan_x.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


async def generate_pdf(
    vulns: list[Vulnerability],
    config: ReportConfig,
    metadata: ReportMetadata,
) -> Path:
    """Generate a PDF vulnerability report.

    The report is first rendered as HTML (reusing :func:`render_html`) and
    then converted to PDF via *WeasyPrint*.  The WeasyPrint call is offloaded
    to a thread because it is synchronous and can be slow.

    Raises
    ------
    ImportError
        If WeasyPrint is not installed.
    """
    try:
        import weasyprint  # noqa: TC004
    except ImportError as exc:
        raise ImportError(
            "WeasyPrint is required for PDF report generation. "
            "Install it with:  pip install weasyprint"
        ) from exc

    html_string = render_html(vulns, config, metadata)

    output = config.output_path
    output.parent.mkdir(parents=True, exist_ok=True)

    def _write_pdf() -> None:
        doc = weasyprint.HTML(string=html_string)
        doc.write_pdf(str(output))

    await asyncio.to_thread(_write_pdf)

    logger.info("PDF report written to %s", output)
    return output
