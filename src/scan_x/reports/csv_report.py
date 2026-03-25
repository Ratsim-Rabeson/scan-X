"""CSV report generator for scan-X."""

from __future__ import annotations

import csv
import io
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from scan_x.models.report import ReportConfig, ReportMetadata
    from scan_x.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

COLUMNS = [
    "CVE ID",
    "Title",
    "Severity",
    "CVSS Score",
    "Ecosystem",
    "Package",
    "Affected Versions",
    "Fixed Versions",
    "Source",
    "Published Date",
    "Remediation",
]


async def generate_csv(
    vulns: list[Vulnerability],
    config: ReportConfig,
    metadata: ReportMetadata,
) -> Path:
    """Generate a CSV vulnerability report.

    Each affected package produces its own row, so a vulnerability with *N*
    affected packages results in *N* rows.

    Returns the path the report was written to.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(COLUMNS)

    for vuln in vulns:
        if vuln.affected_packages:
            for pkg in vuln.affected_packages:
                writer.writerow(_vuln_row(vuln, pkg))
        else:
            # Vulnerability with no recorded packages still gets one row.
            writer.writerow(_vuln_row(vuln, pkg=None))

    output = config.output_path
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(buf.getvalue(), encoding="utf-8", newline="")

    logger.info("CSV report written to %s (%d vulnerabilities)", output, len(vulns))
    return output


def _vuln_row(vuln: Vulnerability, pkg: object | None) -> list[str]:
    """Build a single CSV row for *vuln* / *pkg*."""
    from scan_x.models.vulnerability import AffectedPackage  # noqa: TC004

    ap: AffectedPackage | None = pkg if isinstance(pkg, AffectedPackage) else None

    published = vuln.published_date.isoformat() if vuln.published_date else ""
    return [
        vuln.id,
        vuln.title,
        vuln.severity.value,
        str(vuln.cvss_score) if vuln.cvss_score is not None else "",
        ap.ecosystem if ap else "",
        ap.name if ap else "",
        ", ".join(ap.affected_versions) if ap else "",
        ", ".join(ap.fixed_versions) if ap else "",
        vuln.source.value,
        published,
        vuln.remediation or "",
    ]
