"""HTML report generator for scan-X."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader

from scan_x.models.vulnerability import Severity

if TYPE_CHECKING:
    from scan_x.models.report import ReportConfig, ReportMetadata
    from scan_x.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _build_template_context(
    vulns: list[Vulnerability],
    config: ReportConfig,
    metadata: ReportMetadata,
) -> dict:
    """Prepare the Jinja2 template context dictionary."""
    severities = [s.value for s in Severity]
    severity_counts = {s: metadata.severity_summary.get(Severity(s), 0) for s in severities}
    max_severity_count = max(severity_counts.values(), default=0)

    css_path = _TEMPLATES_DIR / "report.css"
    css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""

    return {
        "metadata": metadata,
        "vulnerabilities": vulns,
        "severities": severities,
        "severity_counts": severity_counts,
        "max_severity_count": max_severity_count,
        "include_remediation": config.include_remediation,
        "css": css,
    }


def render_html(
    vulns: list[Vulnerability],
    config: ReportConfig,
    metadata: ReportMetadata,
) -> str:
    """Render the HTML report and return the markup string."""
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html")
    context = _build_template_context(vulns, config, metadata)
    return template.render(**context)


async def generate_html(
    vulns: list[Vulnerability],
    config: ReportConfig,
    metadata: ReportMetadata,
) -> Path:
    """Generate a self-contained HTML vulnerability report.

    Returns the path the report was written to.
    """
    html = render_html(vulns, config, metadata)

    output = config.output_path
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")

    logger.info("HTML report written to %s", output)
    return output
