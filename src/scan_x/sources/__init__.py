"""Vulnerability data sources."""

from scan_x.sources.aggregator import VulnerabilityAggregator
from scan_x.sources.base import VulnerabilitySourceBase
from scan_x.sources.github_advisory import GitHubAdvisorySource
from scan_x.sources.nvd import NVDSource
from scan_x.sources.osv import OSVSource
from scan_x.sources.snyk import SnykSource

__all__ = [
    "GitHubAdvisorySource",
    "NVDSource",
    "OSVSource",
    "SnykSource",
    "VulnerabilityAggregator",
    "VulnerabilitySourceBase",
]
