"""Abstract base class for vulnerability data sources."""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scan_x.models.vulnerability import Vulnerability, VulnerabilitySource


class VulnerabilitySourceBase(abc.ABC):
    """Abstract base class for vulnerability data sources."""

    source_type: VulnerabilitySource

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key
        self._enabled = True

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    @abc.abstractmethod
    async def search(self, query: str, limit: int = 20) -> list[Vulnerability]:
        """Search vulnerabilities by keyword."""
        ...

    @abc.abstractmethod
    async def get_by_id(self, vuln_id: str) -> Vulnerability | None:
        """Get a specific vulnerability by CVE ID or source-specific ID."""
        ...

    @abc.abstractmethod
    async def get_by_package(
        self, package_name: str, ecosystem: str, version: str | None = None
    ) -> list[Vulnerability]:
        """Get vulnerabilities affecting a specific package."""
        ...

    async def health_check(self) -> bool:
        """Check if the source is reachable. Default: True."""
        return True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} enabled={self.enabled}>"
