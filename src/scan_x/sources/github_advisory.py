"""GitHub Advisory Database client using the GraphQL API."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any

import httpx

from scan_x.models.vulnerability import (
    AffectedPackage,
    Reference,
    Severity,
    Vulnerability,
    VulnerabilitySource,
)
from scan_x.sources.base import VulnerabilitySourceBase

if TYPE_CHECKING:
    from scan_x.utils.cache import ResponseCache
    from scan_x.utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

_GRAPHQL_URL = "https://api.github.com/graphql"

_SEARCH_QUERY = """
query($query: String!, $first: Int!) {
  securityAdvisories(
    first: $first,
    orderBy: {field: PUBLISHED_AT, direction: DESC},
    keyword: $query
  ) {
    nodes {
      ghsaId
      summary
      description
      severity
      cvss { score vectorString }
      publishedAt
      updatedAt
      withdrawnAt
      references { url }
      identifiers { type value }
      vulnerabilities(first: 10) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  }
}
"""

_GET_BY_ID_QUERY = """
query($ghsaId: String!) {
  securityAdvisory(ghsaId: $ghsaId) {
    ghsaId
    summary
    description
    severity
    cvss { score vectorString }
    publishedAt
    updatedAt
    withdrawnAt
    references { url }
    identifiers { type value }
    vulnerabilities(first: 10) {
      nodes {
        package { name ecosystem }
        vulnerableVersionRange
        firstPatchedVersion { identifier }
      }
    }
  }
}
"""

_PACKAGE_VULNS_QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!, $first: Int!) {
  securityVulnerabilities(
    first: $first,
    ecosystem: $ecosystem,
    package: $package,
    orderBy: {field: UPDATED_AT, direction: DESC}
  ) {
    nodes {
      advisory {
        ghsaId
        summary
        description
        severity
        cvss { score vectorString }
        publishedAt
        updatedAt
        withdrawnAt
        references { url }
        identifiers { type value }
      }
      package { name ecosystem }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
"""

# GitHub -> our Severity (MODERATE -> MEDIUM)
_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

# GitHub ecosystem name -> lowercase canonical form
_ECOSYSTEM_MAP: dict[str, str] = {
    "NPM": "npm",
    "PIP": "pip",
    "MAVEN": "maven",
    "NUGET": "nuget",
    "GO": "go",
    "RUBYGEMS": "rubygems",
    "RUST": "rust",
    "COMPOSER": "composer",
    "ERLANG": "erlang",
    "ACTIONS": "actions",
    "PUB": "pub",
    "SWIFT": "swift",
}


class GitHubAdvisorySource(VulnerabilitySourceBase):
    """Fetch vulnerability data from the GitHub Advisory Database (GraphQL)."""

    source_type = VulnerabilitySource.GITHUB_ADVISORY

    def __init__(
        self,
        api_key: str | None = None,
        cache: ResponseCache | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        super().__init__(api_key=api_key)
        self._cache = cache
        self._rate_limiter = rate_limiter
        if not api_key:
            self._enabled = False
            logger.warning("GitHubAdvisorySource: no API key — source disabled")

    # ------------------------------------------------------------------
    # GraphQL transport
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def _graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        if self._rate_limiter:
            await self._rate_limiter.acquire()

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                _GRAPHQL_URL,
                headers=self._headers(),
                json={"query": query, "variables": variables},
            )
            resp.raise_for_status()
            body: dict[str, Any] = resp.json()

        if "errors" in body:
            logger.error("GitHub GraphQL errors: %s", body["errors"])
        result: dict[str, Any] = body.get("data", {})
        return result

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _map_severity(raw: str | None) -> Severity:
        if not raw:
            return Severity.NONE
        return _SEVERITY_MAP.get(raw.upper(), Severity.NONE)

    @staticmethod
    def _map_ecosystem(raw: str | None) -> str:
        if not raw:
            return "unknown"
        return _ECOSYSTEM_MAP.get(raw.upper(), raw.lower())

    @staticmethod
    def _extract_aliases(identifiers: list[dict[str, str]]) -> tuple[str | None, list[str]]:
        """Return (primary_cve, alias_list) from a list of identifier dicts."""
        cve_id: str | None = None
        aliases: list[str] = []
        for ident in identifiers:
            if ident.get("type") == "CVE":
                if cve_id is None:
                    cve_id = ident["value"]
                else:
                    aliases.append(ident["value"])
            elif ident.get("type") == "GHSA":
                aliases.append(ident["value"])
        return cve_id, aliases

    def _parse_advisory(self, node: dict[str, Any]) -> Vulnerability:
        ghsa_id: str = node["ghsaId"]
        identifiers: list[dict[str, str]] = node.get("identifiers", [])
        cve_id, aliases = self._extract_aliases(identifiers)

        # Use CVE as primary ID when available, GHSA otherwise
        vuln_id = cve_id or ghsa_id
        if cve_id and ghsa_id not in aliases:
            aliases.insert(0, ghsa_id)

        cvss = node.get("cvss") or {}
        vuln_nodes: list[dict[str, Any]] = (
            node.get("vulnerabilities", {}).get("nodes") or []
        )

        affected_packages = [
            AffectedPackage(
                name=vn["package"]["name"],
                ecosystem=self._map_ecosystem(vn["package"].get("ecosystem")),
                affected_versions=[vn["vulnerableVersionRange"]]
                if vn.get("vulnerableVersionRange")
                else [],
                fixed_versions=[vn["firstPatchedVersion"]["identifier"]]
                if vn.get("firstPatchedVersion")
                else [],
            )
            for vn in vuln_nodes
            if vn.get("package")
        ]

        references = [
            Reference(url=r["url"], type="ADVISORY")
            for r in node.get("references", [])
            if r.get("url")
        ]

        return Vulnerability(
            id=vuln_id,
            aliases=aliases,
            title=node.get("summary", ""),
            description=node.get("description", ""),
            severity=self._map_severity(node.get("severity")),
            cvss_score=cvss.get("score"),
            cvss_vector=cvss.get("vectorString"),
            affected_packages=affected_packages,
            references=references,
            source=VulnerabilitySource.GITHUB_ADVISORY,
            source_url=f"https://github.com/advisories/{ghsa_id}",
            published_date=self._parse_datetime(node.get("publishedAt")),
            modified_date=self._parse_datetime(node.get("updatedAt")),
            withdrawn_date=self._parse_datetime(node.get("withdrawnAt")),
        )

    def _parse_package_vuln_node(self, node: dict[str, Any]) -> Vulnerability:
        """Parse a securityVulnerabilities node (advisory nested inside)."""
        advisory: dict[str, Any] = node.get("advisory", {})
        # Inject the single vulnerability info back into the advisory shape
        advisory_with_vulns = {
            **advisory,
            "vulnerabilities": {
                "nodes": [
                    {
                        "package": node.get("package"),
                        "vulnerableVersionRange": node.get("vulnerableVersionRange"),
                        "firstPatchedVersion": node.get("firstPatchedVersion"),
                    }
                ]
            },
        }
        return self._parse_advisory(advisory_with_vulns)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def search(self, query: str, limit: int = 20) -> list[Vulnerability]:
        if not self._enabled:
            return []

        cache_key = f"search:{query}:{limit}"
        if self._cache:
            cached = await self._cache.get("github_advisory", cache_key)
            if cached is not None:
                return [Vulnerability.model_validate(v) for v in cached]

        try:
            data = await self._graphql(_SEARCH_QUERY, {"query": query, "first": min(limit, 100)})
        except httpx.HTTPError:
            logger.exception("GitHub Advisory search failed for query=%r", query)
            return []

        nodes: list[dict[str, Any]] = data.get("securityAdvisories", {}).get("nodes") or []
        results = [self._parse_advisory(n) for n in nodes]

        if self._cache:
            await self._cache.set(
                "github_advisory", cache_key, [v.model_dump(mode="json") for v in results]
            )
        return results

    async def get_by_id(self, vuln_id: str) -> Vulnerability | None:
        if not self._enabled:
            return None

        cache_key = f"id:{vuln_id}"
        if self._cache:
            cached = await self._cache.get("github_advisory", cache_key)
            if cached is not None:
                return Vulnerability.model_validate(cached)

        try:
            # Direct GHSA lookup
            if vuln_id.upper().startswith("GHSA-"):
                data = await self._graphql(_GET_BY_ID_QUERY, {"ghsaId": vuln_id})
                advisory = data.get("securityAdvisory")
                if advisory:
                    result = self._parse_advisory(advisory)
                    if self._cache:
                        await self._cache.set(
                            "github_advisory", cache_key, result.model_dump(mode="json")
                        )
                    return result

            # CVE lookup via search
            if vuln_id.upper().startswith("CVE-"):
                data = await self._graphql(_SEARCH_QUERY, {"query": vuln_id, "first": 5})
                nodes = data.get("securityAdvisories", {}).get("nodes") or []
                for node in nodes:
                    for ident in node.get("identifiers", []):
                        if ident.get("value", "").upper() == vuln_id.upper():
                            result = self._parse_advisory(node)
                            if self._cache:
                                await self._cache.set(
                                    "github_advisory",
                                    cache_key,
                                    result.model_dump(mode="json"),
                                )
                            return result
        except httpx.HTTPError:
            logger.exception("GitHub Advisory get_by_id failed for id=%r", vuln_id)

        return None

    async def get_by_package(
        self, package_name: str, ecosystem: str, version: str | None = None
    ) -> list[Vulnerability]:
        if not self._enabled:
            return []

        cache_key = f"pkg:{ecosystem}:{package_name}:{version or '*'}"
        if self._cache:
            cached = await self._cache.get("github_advisory", cache_key)
            if cached is not None:
                return [Vulnerability.model_validate(v) for v in cached]

        # Map our lowercase ecosystem back to the GitHub enum
        gh_ecosystem = ecosystem.upper()
        # Normalise common names to GitHub's expected enum values
        eco_aliases: dict[str, str] = {
            "PYPI": "PIP",
            "PYTHON": "PIP",
            "NODE": "NPM",
            "JAVASCRIPT": "NPM",
            "GOLANG": "GO",
            "RUBY": "RUBYGEMS",
            "CRATES": "RUST",
            "CRATES.IO": "RUST",
            "DOTNET": "NUGET",
        }
        gh_ecosystem = eco_aliases.get(gh_ecosystem, gh_ecosystem)

        try:
            data = await self._graphql(
                _PACKAGE_VULNS_QUERY,
                {"ecosystem": gh_ecosystem, "package": package_name, "first": 100},
            )
        except httpx.HTTPError:
            logger.exception(
                "GitHub Advisory get_by_package failed for %s/%s", ecosystem, package_name
            )
            return []

        nodes: list[dict[str, Any]] = (
            data.get("securityVulnerabilities", {}).get("nodes") or []
        )
        results = [self._parse_package_vuln_node(n) for n in nodes]

        if self._cache:
            await self._cache.set(
                "github_advisory", cache_key, [v.model_dump(mode="json") for v in results]
            )
        return results

    async def health_check(self) -> bool:
        if not self._enabled:
            return False
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    _GRAPHQL_URL,
                    headers=self._headers(),
                    json={"query": "{ viewer { login } }"},
                )
                return resp.status_code == 200
        except httpx.HTTPError:
            logger.exception("GitHub Advisory health check failed")
            return False
