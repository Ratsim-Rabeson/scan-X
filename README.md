# scan-X 🔍🛡️

> Terminal UI for vulnerability searching, scanning, and reporting.

[![CI](https://github.com/rico-ratsim/scan-x/actions/workflows/ci.yml/badge.svg)](https://github.com/rico-ratsim/scan-x/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/scan-x)](https://pypi.org/project/scan-x/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**scan-X** is a powerful terminal-based vulnerability scanner and browser. Search CVEs across multiple databases, scan your projects for vulnerable dependencies, visualize severity distributions, and generate professional reports — all from your terminal.

## Features

- 🔎 **Search vulnerabilities** across OSV, NVD, GitHub Advisories, and Snyk
- 📦 **Scan projects** — auto-detects Angular, Java (Maven/Gradle), NestJS/Node.js, Python, .NET
- 📊 **Interactive TUI** — filterable tables, severity badges, terminal charts
- 📝 **Reports** — generate PDF, HTML, JSON, and CSV reports
- ⚡ **Fast** — async API calls, local caching, rate limiting
- 🌐 **Multi-source** — aggregates and deduplicates results from 6+ vulnerability databases

## Installation

```bash
# Recommended: install globally with pipx
pipx install scan-x

# Or with pip
pip install scan-x
```

## Quick Start

```bash
# Launch the interactive TUI
scan-x

# Scan a project directory
scan-x scan ./my-project

# Search for a specific CVE
scan-x search CVE-2024-1234

# Search by keyword
scan-x search "log4j remote code execution"

# Generate a report from the last scan
scan-x report --format pdf --output report.pdf
```

## Configuration

scan-X stores its configuration at `~/.config/scan-x/config.toml`:

```toml
[api_keys]
nvd = "your-nvd-api-key"        # https://nvd.nist.gov/developers/request-an-api-key
github = "ghp_xxxxxxxxxxxx"      # GitHub PAT with read:packages
snyk = "your-snyk-api-token"     # https://app.snyk.io/account

[cache]
ttl_hours = 1
directory = "~/.cache/scan-x"

[display]
theme = "dark"                   # dark | light
default_report_format = "html"
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `S` | Search vulnerabilities |
| `P` | Scan project |
| `R` | Generate report |
| `C` | Configuration |
| `?` | Help |
| `Q` | Quit |

## Supported Project Types

| Type | Detected By | Scanner |
|------|-------------|---------|
| Node.js / Angular / NestJS | `package-lock.json`, `yarn.lock` | lockfile parser + `npm audit` |
| Java (Maven) | `pom.xml` | POM parser + `mvn dependency-check` |
| Java (Gradle) | `build.gradle` | Gradle parser |
| Python | `requirements.txt`, `poetry.lock` | lockfile parser + `pip-audit` |
| .NET | `*.csproj`, `packages.config` | NuGet reference parser |

External tools (Trivy, Grype) are used when available for enhanced scanning.

## Data Sources

| Source | API Key Required | Coverage |
|--------|-----------------|----------|
| [OSV.dev](https://osv.dev/) | No | npm, PyPI, Maven, Go, NuGet, and more |
| [NVD](https://nvd.nist.gov/) | Optional (higher rate limits) | All CVEs |
| [GitHub Advisories](https://github.com/advisories) | Yes (PAT) | npm, PyPI, Maven, Go, NuGet, Rust |
| [Snyk](https://snyk.io/) | Yes | npm, PyPI, Maven, Go, and more |
| OWASP Dependency Check | No (local tool) | Java, .NET |

## Development

```bash
# Clone the repository
git clone https://github.com/rico-ratsim/scan-x.git
cd scan-x

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src/ tests/

# Run type checker
mypy src/
```

## License

MIT — see [LICENSE](LICENSE) for details.
