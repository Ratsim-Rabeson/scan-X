# scan-X Usage Guide

## Installation

### Using pipx (recommended)

[pipx](https://pypa.github.io/pipx/) installs scan-X in an isolated environment and makes the `scan-x` command available globally:

```bash
pipx install scan-x
```

### Using pip

```bash
pip install scan-x
```

### From source

```bash
git clone https://github.com/rico-ratsim/scan-x.git
cd scan-x
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick Start

```bash
# Launch the interactive TUI
scan-x

# Search for a specific CVE
scan-x search CVE-2024-1234

# Search by keyword
scan-x search "log4j remote code execution"

# Scan a project directory for vulnerable dependencies
scan-x scan ./my-project

# Generate a vulnerability report
scan-x report --format pdf --output report.pdf

# Show current configuration
scan-x config

# Show version
scan-x version
```

## TUI Navigation

Launch the TUI by running `scan-x` with no arguments (or `scan-x tui`).

### Screens

| Screen     | Description                                      |
| ---------- | ------------------------------------------------ |
| Home       | Dashboard with summary statistics and quick actions |
| Search     | Search vulnerabilities by CVE ID or keyword      |
| Scan       | Scan a project directory for vulnerabilities     |
| Report     | Configure and generate vulnerability reports     |
| Settings   | Manage API keys, sources, cache, and display     |
| Help       | Quick-reference for keyboard shortcuts           |

### Keyboard Shortcuts

#### Global Shortcuts

| Key       | Action                           |
| --------- | -------------------------------- |
| `S`       | Open the Search screen           |
| `P`       | Open the Scan Project screen     |
| `R`       | Open the Report screen           |
| `C`       | Open the Settings screen         |
| `?`       | Show Help overlay                |
| `Q`       | Quit the application             |

#### Navigation

| Key       | Action                           |
| --------- | -------------------------------- |
| `Escape`  | Go back to the previous screen   |
| `Tab`     | Move focus to the next widget    |
| `Enter`   | Activate focused button / submit |

#### Search Screen

| Key       | Action                           |
| --------- | -------------------------------- |
| `Enter`   | Submit search query              |
| Click row | View vulnerability details       |

Use the filter bar to narrow results by severity level (Critical, High, Medium, Low).

## CLI Commands Reference

### `scan-x`

Run with no arguments to launch the interactive TUI.

```
Usage: scan-x [COMMAND]

scan-X: Terminal vulnerability search, scanning & reporting.

Commands:
  config   Show current configuration.
  report   Generate a vulnerability report.
  scan     Scan a project directory for vulnerabilities.
  search   Search vulnerabilities by keyword or CVE ID.
  tui      Launch the interactive TUI.
  version  Show scan-X version.
```

### `scan-x scan`

Scan a project directory for vulnerable dependencies. The project type is auto-detected.

```
Usage: scan-x scan [OPTIONS] PATH

Options:
  -f, --format [table|json|csv]  Output format (default: table)
  -o, --output PATH              Write results to file instead of stdout
```

**Examples:**

```bash
# Scan the current directory
scan-x scan .

# Scan and output as JSON
scan-x scan ./my-project --format json

# Scan and save results to a file
scan-x scan ./my-project --format csv --output results.csv
```

### `scan-x search`

Search vulnerabilities by keyword, CVE ID, or package name across multiple databases.

```
Usage: scan-x search [OPTIONS] QUERY

Options:
  -s, --source [all|osv|nvd|github|snyk]  Data source (default: all)
  --severity [critical|high|medium|low]    Filter by severity
  -n, --limit INTEGER                      Max results (default: 20)
```

**Examples:**

```bash
# Search by CVE ID
scan-x search CVE-2023-44487

# Search by keyword
scan-x search "remote code execution"

# Search a specific source
scan-x search "log4j" --source nvd

# Filter by severity and limit results
scan-x search "openssl" --severity critical --limit 10
```

### `scan-x report`

Generate a vulnerability report from the most recent scan or search results.

```
Usage: scan-x report [OPTIONS]

Options:
  -f, --format [pdf|html|json|csv]  Report format (default: html)
  -o, --output PATH                 Output file path (required)
  -t, --title TEXT                  Report title (default: "scan-X Vulnerability Report")
```

**Examples:**

```bash
# Generate an HTML report
scan-x report --format html --output report.html

# Generate a PDF report with a custom title
scan-x report --format pdf --output audit.pdf --title "Q4 Security Audit"

# Generate a JSON report for CI/CD pipelines
scan-x report --format json --output results.json

# Generate a CSV report for spreadsheet analysis
scan-x report --format csv --output vulns.csv
```

### `scan-x config`

Display the current configuration values.

```bash
scan-x config
```

### `scan-x version`

Print the installed scan-X version.

```bash
scan-x version
```

## Searching Vulnerabilities

scan-X aggregates results from multiple vulnerability databases:

| Source              | API Key Required | What It Covers                       |
| ------------------- | --------------- | ------------------------------------ |
| [OSV.dev](https://osv.dev/) | No | npm, PyPI, Maven, Go, NuGet, and more |
| [NVD](https://nvd.nist.gov/) | Optional (higher rate limits) | All CVEs |
| [GitHub Advisories](https://github.com/advisories) | Yes (PAT) | npm, PyPI, Maven, Go, NuGet, Rust |
| [Snyk](https://snyk.io/) | Yes | npm, PyPI, Maven, Go, and more |

### Search by CVE ID

Provide a CVE identifier to look up a specific vulnerability:

```bash
scan-x search CVE-2024-1234
```

### Search by Keyword

Use natural-language keywords to find related vulnerabilities:

```bash
scan-x search "log4j remote code execution"
scan-x search "openssl buffer overflow"
```

### Search by Package Name

Search for vulnerabilities affecting a specific package:

```bash
scan-x search "lodash"
scan-x search "django"
```

### Source Selection

Query a single source instead of all:

```bash
scan-x search "spring4shell" --source nvd
scan-x search "prototype pollution" --source osv
```

Results are deduplicated across sources — if the same CVE appears in both NVD and OSV, only one record is shown with merged information.

## Scanning Projects

### Supported Project Types

| Type                  | Detected By                                    | Scanner Strategy                |
| --------------------- | ---------------------------------------------- | ------------------------------- |
| Node.js / Angular / NestJS | `package-lock.json`, `yarn.lock`, `package.json` | Lockfile parser + `npm audit` |
| Java (Maven)          | `pom.xml`                                      | POM dependency parser           |
| Java (Gradle)         | `build.gradle`, `build.gradle.kts`             | Gradle dependency parser        |
| Python                | `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `pyproject.toml` | Lockfile parser + `pip-audit` |
| .NET                  | `*.csproj`, `packages.config`                  | NuGet reference parser          |

### How Auto-Detection Works

When you run `scan-x scan ./my-project`, the `ProjectDetector` inspects the directory for indicator files:

1. **Filename matching** — checks for known filenames (`package-lock.json`, `pom.xml`, `requirements.txt`, etc.).
2. **Glob matching** — for types like .NET, looks for glob patterns such as `*.csproj`.
3. **Content inspection** — for ambiguous files like `pyproject.toml`, checks for Python-specific markers (`[tool.poetry]` or `[project]`).

Multiple project types can be detected in a single directory (e.g., a monorepo with both Python and Node.js).

### External Tools

scan-X integrates with external scanning tools when they are installed:

- **[Trivy](https://aquasecurity.github.io/trivy/)** — comprehensive vulnerability scanner for containers, filesystems, and more.
- **[Grype](https://github.com/anchore/grype)** — vulnerability scanner for container images and filesystems.

These tools are used automatically when available on `PATH` for enhanced scanning coverage.

### Scan Workflow

1. The project type is auto-detected.
2. Dependencies are parsed from lockfiles and manifests.
3. Each dependency is checked against enabled vulnerability databases.
4. Results from database lookups and external tools (if available) are merged and deduplicated.
5. A `ScanResult` is produced with all found vulnerabilities, dependency counts, and severity summaries.

## Report Generation

### Supported Formats

| Format | Description                              | Use Case                     |
| ------ | ---------------------------------------- | ---------------------------- |
| HTML   | Rich HTML with severity charts and styling | Human-readable reports       |
| PDF    | PDF generated from the HTML template via WeasyPrint | Formal audits, sharing       |
| JSON   | Structured JSON with metadata and vulns  | CI/CD integration, tooling   |
| CSV    | Flat CSV with one row per affected package | Spreadsheet analysis         |

### Report Customization

Reports support these options (via TUI or CLI):

- **Title** — custom report title (`--title`).
- **Charts** — include/exclude severity distribution charts (TUI toggle).
- **Remediation** — include/exclude remediation guidance (TUI toggle).
- **Severity filter** — only include vulnerabilities at or above a threshold (TUI select).

### PDF Requirements

PDF generation requires [WeasyPrint](https://weasyprint.org/). It is included as a dependency but may need system-level libraries:

```bash
# macOS
brew install pango

# Ubuntu/Debian
sudo apt install libpango-1.0-0 libpangocairo-1.0-0
```

### Report via TUI

1. Press `R` to open the Report screen.
2. Select the output format from the dropdown.
3. Enter the output file path.
4. Optionally set a custom title, toggle charts and remediation.
5. Press **Generate** to create the report.
