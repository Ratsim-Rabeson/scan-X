# scan-X Configuration Reference

## Config File Location

scan-X stores its configuration in a TOML file at:

```
~/.config/scan-x/config.toml
```

The file is created automatically with default values the first time scan-X runs. You can also edit it manually or configure settings through the TUI Settings screen (press `C`).

## Full Configuration Example

```toml
[api_keys]
nvd = "your-nvd-api-key"
github = "ghp_xxxxxxxxxxxxxxxxxxxx"
snyk = "your-snyk-api-token"

[cache]
enabled = true
ttl_hours = 1
directory = "~/.cache/scan-x"

[display]
theme = "dark"
default_report_format = "html"
show_severity = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]

[sources]
osv_enabled = true
nvd_enabled = true
github_enabled = true
snyk_enabled = true
```

## API Key Setup

### NVD (National Vulnerability Database)

An API key is **optional** but recommended. Without a key, NVD enforces stricter rate limits (5 requests per 30 seconds vs. 50 with a key).

1. Go to <https://nvd.nist.gov/developers/request-an-api-key>
2. Fill out the form and submit.
3. Check your email for the API key.
4. Add it to your config:

```toml
[api_keys]
nvd = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### GitHub Advisories

A **GitHub Personal Access Token (PAT)** is required to query the GitHub Advisory Database via GraphQL.

1. Go to <https://github.com/settings/tokens>
2. Click **Generate new token (classic)**.
3. Select the `read:packages` scope (no other scopes are needed).
4. Copy the token and add it to your config:

```toml
[api_keys]
github = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

### Snyk

A Snyk API token is required to query the Snyk vulnerability database.

1. Sign up or log in at <https://app.snyk.io/>
2. Go to **Account Settings** → **API Token** (<https://app.snyk.io/account>).
3. Copy the token and add it to your config:

```toml
[api_keys]
snyk = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### OSV.dev

No API key is required. OSV.dev is a free, open vulnerability database that scan-X queries by default.

## Configuration Sections

### `[api_keys]`

API keys for vulnerability data sources. All keys are optional — sources without keys are either queried anonymously (with lower rate limits) or skipped.

| Key      | Type           | Default | Description                        |
| -------- | -------------- | ------- | ---------------------------------- |
| `nvd`    | string or null | `null`  | NVD API key for higher rate limits |
| `github` | string or null | `null`  | GitHub PAT with `read:packages`    |
| `snyk`   | string or null | `null`  | Snyk API token                     |

### `[cache]`

Controls the local file-based response cache. Cached responses avoid redundant API calls and speed up repeated queries.

| Key         | Type    | Default            | Description                           |
| ----------- | ------- | ------------------ | ------------------------------------- |
| `enabled`   | boolean | `true`             | Enable or disable caching             |
| `ttl_hours` | integer | `1`                | Cache entry time-to-live in hours     |
| `directory` | string  | `~/.cache/scan-x`  | Directory for cached response files   |

Each cache entry is stored as a JSON file named by a SHA-256 hash of the source and query key. Expired entries are automatically ignored.

### `[display]`

Controls the TUI appearance and default behaviors.

| Key                     | Type         | Default  | Description                                    |
| ----------------------- | ------------ | -------- | ---------------------------------------------- |
| `theme`                 | `"dark"` or `"light"` | `"dark"` | TUI color theme                     |
| `default_report_format` | string       | `"html"` | Default format for report generation           |
| `show_severity`         | list of strings | `["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]` | Severity levels to display |

Valid severity values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`.

### `[sources]`

Enable or disable individual vulnerability data sources. Disabled sources are skipped during searches and scans.

| Key              | Type    | Default | Description                    |
| ---------------- | ------- | ------- | ------------------------------ |
| `osv_enabled`    | boolean | `true`  | Enable OSV.dev queries         |
| `nvd_enabled`    | boolean | `true`  | Enable NVD queries             |
| `github_enabled` | boolean | `true`  | Enable GitHub Advisory queries |
| `snyk_enabled`   | boolean | `true`  | Enable Snyk queries            |

> **Note:** Even when a source is enabled, it requires a valid API key if one is mandatory (GitHub, Snyk). Sources with missing required keys are silently skipped.

## Managing Configuration

### Via the TUI

Press `C` from any screen to open Settings. Changes are saved automatically to `~/.config/scan-x/config.toml`.

### Via the CLI

View the current configuration:

```bash
scan-x config
```

### Manual Editing

Open the config file in your editor:

```bash
# macOS / Linux
${EDITOR:-nano} ~/.config/scan-x/config.toml
```

### Resetting to Defaults

Delete the config file to reset to defaults. scan-X will regenerate it on next launch:

```bash
rm ~/.config/scan-x/config.toml
scan-x config
```
