---
title: Quick Start
description: Get started with Who Touched My Deps in minutes
---

This guide will walk you through scanning your first project for vulnerabilities.

## Installation

First, install the tool globally:

```bash
npm install -g who-touched-my-packages
```

Or use it directly with npx:

```bash
npx who-touched-my-packages
```

## Basic Usage

### Scan Current Directory

Navigate to your project and run:

```bash
wtmd
```

The tool will:
1. Recursively find all `package.json` and `requirements.txt` files
2. Parse the dependencies
3. Query OSV and GitHub Advisory databases
4. Display a beautiful report

### Example: Scanning a Node.js Project

```bash
cd ~/my-nodejs-app
wtmd
```

Output:

```
┌  🛡️ Who Touched My Packages?
│  Scanning dependencies for vulnerabilities...
│
✔ Found 1 dependency file(s)

📄 Found 1 dependency file(s):
  📦 package.json

✔ Parsed 45 package(s)

════════════════════════════════════════════════════════════
🛡️ Security Audit Summary
════════════════════════════════════════════════════════════

Scanned Packages: 45
Total Vulnerabilities: 3

🔴 Critical: 1
🟠 High: 2

════════════════════════════════════════════════════════════

📋 Vulnerability Details:

────────────────────────────────────────────────────────────

🔴 CRITICAL - CVE-2023-12345
Package: lodash@4.17.20
Title: Prototype Pollution in lodash
CVSS Score: 9.8
Affected: >=4.0.0 <4.17.21
Fixed in: 4.17.21

Prototype pollution vulnerability in lodash...

References:
  • https://nvd.nist.gov/vuln/detail/CVE-2023-12345
  • https://github.com/advisories/GHSA-xxxx-yyyy-zzzz

Source: OSV
```

## Command Line Options

### Filter by Severity

Only show high and critical vulnerabilities:

```bash
wtmd --severity HIGH
```

### Scan Specific Directory

```bash
wtmd --path /path/to/project
```

## Scanning Remote Repositories

You can scan any Git repository without cloning it manually. The tool will automatically clone it to a temporary directory, scan it, and clean up afterwards.

### Scan a Repository

```bash
wtmd --repo https://github.com/user/repository
```

Example:

```bash
wtmd --repo https://github.com/expressjs/express
```

Output:

```
✔ Repository cloned to /tmp/wtmd-abc123
┌  🛡️ Who Touched My Packages?
│  Scanning dependencies for vulnerabilities...
│
✔ Found 1 dependency file(s)
✔ Parsed 42 package(s)
```

### Scan a Specific Branch

To scan a specific branch or tag:

```bash
wtmd --repo https://github.com/user/repository --branch develop
```

Example:

```bash
wtmd --repo https://github.com/expressjs/express --branch 5.x
```

### Combine with Other Options

You can combine repository scanning with other options:

```bash
# Scan a repo and filter by severity
wtmd --repo https://github.com/user/repo --severity HIGH

# Scan a repo with JSON output
wtmd --repo https://github.com/user/repo --json

# Scan a repo and fail on high vulnerabilities
wtmd --repo https://github.com/user/repo --fail-on HIGH
```

### Use Cases for Remote Scanning

- **Security audits** - Quickly audit third-party dependencies before using a library
- **Due diligence** - Check dependencies of projects you're considering adopting
- **CI/CD** - Scan repositories as part of your pipeline without checking them out
- **Monitoring** - Regularly scan important dependencies for new vulnerabilities

### Exclude Directories

Skip certain directories:

```bash
wtmd --exclude test fixtures examples
```

### JSON Output

Get machine-readable output:

```bash
wtmd --json
```

Output:

```json
{
  "summary": {
    "total": 3,
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0,
    "unknown": 0
  },
  "scannedPackages": 45,
  "timestamp": "2024-03-25T12:00:00.000Z",
  "vulnerabilities": [
    {
      "id": "CVE-2023-12345",
      "packageName": "lodash",
      "packageVersion": "4.17.20",
      "ecosystem": "npm",
      "severity": "CRITICAL",
      "title": "Prototype Pollution in lodash",
      "cvss": 9.8,
      "affectedVersions": ">=4.0.0 <4.17.21",
      "fixedVersions": "4.17.21",
      "references": [...]
    }
  ]
}
```

### Fail on Vulnerabilities (CI/CD)

Exit with error code if vulnerabilities are found:

```bash
wtmd --fail-on HIGH
```

This will:
- Exit with code `0` if no HIGH or CRITICAL vulnerabilities
- Exit with code `1` if HIGH or CRITICAL vulnerabilities found
- Exit with code `2` if an error occurred

## Scanning Python Projects

The tool automatically detects `requirements.txt` files:

```bash
cd ~/my-python-app
wtmd
```

Output:

```
✔ Found 1 dependency file(s)

📄 Found 1 dependency file(s):
  📄 requirements.txt

✔ Parsed 23 package(s)
```

## Scanning Monorepos

For large monorepos, you might want to exclude certain directories:

```bash
wtmd --exclude node_modules dist build .venv
```

You can also scan remote monorepos:

```bash
wtmd --repo https://github.com/user/monorepo --exclude examples test
```

The tool automatically ignores common directories like:
- `node_modules`
- `.git`
- `dist`
- `build`
- `venv`
- `__pycache__`

## Environment Variables

### GitHub Token (Optional)

Set a GitHub personal access token for higher API rate limits:

```bash
export GITHUB_TOKEN=ghp_your_token_here
wtmd
```

Without a token:
- 60 requests per hour

With a token:
- 5,000 requests per hour

## Next Steps

- Learn about [all CLI options](/usage/cli-options/)
- Set up [CI/CD integration](/usage/ci-cd/)
- Understand the [data sources](/data-sources/overview/)
- Learn how to [filter results](/guides/filtering/)
